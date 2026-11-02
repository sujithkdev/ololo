import importlib
import threading

import pytest


@pytest.fixture(scope="module")
def app(tmp_path_factory, request):
    patch = pytest.MonkeyPatch()
    request.addfinalizer(patch.undo)
    state = tmp_path_factory.mktemp("server")
    patch.setenv("EDR_DATA_DIR", str(state))
    patch.setenv("EDR_LAB_MODE", "true")
    patch.setenv("EDR_API_KEY", "test-key-" + "a" * 40)
    patch.setenv("EDR_JWT_SECRET", "test-jwt-" + "b" * 40)
    patch.setenv("FLASK_SECRET_KEY", "test-flask-" + "c" * 40)
    # Prevent background collection, intelligence downloads and schedulers.
    patch.setattr(threading.Thread, "start", lambda self: None)
    from behedr_server.core import detector
    patch.setattr(detector, "initialize", lambda: None)
    from behedr_server import threatintel
    patch.setattr(threatintel, "load_iocs", lambda: None)
    from behedr_server import create_app
    application = create_app()
    application.config["TESTING"] = True
    yield application
    patch.undo()


def test_health_and_dashboard_assets(app):
    client = app.test_client()
    assert client.get("/health").status_code == 200
    assert app.jinja_env.get_template("dashboard.html") is not None


def test_agent_key_required(app):
    assert app.test_client().post("/events", json={}).status_code == 401


def test_process_contract_rejects_bad_numeric_fields(app):
    from behedr_server.core.processor import process
    base = {"system_id": "PC", "event": "process_spawn", "parent": "explorer.exe",
            "child": "notepad.exe", "pid": "bad", "time": 12345}
    assert process(base) is None
    base["pid"] = 42
    event = process(base)
    assert event["pid"] == 42


def test_yara_file_result_reaches_detector(app, monkeypatch):
    from behedr_server.config import API_KEY
    from behedr_server.core import detector
    emitted = []
    monkeypatch.setattr(detector, "_emit", emitted.append)
    response = app.test_client().post("/yara_hits", headers={"API-Key": API_KEY}, json={
        "events": [{"system_id": "PC", "event": "yara_hit", "scan_type": "file",
                    "exe_path": "C:\\lab\\sample.exe", "process": "sample.exe",
                    "pid": 42, "rule": "test_rule", "severity": "MEDIUM"}]})
    assert response.status_code == 200
    assert response.json["processed"] == 1
    assert "YARA FILE" in emitted[0]["reason"]
    assert "RWX" not in emitted[0]["reason"]


def test_remote_path_is_never_scanned_by_server(app, monkeypatch):
    from behedr_server.core import detector
    monkeypatch.setattr(detector.os.path, "exists", lambda path: pytest.fail("remote file access"))
    assert detector._l0b_yara_scan({"exe_path": "C:\\lab\\sample.exe"}) == (0, "")


def test_rules_still_detect_office_shell_chain(app, monkeypatch):
    from behedr_server.core import detector
    detector.load_rules()
    monkeypatch.setattr(detector, "_emit", lambda alert: None)
    alerts = detector._l1_chain_rules({"system_id": "PC", "parent": "winword.exe",
                                      "child": "powershell.exe", "cmdline": "-enc example"})
    assert alerts
    assert any("L1 EXACT MATCH" in alert["reason"] for alert in alerts)


def test_feedback_aliases_register_without_endpoint_collisions(app):
    rules = list(app.url_map.iter_rules())
    assert sum(rule.rule == "/api/uba/users" for rule in rules) == 1
    assert any(rule.rule == "/api/feedback/<int:alert_id>" for rule in rules)
    assert any(rule.rule == "/api/alerts/<int:alert_id>/feedback" for rule in rules)


def test_command_poll_and_result_roundtrip(app):
    from behedr_server.config import API_KEY
    from behedr_server.database.storage import queue_cmd, get_cmds
    client = app.test_client()
    cid = queue_cmd("LAB-PC", "collect_info")
    assert client.get("/commands/LAB-PC").status_code == 401
    headers = {"API-Key": API_KEY}
    response = client.get("/commands/LAB-PC", headers=headers)
    assert response.json["commands"][0]["id"] == cid
    assert client.get("/commands/OTHER-PC", headers=headers).json["commands"] == []
    assert client.post("/commands/result", headers=headers,
                       json={"id": cid, "result": "lab information"}).status_code == 200
    assert client.get("/commands/LAB-PC", headers=headers).json["commands"] == []
    assert get_cmds("LAB-PC")[0]["status"] == "executed"
    assert client.post("/commands/result", headers=headers,
                       json={"id": "invalid"}).status_code == 400


def test_lab_blocks_new_and_preexisting_disruptive_commands(app, monkeypatch):
    from behedr_server import config
    from behedr_server.database.storage import queue_cmd
    assert config.LAB_MODE and not config.AUTO_RESPONSE and not config.ADVANCED_ML_ENABLED
    with pytest.raises(PermissionError):
        queue_cmd("LAB-PC", "kill_process", {"target": "notepad.exe"})
    monkeypatch.setattr(config, "LAB_MODE", False)
    queue_cmd("OLD-PC", "isolate_network")
    monkeypatch.setattr(config, "LAB_MODE", True)
    response = app.test_client().get("/commands/OLD-PC", headers={"API-Key": config.API_KEY})
    assert response.json["commands"] == []


def test_lab_rejects_manual_disruptive_commands_and_marks_missing_features(app):
    from behedr_server.auth import _make_jwt
    headers = {"Authorization": "Bearer " + _make_jwt("lab-analyst", "analyst")}
    client = app.test_client()
    assert client.post("/api/command", headers=headers, json={
        "system_id": "LAB-PC", "action": "isolate_network"}).status_code == 403
    for route in ("/api/memory_forensics/stats", "/api/lateral_movement/stats", "/api/predictions"):
        response = client.get(route, headers=headers)
        assert response.status_code == 503
        assert response.json["available"] is False


def test_automatic_playbooks_do_not_start_in_lab(app, monkeypatch):
    from behedr_server import playbooks
    monkeypatch.setattr(playbooks.threading, "Thread", lambda **kwargs: pytest.fail("Automatic playbook started"))
    playbooks.run_playbooks({"system_id": "LAB-PC", "risk_level": "CRITICAL"})


def test_feedback_edits_do_not_inflate_counts(app, monkeypatch):
    from behedr_server.core import active_learning as al
    from behedr_server.database import storage
    monkeypatch.setattr(al, "_feedback", {})
    monkeypatch.setattr(al, "_stats", {"total_feedback": 0, "true_positives": 0,
        "false_positives": 0, "accuracy_current": 0.0, "accuracy_week1": 0.0, "last_retrain": 0})
    monkeypatch.setattr(storage, "save_alert_feedback", lambda *args: None)
    monkeypatch.setattr(al, "_maybe_retrain", lambda: None)
    al.record_feedback(1, "true_positive", "analyst")
    al.record_feedback(1, "false_positive", "analyst")
    assert al.get_stats()["total_feedback"] == 1
    assert al.get_stats()["true_positives"] == 0
    assert al.get_stats()["false_positives"] == 1
    assert al._retrain_with_feedback() is False
    assert al.get_stats()["last_retrain"] == 0


def test_false_positive_adjustment_uses_valid_counters(app, monkeypatch):
    from behedr_server.core import active_learning as al
    from behedr_server.database import storage
    monkeypatch.setattr(al, "_feedback", {i: {"verdict": "false_positive"} for i in range(5)})
    monkeypatch.setattr(storage, "get_alert_by_id", lambda aid: {"process": "test.exe", "reason": "L2: test"})
    al._adjust_detection_weights()


def test_frequency_scores_before_recording_in_pipeline(app, monkeypatch):
    import sys
    from types import ModuleType
    from behedr_server.core import detector
    from behedr_server.core import hash_db
    trace = []
    for name, recorder in (("deep_sequence", "record_sequence_event"),
                           ("graph_ml", "record_graph_event"),
                           ("baseline_autoencoder", "record_baseline_event")):
        module = ModuleType("behedr_server.core." + name)
        module.is_available = lambda: False
        setattr(module, recorder, lambda event: trace.append("advanced_record"))
        monkeypatch.setitem(sys.modules, module.__name__, module)
        import behedr_server.core as core
        monkeypatch.setattr(core, name, module, raising=False)
    monkeypatch.setattr(hash_db, "check_hash", lambda sha: None)
    monkeypatch.setattr(detector, "check_ioc", lambda **kwargs: [])
    monkeypatch.setattr(detector, "_emit", lambda alert: None)
    monkeypatch.setattr(detector, "score_frequency", lambda *args: (trace.append("score") or 0, ""))
    monkeypatch.setattr(detector, "record_event", lambda *args: trace.append("record"))
    detector.analyze({"system_id": "ORDER-PC", "parent": "lab-parent.exe",
        "child": "lab-child.exe", "pid": 123, "time": 12345, "cmdline": ""})
    assert trace.index("score") < trace.index("record")
    assert trace.index("score") < trace.index("advanced_record")


def test_dashboard_login_loads_registered_endpoint_without_exposing_agent_key(app):
    from behedr_server.config import API_KEY
    client = app.test_client()
    page = client.get('/').get_data(as_text=True)
    assert 'dashboard-login' in page
    assert API_KEY not in page
    assert client.get('/api/status').status_code == 401
    assert client.get('/api/status', headers={'API-Key': API_KEY}).status_code == 401
    response = client.post('/register', headers={'API-Key': API_KEY}, json={
        'system_id': 'DASHBOARD-TEST', 'hostname': 'DASHBOARD-TEST', 'platform': 'Windows'})
    assert response.status_code == 200
    login = client.post('/auth/login', json={'username': 'admin', 'password': 'change-me-now'})
    assert login.status_code == 200
    status = client.get('/api/status', headers={'Authorization': 'Bearer ' + login.json['token']})
    assert status.status_code == 200
    assert any(s['id'] == 'DASHBOARD-TEST' for s in status.json['systems'])
