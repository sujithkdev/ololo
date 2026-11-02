"""
run.py — Start the BehEDR server.

Usage:
    python run.py

Environment overrides (CHANGE ALL OF THESE IN PRODUCTION):
    EDR_API_KEY      — agent API key          (default: 123456789  ← INSECURE)
    EDR_JWT_SECRET   — JWT signing secret     (MUST change, min 32 chars)
    FLASK_SECRET_KEY — Flask session secret   (MUST change)
    EDR_PORT         — port                   (default: 5000)
    VT_API_KEY       — VirusTotal key         (optional)
    EDR_DEV_MODE     — set to 'true' to enable /simulate endpoint (dev only)

TLS (optional — HTTP is the default for ease of setup):
    EDR_TLS_ENABLED  — set to 'true' to enable HTTPS
    EDR_TLS_CERT     — path to PEM certificate file  (auto-generated self-signed if absent)
    EDR_TLS_KEY      — path to PEM private key file  (auto-generated self-signed if absent)

    Quick start with TLS:
        EDR_TLS_ENABLED=true python run.py
        # Self-signed cert is written to data/server.crt + data/server.key on first run.
        # Point the agent at it:  EDR_TLS_CA_CERT=data/server.crt EDR_TLS_ENABLED=true

    Production:
        Replace data/server.crt + data/server.key with certs from your CA,
        or set EDR_TLS_CERT / EDR_TLS_KEY to point at your cert files.
"""
import sys, os, socket, gc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
gc.set_threshold(700, 10, 10)

from behedr_server import create_app
from behedr_server.config import HOST, PORT, API_KEY, JWT_SECRET, DATA_DIR


# ── Production secret validation ──────────────────────────────────────────────
# config.py handles hard-fail on insecure secrets in non-dev mode.
# run.py just re-reads the result for display purposes.
_PROD_WARNINGS = []
_DEV_MODE = os.environ.get("EDR_DEV_MODE", "false").lower() == "true"
if _DEV_MODE:
    for env_var, bad_default in {
        "EDR_API_KEY":    "123456789",
        "EDR_JWT_SECRET": "change-me-in-production-min-32-chars!",
        "FLASK_SECRET_KEY": "edr-flask-secret-change-in-production-2026",
    }.items():
        if os.environ.get(env_var, bad_default) == bad_default:
            _PROD_WARNINGS.append(
                f"  ⚠  {env_var} is still the default value "
                f"— run generate_secrets.py before going to production."
            )


def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _generate_self_signed(cert_path: str, key_path: str):
    """
    Generate a minimal self-signed certificate using the cryptography library.
    Falls back to a subprocess openssl call if cryptography is not installed.
    The cert is valid for 3 years and includes the local IP as a SAN so that
    the agent can verify it when EDR_TLS_CA_CERT points at this file.
    """
    local_ip = _local_ip()

    # Try cryptography library first (preferred — no subprocess, no openssl dep)
    try:
        import datetime as _dt
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"BehEDR-Server"),
        ])
        san = x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.IPv4Address(local_ip)),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow())
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=1095))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"  [TLS] Self-signed cert generated (cryptography library)")
        print(f"        cert : {cert_path}")
        print(f"        key  : {key_path}")
        print(f"        SANs : localhost, {local_ip}, 127.0.0.1")
        return True
    except ImportError:
        pass   # fall through to openssl subprocess
    except Exception as e:
        print(f"  [TLS] cryptography library error: {e}")
        return False

    # Fallback: openssl subprocess
    try:
        import subprocess
        subj = f"/CN=BehEDR-Server/O=EDR"
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", key_path, "-out", cert_path,
             "-days", "1095", "-nodes", "-subj", subj],
            capture_output=True, timeout=30)
        if r.returncode == 0:
            print(f"  [TLS] Self-signed cert generated (openssl)")
            print(f"        cert : {cert_path}")
            print(f"        key  : {key_path}")
            return True
        else:
            print(f"  [TLS] openssl failed: {r.stderr.decode()[:200]}")
            return False
    except FileNotFoundError:
        print("  [TLS] openssl not found. Install the 'cryptography' package:")
        print("        pip install cryptography")
        return False
    except Exception as e:
        print(f"  [TLS] openssl subprocess error: {e}")
        return False


def _resolve_ssl_context():
    """
    Return an ssl.SSLContext ready for Flask, or None if TLS is disabled.

    Resolution order:
      1. EDR_TLS_ENABLED != 'true'  → return None (plain HTTP)
      2. EDR_TLS_CERT + EDR_TLS_KEY set and files exist → load them
      3. Default paths data/server.crt + data/server.key exist → load them
      4. Neither found → auto-generate self-signed into data/ then load
    """
    if os.environ.get("EDR_TLS_ENABLED", "false").lower() != "true":
        return None, None, None   # (ssl_context, cert_path, key_path)

    import ssl

    default_cert = os.path.join(DATA_DIR, "server.crt")
    default_key  = os.path.join(DATA_DIR, "server.key")
    cert_path    = os.environ.get("EDR_TLS_CERT", default_cert)
    key_path     = os.environ.get("EDR_TLS_KEY",  default_key)

    # Auto-generate if either file is missing
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        print("  [TLS] Certificate not found — generating self-signed cert...")
        if not _generate_self_signed(cert_path, key_path):
            print("  [TLS] ⚠  Could not generate cert — falling back to HTTP.")
            return None, None, None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx, cert_path, key_path
    except Exception as e:
        print(f"  [TLS] Failed to load cert/key: {e}")
        print("  [TLS] ⚠  Falling back to HTTP.")
        return None, None, None


if __name__ == "__main__":
    app      = create_app()
    local_ip = _local_ip()

    ssl_ctx, cert_path, key_path = _resolve_ssl_context()
    tls_on  = ssl_ctx is not None
    scheme  = "https" if tls_on else "http"

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        BehEDR  Behavioral EDR  v4.0  — Enterprise           ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    if _PROD_WARNINGS:
        print("  ╔═══════════════════════ SECURITY WARNINGS ══════════════════╗")
        for w in _PROD_WARNINGS:
            print(f"  ║ {w}")
        print("  ╚════════════════════════════════════════════════════════════╝")
        print()

    if not tls_on:
        print("  ⚠  TLS DISABLED — traffic is unencrypted (HTTP).")
        print("     Set EDR_TLS_ENABLED=true to enable HTTPS.")
        print()

    print(f"  Server IP    :  {local_ip}")
    print(f"  Port         :  {PORT}")
    print(f"  TLS          :  {'ENABLED  (' + cert_path + ')' if tls_on else 'disabled (HTTP)'}")
    print(f"  Agent Key    :  {'<hidden>' if len(API_KEY) > 12 else API_KEY + '  ← CHANGE THIS'}")
    print()
    print(f"  Dashboard    :  {scheme}://localhost:{PORT}/")
    print(f"  Network URL  :  {scheme}://{local_ip}:{PORT}/")
    print(f"  Health       :  {scheme}://{local_ip}:{PORT}/health")
    print()
    print("  Default login :  admin / change-me-now  (change immediately)")
    print("  Get JWT :")
    print(f'    curl -X POST {scheme}://{local_ip}:{PORT}/auth/login \\')
    print(f'      -H "Content-Type: application/json" \\')
    print(f"      -d '{{\"username\":\"admin\",\"password\":\"change-me-now\"}}'")

    if tls_on:
        print()
        print("  Agent config for this server:")
        print(f"    EDR_TLS_ENABLED=true")
        print(f"    EDR_TLS_CA_CERT={cert_path}")
        print(f"    EDR_SERVER_IP={local_ip}")
    else:
        print()
        print("  Agent config for this server:")
        print(f"    EDR_TLS_ENABLED=false")
        print(f"    EDR_SERVER_IP={local_ip}")

    print()
    print("  10-Layer Detection Engine:")
    print("    L0   Threat Intel IOC      (local feed + VirusTotal)")
    print("    L1   Behaviour Chains      (YAML, 74+ rules)")
    print("    L2   Heuristic Scoring     (YAML, 23 signals, dev-tool exclusions)")
    print("    L3   Parent-Child Analysis (YAML, suspicious + safe pairs)")
    print("    L4   MITRE Intent Classif. (keyword scoring)")
    print("    L5   ML Anomaly Detection  (Isolation Forest, 23 features, persisted)")
    print("    L6   Network Behaviour     (C2 beaconing + lateral movement ports)")
    print("    L7   File & Registry       (ransomware, ransom notes)")
    print("    L8   Process Masquerading  (T1036.005 — system proc from wrong dir)")
    print("    L9   DLL Hijacking         (T1574 — system DLL from non-System32)")
    print("    L10  Sequence ML           (rare pairs, recon burst, download+exec)")
    print()
    print("  Enterprise features:")
    print("    ✅  JWT auth + RBAC (admin / analyst / viewer)")
    print("    ✅  Rate limiting per system_id — NAT-safe")
    print("    ✅  IOC feed (SHA-256, IP, domain, name + VirusTotal)")
    print("    ✅  SHA-256 + exe_path per process event")
    print("    ✅  DLL load monitoring (L9) with signing check + cache")
    print("    ✅  Network auto-feed (L6 — lateral movement ports included)")
    print("    ✅  File system monitoring (L7 — RDCW-based, 6 watched dirs)")
    print("    ✅  ML model persisted to disk (no blind window on restart)")
    print("    ✅  Incident correlation (alert grouping + lifecycle)")
    print("    ✅  False positive suppression list")
    print("    ✅  Audit log (every user action)")
    print("    ✅  2-step data clear with auto-backup")
    print("    ✅  Wazuh integration bridge (/wazuh/events)")
    print()

    # ── Notification channels ──────────────────────────────────────────────
    from behedr_server.notifier import is_configured
    nc = is_configured()
    any_notify = any(v for k, v in nc.items() if k != "enabled")
    if nc["enabled"] and any_notify:
        print("  Alerting channels configured:")
        if nc["slack"]:     print("    ✅  Slack")
        if nc["teams"]:     print("    ✅  Microsoft Teams")
        if nc["email"]:     print("    ✅  Email (SMTP)")
        if nc["pagerduty"]: print("    ✅  PagerDuty")
        print()
    else:
        print("  ⚠  No alerting channels configured (optional).")
        print("     Set any of these env vars to enable notifications:")
        print("       EDR_NOTIFY_SLACK_URL      — Slack incoming webhook")
        print("       EDR_NOTIFY_TEAMS_URL      — MS Teams incoming webhook")
        print("       EDR_NOTIFY_EMAIL_HOST     — SMTP host (+ USER/PASS/TO)")
        print("       EDR_NOTIFY_PD_KEY         — PagerDuty integration key")
        print()

    dev_mode = os.environ.get("EDR_DEV_MODE", "false").lower() == "true"
    if dev_mode:
        print("  ⚠  DEV MODE: /simulate endpoint is ENABLED (EDR_DEV_MODE=true)")
        print(f'    curl -X POST {scheme}://{local_ip}:{PORT}/simulate \\')
        print(f'      -H "Authorization: Bearer <analyst_token>" \\')
        print(f"      -d '{{\"scenario\":\"phishing\"}}'")
        print()

    print("  Press Ctrl+C to stop.")
    print()

    app.run(
        host=HOST, port=PORT,
        debug=False, threaded=True, use_reloader=False,
        ssl_context=ssl_ctx,   # None = plain HTTP; SSLContext = HTTPS
    )
