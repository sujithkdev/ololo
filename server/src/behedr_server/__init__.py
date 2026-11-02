# server/__init__.py — Flask application factory
import gc, os
from flask import Flask


def create_app():
    from behedr_server.database.storage import init_db
    from behedr_server.core.graph import rebuild_from_db
    app = Flask(__name__, static_folder=None)
    # Flask SESSION secret — must come from env in production.
    # This key protects Flask session cookies. It is separate from
    # EDR_JWT_SECRET (which protects API JWTs).
    app.config["SECRET_KEY"] = os.environ.get(
        "FLASK_SECRET_KEY",
        "edr-flask-secret-change-in-production-2026"
    )
    app.config["JSON_SORT_KEYS"] = False

    # Initialise DB + graph before registering blueprints
    init_db()
    rebuild_from_db()

    # ── Hash DB: seed built-in hashes + kick off background update ────────
    # Runs in a daemon thread so it never delays server startup.
    # seed_known_hashes() is idempotent (INSERT OR IGNORE).
    try:
        import threading as _threading
        from behedr_server.core.hash_db import init_hash_db, start_auto_updater

        def _boot_hash_db():
            try:
                init_hash_db()
                # Seed the built-in known-bad hashes (fast, no network)
                from behedr_server.tools.update_hash_db import seed_known_hashes
                seed_known_hashes()
                # Background 24-hour refresh from MalwareBazaar + ThreatFox
                start_auto_updater()
                # Trigger one immediate update if DB is empty or stale
                from behedr_server.core.hash_db import update_hash_db, get_stats
                stats = get_stats()
                if stats["total_hashes"] < len([]):   # always runs first time
                    pass
                update_hash_db(force=False)  # skips if updated <24 h ago
            except Exception as _e:
                print(f"[HASH-DB] Boot init error (non-fatal): {_e}")

        _threading.Thread(target=_boot_hash_db, daemon=True,
                          name="HashDBBoot").start()
    except Exception as e:
        print(f"[HASH-DB] Failed to start hash DB boot (non-fatal): {e}")

    # Start automated backup scheduler
    try:
        from behedr_server.backup_manager import start_backup_scheduler
        start_backup_scheduler()
    except Exception as e:
        print(f"[BACKUP] Failed to start backup scheduler: {e}")

    # Start health monitoring
    try:
        from behedr_server.health_monitor import start_health_monitor
        start_health_monitor()
    except Exception as e:
        print(f"[HEALTH] Failed to start health monitor: {e}")

    # Start email digest scheduler
    try:
        from behedr_server.email_digest import start_digest_scheduler
        start_digest_scheduler()
    except Exception as e:
        print(f"[DIGEST] Failed to start digest scheduler: {e}")

    # ── Active Learning — load feedback from DB + start weekly retrain ────
    # initialize() replays all existing TP/FP feedback from the DB so
    # accuracy stats are correct even after a server restart.
    # The weekly scheduler triggers a background retrain even when feedback
    # volume is low (< _RETRAIN_THRESHOLD), so models stay current.
    try:
        import threading as _al_thread
        from behedr_server.core.active_learning import initialize as al_init, \
            _retrain_with_feedback as _al_retrain

        al_init()   # Load existing feedback + recalculate accuracy stats

        def _weekly_retrain_scheduler():
            """Trigger a model retrain every 7 days regardless of feedback count."""
            import time as _t
            WEEKLY = 7 * 86400
            while True:
                _t.sleep(WEEKLY)
                print("[ACTIVE LEARNING] Weekly scheduled retrain starting...")
                try:
                    _al_retrain()
                except Exception as _we:
                    print(f"[ACTIVE LEARNING] Weekly retrain error: {_we}")

        _al_thread.Thread(
            target=_weekly_retrain_scheduler,
            name="WeeklyRetrain",
            daemon=True
        ).start()
        print("[ACTIVE LEARNING] Weekly retrain scheduler started (every 7 days)")
    except Exception as e:
        print(f"[ACTIVE LEARNING] Failed to start scheduler: {e}")

    from behedr_server.routes.api       import api_bp
    from behedr_server.routes.dashboard import dash_bp
    from behedr_server.wazuh_bridge     import wazuh_bp

    app.register_blueprint(api_bp)
    app.register_blueprint(dash_bp)
    app.register_blueprint(wazuh_bp)

    gc.set_threshold(700, 10, 10)

    return app
