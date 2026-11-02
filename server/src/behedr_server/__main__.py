"""Linux/server entry point; --help never starts collectors or schedulers."""
import argparse
import os

def main():
    parser = argparse.ArgumentParser(description="BehEDR detection server")
    parser.add_argument("--dev", action="store_true", help="Use the development server (lab only)")
    parser.add_argument("--version", action="version", version="BehEDR server 0.1.0")
    args = parser.parse_args()
    from .config import _check_secrets, HOST, PORT
    if os.environ.get("EDR_DEV_MODE", "false").lower() != "true":
        _check_secrets()
        secret = os.environ.get("FLASK_SECRET_KEY", "")
        if len(secret) < 32 or secret == "edr-flask-secret-change-in-production-2026":
            parser.error("Set a unique FLASK_SECRET_KEY of at least 32 characters")
    if args.dev:
        import runpy
        runpy.run_module("behedr_server.launcher", run_name="__main__")
    else:
        if os.environ.get("EDR_TLS_ENABLED", "false").lower() == "true":
            parser.error("Production listener uses HTTP behind a TLS reverse proxy. Set EDR_TLS_ENABLED=false on the server; keep TLS enabled on agents.")
        from waitress import serve
        from . import create_app
        serve(create_app(), host=os.environ.get("EDR_HOST", HOST), port=PORT, threads=8)

if __name__ == "__main__":
    main()
