# Linux server

Use Python 3.11 and run repository commands from the root. Sysmon and Windows agent
dependencies are not needed on Linux.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./shared ./server
cp server/config/server.env.example .env
python tools/generate_secrets.py
```

Copy distinct generated secrets into `.env`; replace all placeholders and keep
`EDR_DEV_MODE=false`. Load this trusted configuration:

```bash
set -a
. ./.env
set +a
python -m behedr_server
```

Production runs one Waitress process on `EDR_HOST:EDR_PORT`. Set `EDR_HOST=127.0.0.1`
when a reverse proxy runs on the same host. Configure HTTPS using
`deploy/linux/nginx.conf.example`, replacing the hostname and certificate paths.
Expose HTTPS port 443 to agents and keep port 5000 private. Agents use
`EDR_TLS_ENABLED=true` and `EDR_PORT=443`; the internal server uses
`EDR_TLS_ENABLED=false`. Python does not automatically load the server environment file.

Sign in with the existing bootstrap account `admin / change-me-now`, then immediately
change its password. Existing authentication and response policy are preserved.

## Docker

Fill `.env` first:

```bash
docker compose up --build -d
```

Only server and shared packages enter the image. The container uses a non-root account
and named volumes for state and logs; models live under state. Its published port binds
to host loopback. Put the HTTPS proxy in front. Preserve named volumes when upgrading.

## systemd alternative

Place the repository at `/opt/behedr`, create its virtual environment and install the
packages there. Create a dedicated `behedr` system user/group. Place the filled server
configuration at `/etc/behedr/server.env`, readable only by root and the service group.
Install `deploy/linux/behedr-server.service` under `/etc/systemd/system`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now behedr-server
sudo journalctl -u behedr-server -f
```

Use Docker or systemd, not both on the same port. For local development,
`python -m behedr_server --dev` uses the legacy Flask launcher and optional direct TLS.
`--dev` does not enable `/simulate`; that remains controlled by `EDR_DEV_MODE`.

Optional frameworks in `server/requirements-ml.txt` are experimental and not installed
by default. Maintenance commands:

```bash
python -m behedr_server.tools.update_hash_db
python -m behedr_server.tools.update_yara_rules --list
```
