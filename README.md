# ololo — BehEDR Linux server

Server-only testing repository extracted from BehEDR. Includes the detection server,
dashboard, shared rules, optional ML modules, and focused integration tests.
The Windows endpoint agent is maintained separately and is not required to start this server.

## Easiest start: Docker (Linux or Windows)

Install Docker with Linux containers and Python 3. Clone this repository, then run:

```bash
git clone https://github.com/sujithkdev/ololo.git
cd ololo
python3 tools/start_docker.py
```

On Windows use `python tools/start_docker.py`. Open http://localhost:5000 and
sign in. The script creates unique secrets only on first run and writes the local
`credentials.txt`. Never upload that file or `.env`. `credentials.example.txt`
contains only bootstrap information and placeholders.

Stop with `docker compose stop`; start again with `docker compose up -d`.
Keep the named volumes to retain events and users. Port 5000 must be free; if you
already run the testml lab, stop its server before starting another checkout.

## Quick start on Linux

Use Python 3.11 or 3.12, Git, and Python venv support. On Ubuntu/Debian, install
`python3-venv` if creating a virtual environment fails.

```bash
git clone https://github.com/sujithkdev/ololo.git
cd ololo
bash scripts/setup.sh
bash scripts/run.sh
```

Open **http://127.0.0.1:5000**. Existing bootstrap login:
**admin / change-me-now** — change the password after signing in.

Setup installs `shared` and `server`, generates unique secrets in `.env` on first use,
and preserves an existing `.env`. Runtime data is stored in the ignored `data/` directory.
No Windows libraries or experimental deep-learning frameworks are installed by default.

If the server is on another machine, use SSH forwarding from your computer:

```bash
ssh -L 5000:127.0.0.1:5000 your-user@your-linux-server
```

Then open the same localhost URL. For real Windows endpoints, use HTTPS via the reverse
proxy example in `deploy/linux/nginx.conf.example`; see [Linux deployment](docs/linux-server.md).
The default listener is intentionally bound to localhost.

## Lab mode (default)

`EDR_LAB_MODE=true` disables automatic response, manual playbook execution and
disruptive commands. Only `collect_info`, `get_processes`, and `get_network` can be
queued and delivered. Previously queued disruptive commands are withheld while lab
mode is active. Experimental LSTM/GNN/VAE detection and recording are disabled.
Isolation Forest and behavioral rules remain available.

Existing `.env` files are preserved by setup. Add these explicit settings for lab tests:

```env
EDR_LAB_MODE=true
EDR_AUTO_RESPONSE=false
EDR_ADVANCED_ML=false
```

Restart after changing configuration. Turning lab mode off permits manual response
commands; automatic response also requires `EDR_AUTO_RESPONSE=true`. Experimental
deep models separately require `EDR_ADVANCED_ML=true` and their optional dependencies.
Leave those options disabled for initial integration testing.

See [lab validation checklist](docs/lab-validation.md) for the next milestone.

## Run tests

```bash
.venv/bin/python -m pip install pytest
.venv/bin/python -m pytest -q
```

Tests use temporary state and disable background workers and response emission.
They test API registration, authentication requirements, event validation, rules and
received YARA metadata. They do not measure ML accuracy or attack coverage.

## Docker alternative

Create secrets first; no Python dependencies are needed for this step:

```bash
python3 tools/generate_secrets.py --write
docker compose up --build -d
```

The container publishes `127.0.0.1:5000` and retains data in named volumes. Inspect logs:

```bash
docker compose logs -f server
```

## Layout

```text
server/src/behedr_server/   API, detection, ML, storage and dashboard
shared/src/behedr_common/   Shared event definitions and YAML/YARA rules
scripts/                   Linux setup and launch scripts
tests/                     Server regression/integration checks
deploy/linux/              systemd and HTTPS reverse-proxy examples
tools/                     Secret generation utility
```

Optional frameworks are listed in `server/requirements-ml.txt`. These are experimental:
feedback retraining is incomplete, the feedback "accuracy" metric is not overall accuracy,
and the GNN training objective needs further validation. This repository provides a runnable
research prototype, not demonstrated detection results. See [validation](docs/validation.md).

The server alone does not collect Windows telemetry. Connect an authorized Windows agent
to receive real events. No private telemetry, runtime databases, generated secrets, or
Windows memory-scanner code is included. Original copyright and license notices are
preserved in [LICENSE](LICENSE).
