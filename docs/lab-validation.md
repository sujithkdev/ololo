# Windows–Linux lab validation

This checklist is a plan for live validation, not a report of completed deployment.
Use a disposable Windows VM and a Linux server, with `EDR_LAB_MODE=true`.
The Windows memory-scanner source remains subject to the previously reported host
security finding; do not disable security protections to work around it.

| Check | Expected evidence | Live result |
|---|---|---|
| Start server | `/health` responds, startup logs saved | Not run |
| Start agent | Registration succeeds; correct hostname | Not run |
| Heartbeats | Endpoint shown online | Not run |
| Open a benign application | Real process event arrives and is stored | Not run |
| Controlled rule test | Expected rule, endpoint and timestamp in alert | Not run |
| Harmless command | `collect_info` retrieved and result acknowledged | Not run |
| Restart | Database events and alerts retained | Not run |
| Disconnect/reconnect | Reconnection observed; any lost events documented | Not run |

Record commands/configuration, expected and actual outcomes, and relevant logs for
each row. Distinguish injected telemetry from events actually collected on Windows.

Command polling is `GET /commands/<system_id>` with the agent API key. Its JSON response
is `{"commands": [...]}`. Results are posted to `/commands/result`. Commands remain
pending until acknowledgement, so delivery is at-least-once: a lost result can cause a
repeat. Exactly-once execution, durable agent-side deduplication and per-agent identity
credentials are not implemented. Lab commands are read-only.

Server regression checks pass without executing any endpoint command. They do not
substitute for completing this checklist on real machines.

Feedback labels are stored and reviewed-alert precision is reported. Automated feedback
retraining remains explicitly unavailable; legacy `accuracy_*` fields are retained for
API compatibility and must not be reported as overall classification accuracy.
Memory-forensics, predictive scoring and advanced lateral-movement APIs return HTTP 503
with `available=false` until their missing implementations are supplied.
