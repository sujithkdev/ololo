"""Existing response command vocabulary shared by both distributions."""
VALID_COMMANDS = frozenset({
    "kill_process", "restart_agent", "update_interval", "collect_info", "isolate",
    "scan", "get_processes", "get_network", "isolate_network", "restore_network",
    "collect_forensics",
})
