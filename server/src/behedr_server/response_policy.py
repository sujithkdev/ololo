"""Central response policy, including commands queued before entering lab mode."""
from behedr_server import config
LAB_COMMANDS = frozenset({"collect_info", "get_processes", "get_network"})

def command_allowed(action):
    return not config.LAB_MODE or action in LAB_COMMANDS
