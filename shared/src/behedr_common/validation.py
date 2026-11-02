from .events import PROCESS_REQUIRED_FIELDS

def valid_process_event(raw):
    if not isinstance(raw, dict) or not all(raw.get(k) is not None for k in PROCESS_REQUIRED_FIELDS):
        return False
    if not str(raw["system_id"]).strip() or raw["event"] != "process_spawn":
        return False
    try:
        int(raw["pid"])
        int(raw["time"])
    except (ValueError, TypeError, OverflowError):
        return False
    return True
