# server/core/processor.py — Validate, normalize, deduplicate events
"""Dedup cache capped at 10 000 entries (FIFO eviction)."""
from typing import Optional
from collections import deque

_REQUIRED  = ["system_id", "event", "parent", "child", "pid", "time"]
MAX_SEEN   = 10_000
_seen_keys: set   = set()
_seen_fifo: deque = deque()


def validate(raw) -> bool:
    from behedr_common.validation import valid_process_event
    return valid_process_event(raw)


def normalize(raw) -> dict:
    return {
        "system_id": str(raw["system_id"]).strip(),
        "event":     "process_spawn",
        "parent":    str(raw["parent"]).lower().strip(),
        "child":     str(raw["child"]).lower().strip(),
        "pid":       int(raw["pid"]),
        "time":      int(raw["time"]),
        "cmdline":   str(raw.get("cmdline", "")).strip()[:2048],
        "sha256":    str(raw.get("sha256", "")).strip().lower(),
        "exe_path":  str(raw.get("exe_path", "")).strip(),
        "user":      str(raw.get("user", "")).strip(),
    }


def _track(key) -> bool:
    if key in _seen_keys:
        return False
    if len(_seen_keys) >= MAX_SEEN:
        _seen_keys.discard(_seen_fifo.popleft())
    _seen_keys.add(key)
    _seen_fifo.append(key)
    return True


def process(raw) -> Optional[dict]:
    if not validate(raw):
        return None
    e = normalize(raw)
    if not _track((e["system_id"], e["parent"], e["child"], e["time"])):
        return None
    return e
