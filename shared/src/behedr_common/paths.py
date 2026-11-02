"""Bundled rules and writable per-installation runtime paths."""
import os
from pathlib import Path
import shutil

BUNDLED_RULES = Path(__file__).parent / "rules"

def state_dir(component):
    override = os.environ.get("EDR_DATA_DIR" if component == "server" else "EDR_AGENT_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        base = Path(os.environ.get("PROGRAMDATA", str(Path.home()))) / "BehEDR"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "behedr"
    return base / component

def rules_dir():
    return Path(os.environ.get("EDR_RULES_DIR", str(BUNDLED_RULES))).expanduser().resolve()

def writable_rules(component="server"):
    """Seed writable rules once, keeping installed package assets read-only."""
    if os.environ.get("EDR_RULES_DIR"):
        return rules_dir()
    target = state_dir(component) / "rules"
    for source in BUNDLED_RULES.rglob("*"):
        if source.is_file():
            dest = target / source.relative_to(BUNDLED_RULES)
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                shutil.copyfile(source, dest)
    return target
