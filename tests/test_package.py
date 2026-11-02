import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_server_sources_parse_without_windows_imports():
    for path in (ROOT / "server/src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("behedr_agent")


def test_shared_rules_are_present():
    from behedr_common.paths import BUNDLED_RULES
    assert (BUNDLED_RULES / "behaviour_chains.yaml").is_file()
    assert len(list((BUNDLED_RULES / "yara").glob("*.yar"))) == 7
