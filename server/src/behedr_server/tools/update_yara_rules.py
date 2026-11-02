#!/usr/bin/env python3
"""
update_yara_rules.py — Download/update community YARA rule packs.

Usage:
    python update_yara_rules.py              # download all packs
    python update_yara_rules.py --compile    # download + compile
    python update_yara_rules.py --list       # list downloaded rule files
    python update_yara_rules.py --test       # test EICAR detection

Bundled rules (always present, no download needed):
    rules/yara/credential_dumping.yar  — Mimikatz, LaZagne, LSASS dump
    rules/yara/ransomware.yar          — WannaCry, Ryuk, LockBit, Conti, generic
    rules/yara/lolbins_and_shellcode.yar — PS encoded cmds, certutil, rundll32
    rules/yara/c2_and_backdoors.yar    — Cobalt Strike, Metasploit, Sliver, njRAT
    rules/yara/persistence.yar         — Registry Run, schtasks, WMI, services
    rules/yara/defense_evasion.yar     — AMSI bypass, ETW patch, UAC bypass
    rules/yara/test_and_eicar.yar      — EICAR + smoke-test markers

Downloadable community packs (optional):
    YaraRules project  — https://github.com/Yara-Rules/rules
    Elastic detection  — https://github.com/elastic/protections-artifacts
    Neo23x0 (Florian)  — https://github.com/Neo23x0/signature-base
"""

import sys
import os
import argparse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from behedr_server.config import RULES_DIR as _RULES_DIR
RULES_DIR = Path(_RULES_DIR) / "yara"

# Community rule packs from public GitHub repos (no auth required)
COMMUNITY_PACKS = [
    {
        "name": "yara_rules_malware_index",
        "url":  "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar",
        "description": "EICAR test rule (YaraRules project)",
    },
    {
        "name": "yara_rules_ransomware_ryuk",
        "url":  "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RANSOM_Ryuk.yar",
        "description": "Ryuk ransomware (YaraRules project)",
    },
    {
        "name": "yara_rules_apt_apt29",
        "url":  "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT29.yar",
        "description": "APT29 (Cozy Bear) detection rules",
    },
    {
        "name": "yara_rules_rat_generic",
        "url":  "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RAT_Generic.yar",
        "description": "Generic RAT detection (YaraRules project)",
    },
    {
        "name": "yara_rules_webshells",
        "url":  "https://raw.githubusercontent.com/Yara-Rules/rules/master/webshells/WShell_Generic.yar",
        "description": "Generic webshell detection",
    },
]


def list_rules():
    """Print all rule files currently in rules/yara/."""
    yar_files = sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara"))
    if not yar_files:
        print("No rule files found. Run without --list to download rules.")
        return

    total_rules = 0
    print()
    print(f"{'File':<45}  {'Rules':>6}  {'Size':>8}")
    print("─" * 65)
    for yf in yar_files:
        try:
            content = yf.read_text(encoding="utf-8", errors="ignore")
            rule_count = content.count("\nrule ") + content.count("^rule ")
            # Simple count by looking for "rule " at start of line
            rule_count = sum(1 for line in content.splitlines()
                             if line.strip().startswith("rule "))
            size_kb = yf.stat().st_size / 1024
            print(f"  {yf.name:<43}  {rule_count:>6}  {size_kb:>6.1f} KB")
            total_rules += rule_count
        except Exception as e:
            print(f"  {yf.name:<43}  (error: {e})")
    print("─" * 65)
    print(f"  {'TOTAL':<43}  {total_rules:>6}")
    print()


def download_community_packs():
    """Download optional community YARA rule packs from GitHub."""
    try:
        import requests
    except ImportError:
        print("requests library not installed. Run: pip install requests")
        return 0

    RULES_DIR.mkdir(parents=True, exist_ok=True)
    success = 0

    print()
    print("Downloading community YARA rule packs...")
    print()
    for pack in COMMUNITY_PACKS:
        dest = RULES_DIR / f"{pack['name']}.yar"
        try:
            print(f"  ↓  {pack['description']}")
            r = requests.get(pack["url"], timeout=30)
            if r.status_code == 200:
                dest.write_text(r.text, encoding="utf-8")
                rule_count = sum(1 for line in r.text.splitlines()
                                 if line.strip().startswith("rule "))
                print(f"     ✅ Saved → {dest.name}  ({rule_count} rules)")
                success += 1
            else:
                print(f"     ❌ HTTP {r.status_code}")
        except Exception as e:
            print(f"     ❌ {e}")
    print()
    print(f"Downloaded {success}/{len(COMMUNITY_PACKS)} packs.")
    return success


def compile_all():
    """Compile all .yar files into a single compiled ruleset."""
    try:
        import yara
    except ImportError:
        print("yara-python not installed. Run: pip install yara-python")
        return False

    yar_files = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
    if not yar_files:
        print("No rule files to compile.")
        return False

    print(f"\nCompiling {len(yar_files)} rule files...")
    namespaces = {f.stem: str(f) for f in yar_files}
    compiled_path = RULES_DIR / "compiled_rules.yrc"

    errors = []
    for ns, path in list(namespaces.items()):
        try:
            yara.compile(filepath=path)   # syntax check individual file
        except yara.Error as e:
            print(f"  ⚠  Syntax error in {ns}.yar — skipping: {e}")
            del namespaces[ns]
            errors.append(ns)

    if not namespaces:
        print("All rule files have errors. Nothing compiled.")
        return False

    try:
        rules = yara.compile(filepaths=namespaces)
        rules.save(str(compiled_path))
        total_rules = sum(
            sum(1 for line in Path(p).read_text(errors="ignore").splitlines()
                if line.strip().startswith("rule "))
            for p in namespaces.values()
        )
        print(f"  ✅ Compiled {total_rules} rules from {len(namespaces)} files")
        print(f"     → {compiled_path}")
        if errors:
            print(f"  ⚠  Skipped {len(errors)} files with errors: {', '.join(errors)}")
        return True
    except yara.Error as e:
        print(f"  ❌ Compilation failed: {e}")
        return False


def test_detection():
    """Quick smoke test — scan EICAR string and synthetic marker."""
    try:
        import yara
    except ImportError:
        print("yara-python not installed. Run: pip install yara-python")
        return

    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    marker = b"EDR-YARA-TEST-TRIGGER-DO-NOT-USE-IN-PRODUCTION"

    compiled = RULES_DIR / "compiled_rules.yrc"
    test_yar  = RULES_DIR / "test_and_eicar.yar"

    if compiled.exists():
        rules = yara.load(str(compiled))
        source = "compiled_rules.yrc"
    elif test_yar.exists():
        rules = yara.compile(filepath=str(test_yar))
        source = "test_and_eicar.yar"
    else:
        print("No compiled rules or test_and_eicar.yar found.")
        return

    print(f"\nUsing rule source: {source}")

    for label, data in [("EICAR string", eicar), ("EDR test marker", marker)]:
        try:
            hits = rules.match(data=data)
            if hits:
                print(f"  ✅ {label} — detected by: {', '.join(m.rule for m in hits)}")
            else:
                print(f"  ❌ {label} — no match (rules may not include this pattern)")
        except yara.Error as e:
            print(f"  ⚠  {label} — scan error: {e}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Manage YARA rules for the EDR detection engine."
    )
    parser.add_argument("--list",     action="store_true", help="List all rule files")
    parser.add_argument("--download", action="store_true", help="Download community packs")
    parser.add_argument("--compile",  action="store_true", help="Compile all rules")
    parser.add_argument("--test",     action="store_true", help="Run EICAR smoke test")
    args = parser.parse_args()

    # Default: download + compile + test
    if not any([args.list, args.download, args.compile, args.test]):
        args.download = True
        args.compile  = True
        args.test     = True

    if args.list:
        list_rules()

    if args.download:
        download_community_packs()

    if args.compile:
        compile_all()

    if args.test:
        test_detection()

    if not args.list:
        print("Current rule files:")
        list_rules()


if __name__ == "__main__":
    main()
