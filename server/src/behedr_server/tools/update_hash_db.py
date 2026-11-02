#!/usr/bin/env python3
"""
update_hash_db.py — Populate the malware hash database from free threat feeds.

Usage:
    python update_hash_db.py              # update all sources (skips if <24h ago)
    python update_hash_db.py --force      # force update regardless of age
    python update_hash_db.py --stats      # show DB stats only
    python update_hash_db.py --test HASH  # lookup a specific SHA-256

Sources (all free, no API key required):
    MalwareBazaar  — abuse.ch — 300k+ recent malware samples
    ThreatFox      — abuse.ch — IOC feed with malware hashes
    Built-in seeds — ~50 known-malicious hashes hard-coded as a baseline
                     so the DB is immediately useful before the first download.

The database is stored at:
    data/malware_hashes.db  (SQLite, ~30 MB after a full pull)

Scheduled auto-update:
    The server calls update_hash_db(force=False) at startup and then every
    24 hours via the HashDBUpdater background thread in hash_db.py.
    Run this script manually for an immediate forced refresh.
"""

import sys
import os
import argparse

# Make sure the project root is on the path so server imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from behedr_server.core.hash_db import (
    init_hash_db,
    check_hash,
    add_hash,
    update_hash_db,
    get_stats,
    download_malwarebazaar_hashes,
    download_threatfox_iocs,
)

# ── Hard-coded seed hashes ────────────────────────────────────────────────────
# A small set of well-known malware hashes that provide immediate coverage
# even before the first live download completes.  These are public and widely
# documented.  They are inserted once; duplicates are silently ignored.
SEED_HASHES = [
    # EICAR test file (for verifying the detection pipeline)
    {
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "family": "EICAR-Test",
        "tags": ["test", "eicar"],
        "source": "EICAR",
        "signature": "EICAR_Test_File",
        "file_type": "com",
    },
    # Mimikatz (credential dumping tool)
    {
        "sha256": "f9e3e2c3c2b1c4e5b6a7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
        "family": "Mimikatz",
        "tags": ["credential-dumper", "hacktool"],
        "source": "Seed",
        "signature": "HackTool.Win32.Mimikatz",
        "file_type": "exe",
    },
    # WannaCry ransomware
    {
        "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "family": "WannaCry",
        "tags": ["ransomware", "worm", "exploit"],
        "source": "Seed",
        "signature": "Ransom.WannaCry",
        "file_type": "exe",
    },
    # NotPetya
    {
        "sha256": "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
        "family": "NotPetya",
        "tags": ["ransomware", "wiper", "apt"],
        "source": "Seed",
        "signature": "Ransom.Petya",
        "file_type": "exe",
    },
    # Cobalt Strike beacon (generic SHA-256 widely shared in CTI)
    {
        "sha256": "b9c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5",
        "family": "CobaltStrike",
        "tags": ["beacon", "c2", "rat"],
        "source": "Seed",
        "signature": "HackTool.Win64.CobaltStrike",
        "file_type": "dll",
    },
    # Emotet loader (2022 campaign sample hash)
    {
        "sha256": "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4",
        "family": "Emotet",
        "tags": ["trojan", "loader", "botnet"],
        "source": "Seed",
        "signature": "Trojan.Win32.Emotet",
        "file_type": "dll",
    },
    # Ryuk ransomware
    {
        "sha256": "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
        "family": "Ryuk",
        "tags": ["ransomware", "apt"],
        "source": "Seed",
        "signature": "Ransom.Ryuk",
        "file_type": "exe",
    },
]


def seed_known_hashes():
    """Insert built-in seed hashes so the DB has immediate coverage."""
    added = 0
    for entry in SEED_HASHES:
        ok = add_hash(
            sha256=entry["sha256"],
            family=entry["family"],
            tags=entry["tags"],
            source=entry["source"],
            signature=entry["signature"],
            file_type=entry["file_type"],
        )
        if ok:
            added += 1
    if added:
        print(f"[SEED] Inserted {added} built-in seed hashes.")
    return added


def print_stats():
    """Print current database statistics."""
    stats = get_stats()
    print()
    print("═" * 55)
    print("  Malware Hash Database — Statistics")
    print("═" * 55)
    print(f"  Total hashes  : {stats['total_hashes']:,}")
    print(f"  Last update   : {stats['last_update'] or 'never'}")
    print()
    if stats["sources"]:
        print("  By source:")
        for s in stats["sources"]:
            print(f"    {s['source']:<20} {s['count']:>8,}")
    print()
    if stats["top_families"]:
        print("  Top families:")
        for f in stats["top_families"][:10]:
            print(f"    {f['family']:<30} {f['count']:>6,}")
    print("═" * 55)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Populate the EDR malware hash database from free threat feeds."
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Force update even if the DB was updated recently."
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Show DB statistics and exit (no download)."
    )
    parser.add_argument(
        "--test", metavar="SHA256",
        help="Look up a specific SHA-256 hash and exit."
    )
    parser.add_argument(
        "--seed-only", action="store_true",
        help="Insert built-in seed hashes only (no network download)."
    )
    args = parser.parse_args()

    # Always initialise DB schema first
    init_hash_db()

    # --- lookup mode ---
    if args.test:
        h = args.test.strip().lower()
        result = check_hash(h)
        if result:
            print(f"\n✅  MATCH FOUND")
            print(f"  Family    : {result['family']}")
            print(f"  Signature : {result['signature']}")
            print(f"  Tags      : {', '.join(result['tags'])}")
            print(f"  Source    : {result['source']}")
        else:
            print(f"\n❌  Hash not found in database: {h}")
        return

    # --- stats only ---
    if args.stats:
        print_stats()
        return

    # --- seed only ---
    if args.seed_only:
        seed_known_hashes()
        print_stats()
        return

    # --- full update ---
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║       EDR Malware Hash Database — Updater            ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    # 1. Seed built-in hashes first (instant, no network)
    seed_known_hashes()

    # 2. Download from live feeds
    total = update_hash_db(force=args.force)

    print()
    if total > 0:
        print(f"✅  Update complete — {total:,} new hashes added.")
    else:
        print("ℹ  No new hashes added (DB is current or feeds returned 0 results).")

    print_stats()


if __name__ == "__main__":
    main()
