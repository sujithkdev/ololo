# server/core/sysmon_handlers.py — Sysmon-specific detection handlers
"""
Handles the high-fidelity events that only Sysmon can provide:

  handle_sysmon_inject(event)       Ev8  CreateRemoteThread — T1055
  handle_sysmon_lsass(event)        Ev10 ProcessAccess on lsass.exe — T1003
  handle_sysmon_dns(event)          Ev22 DnsQuery — C2 domain IOC check
  handle_sysmon_pipe(event)         Ev17/18 Named pipe — Cobalt Strike
  handle_sysmon_hollowing(event)    Ev25 ProcessTampering — T1055.012
  handle_sysmon_ads(event)          Ev15 Alternate Data Stream — T1564.004
  handle_sysmon_registry(event)     Ev12/13 Registry persistence — T1547.001
  handle_sysmon_network(event)      Ev3 NetworkConnect — feeds L6 + IOC domain
  handle_sysmon_dll(event)          Ev7 ImageLoad — feeds L9 + unsigned DLL check

All handlers:
  - Are called from handle_etw_event() in detector.py
  - Use _make_alert() + _emit() exactly like the existing layers
  - Have NO external dependencies — only stdlib + existing server modules
  - Degrade gracefully (return [] on any error)

Integration point:
  detector.py handle_etw_event() dispatches on event["source"] prefix
  "sysmon_" → route to this module.
"""

import re
import time
import os
import threading
from collections import defaultdict, deque
from typing import List

# ── Known-safe patterns (suppress obvious false positives) ────────────────────

# Access masks for LSASS that are suspicious (credential read)
# 0x1010 = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
# 0x1410 = + PROCESS_QUERY_LIMITED_INFORMATION
# 0x1fffff = PROCESS_ALL_ACCESS
_SUSPICIOUS_LSASS_MASKS = {
    "0x1010", "0x1410", "0x1438", "0x143a",
    "0x1fffff", "0x40",  "0x1000",
}

# Legitimate LSASS callers — suppress to reduce FP
_SAFE_LSASS_CALLERS = {
    "werfault.exe", "taskmgr.exe", "procexp.exe", "procexp64.exe",
    "mssense.exe",  "csrss.exe",   "services.exe",
    "antimalware service executable",
}

# Cobalt Strike default named pipe names (partial match)
_CS_PIPE_PATTERNS = [
    r"\\msagent_",    r"\\postex_",     r"\\postex_ssh_",
    r"\\mojo\.",      r"\\interprocess_", r"\\ntsvcs",
    r"\\wkssvc",      r"\\browser",     r"\\srvsvc",
    r"\\msse-",       r"\\status_",     r"\\win_svc",
    r"\\searchindexer", r"\\advapi_",   r"\\DserNamePipe",
    r"\\Winsock2\\CatalogChangeListener",
]
_CS_PIPE_RE = [re.compile(p, re.IGNORECASE) for p in _CS_PIPE_PATTERNS]

# Persistence-relevant registry keys
_PERSIST_KEYS = [
    "currentversion\\run",
    "currentversion\\runonce",
    "currentversion\\runservices",
    "policies\\explorer\\run",
    "currentversion\\winlogon",
    "userinit",
    "shell\\open\\command",
    "command processor\\autorun",
    "environment",
    r"system\currentcontrolset\services",
    "appinit_dlls",
    "image file execution options",
    "debugger",
]

# ADS stream names that are legitimate (Zone.Identifier is always OK)
_SAFE_ADS_STREAMS = {":zone.identifier", ":com.dropbox.attrs", ":com.apple.quarantine"}

# DNS domains that are trivially benign (suppress noise)
_BENIGN_DOMAIN_SUFFIXES = (
    ".windows.com", ".microsoft.com", ".windowsupdate.com",
    ".office.com", ".office365.com", ".live.com",
    ".akamaiedge.net", ".akamai.net", ".cloudfront.net",
    ".amazonaws.com",
)

# ── Alert dedup (per system, per alert reason) ────────────────────────────────
_dedup: dict = defaultdict(dict)   # {system_id: {reason_key: last_ts}}
_dedup_lock  = threading.Lock()
_DEDUP_TTL   = 300   # 5 min — matches server ALERT_DEDUP_SECS


def _is_dup(system_id: str, key: str) -> bool:
    now = time.time()
    with _dedup_lock:
        last = _dedup[system_id].get(key, 0)
        if now - last < _DEDUP_TTL:
            return True
        _dedup[system_id][key] = now
        return False


# ── Alert factory (mirrors _make_alert in detector.py) ───────────────────────

def _alert(system_id: str, process: str, score: int, level: str,
           reason: str, technique: str, confidence: str = "HIGH",
           ioc_hit: str = "") -> dict:
    return {
        "system_id":  system_id,
        "process":    process,
        "risk_score": score,
        "risk_level": level,
        "reason":     reason,
        "technique":  technique,
        "confidence": confidence,
        "ioc_hit":    ioc_hit,
        "timestamp":  int(time.time()),
    }


def _emit(alert: dict):
    """Save alert and run the full emit pipeline (notify, playbooks, auto-response)."""
    try:
        from behedr_server.core.detector import _emit as detector_emit
        detector_emit(alert)
    except Exception as e:
        # Fallback: save directly if detector import fails
        try:
            from behedr_server.database.storage import save_alert
            save_alert(alert)
        except Exception:
            pass


# ═════════════════════════════════════════════════════════════════════════════
# Ev8 — CreateRemoteThread (Process Injection T1055)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_inject(event: dict) -> List[dict]:
    """
    Sysmon Event 8 — CreateRemoteThread.
    Source process injecting a thread into target process = T1055.
    Always CRITICAL unless source == target (legitimate thread creation).
    """
    sid    = event.get("system_id", "")
    src    = event.get("source_process", "unknown")
    tgt    = event.get("target_process", "unknown")
    src_path = event.get("source_path", "").lower()
    tgt_path = event.get("target_path", "").lower()

    if not sid:
        return []

    # Self-injection is normal for some processes
    if src.lower() == tgt.lower():
        return []

    # Known-safe injectors (Windows internals)
    safe_injectors = {"csrss.exe", "wininit.exe", "services.exe", "svchost.exe"}
    safe_targets   = {"conhost.exe"}   # svchost→conhost is normal console host
    if src.lower() in safe_injectors and tgt.lower() in safe_targets:
        return []

    reason = (
        f"INJECTION: '{src}' created remote thread in '{tgt}' "
        f"(CreateRemoteThread T1055)"
    )
    dedup_key = f"inject:{src}:{tgt}"
    if _is_dup(sid, dedup_key):
        return []

    a = _alert(
        sid, f"{src} → {tgt}", 95, "CRITICAL",
        reason, "T1055",
        confidence="HIGH"
    )
    _emit(a)
    return [a]


# ═════════════════════════════════════════════════════════════════════════════
# Ev10 — ProcessAccess on lsass.exe (Credential Dump T1003.001)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_lsass(event: dict) -> List[dict]:
    """
    Sysmon Event 10 — ProcessAccess targeting lsass.exe.
    Read access to LSASS memory = credential dump.
    CRITICAL — this is what Mimikatz, ProcDump, and Cobalt Strike all do.
    """
    sid    = event.get("system_id", "")
    src    = event.get("source_process", "unknown").lower()
    mask   = event.get("access_mask", "").lower()
    trace  = event.get("call_trace", "").lower()

    if not sid:
        return []

    if src in _SAFE_LSASS_CALLERS:
        return []

    # Check access mask — only alert on suspicious masks
    if mask and mask not in _SUSPICIOUS_LSASS_MASKS:
        # Translate to int for range check
        try:
            mask_int = int(mask, 16)
            # Allow query-only (0x400 PROCESS_QUERY_INFORMATION)
            if mask_int <= 0x400 and mask_int not in {0x40, 0x10, 0x20}:
                return []
        except ValueError:
            pass

    reason = (
        f"LSASS ACCESS: '{src}' accessed lsass.exe memory "
        f"(mask={mask}) — credential dump T1003.001"
    )
    # Add call trace context if useful (shows Mimikatz / MiniDump)
    if trace and "unknown" not in trace and len(trace) < 200:
        reason += f" | CallTrace: {trace[:120]}"

    dedup_key = f"lsass:{src}:{mask}"
    if _is_dup(sid, dedup_key):
        return []

    a = _alert(
        sid, src, 98, "CRITICAL",
        reason, "T1003.001",
        confidence="HIGH"
    )
    _emit(a)
    return [a]


# ═════════════════════════════════════════════════════════════════════════════
# Ev22 — DnsQuery (C2 domain IOC check)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_dns(event: dict) -> List[dict]:
    """
    Sysmon Event 22 — DNSQuery.
    Checks domain against the IOC feed (check_ioc) and runs DGA scoring.
    Also flags queries from non-browser processes to suspicious TLDs.
    """
    sid     = event.get("system_id", "")
    domain  = event.get("domain", "").lower().strip().rstrip(".")
    process = event.get("process", "unknown").lower()

    if not sid or not domain:
        return []

    # Skip trivially benign domains
    for suffix in _BENIGN_DOMAIN_SUFFIXES:
        if domain.endswith(suffix):
            return []

    alerts = []

    # ── IOC feed check ────────────────────────────────────────────────────
    try:
        from behedr_server.threatintel import check_ioc
        hits = check_ioc(sha256="", name="", ip="", domain=domain)
        for hit in hits:
            reason = (
                f"IOC DOMAIN: '{process}' queried blocked domain '{domain}' "
                f"— {hit.get('label', '')} [{hit.get('source', '')}]"
            )
            dedup_key = f"dns_ioc:{domain}"
            if not _is_dup(sid, dedup_key):
                a = _alert(
                    sid, process, 90, "CRITICAL",
                    reason, "T1071.001",
                    confidence="HIGH", ioc_hit=domain
                )
                _emit(a)
                alerts.append(a)
    except Exception:
        pass

    # ── Enhanced threat intel check ───────────────────────────────────────
    try:
        from behedr_server.core.threat_intel_enhanced import check_enhanced
        enhanced = check_enhanced(domain=domain)
        for hit in enhanced:
            reason = (
                f"THREAT INTEL DOMAIN: '{process}' queried '{domain}' "
                f"— {hit.get('label', '')} [{hit.get('feed', '')}]"
            )
            dedup_key = f"dns_ti:{domain}"
            if not _is_dup(sid, dedup_key):
                a = _alert(
                    sid, process, 85, "HIGH",
                    reason, "T1071.001",
                    confidence="HIGH", ioc_hit=domain
                )
                _emit(a)
                alerts.append(a)
    except Exception:
        pass

    # ── DGA-style domain scoring (high entropy + no known TLD) ───────────
    if not alerts:
        dga_score = _score_dga(domain)
        if dga_score >= 70:
            reason = (
                f"POSSIBLE DGA DOMAIN: '{process}' queried '{domain}' "
                f"(DGA score {dga_score} — high entropy, unusual structure)"
            )
            dedup_key = f"dns_dga:{domain}"
            if not _is_dup(sid, dedup_key):
                a = _alert(
                    sid, process, dga_score, "HIGH",
                    reason, "T1568.002",
                    confidence="MEDIUM"
                )
                _emit(a)
                alerts.append(a)

    # ── Non-browser process making DNS to suspicious TLD ─────────────────
    _SUSPICIOUS_TLDS = {".xyz", ".top", ".pw", ".cc", ".tk", ".gq", ".ml", ".cf"}
    domain_tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    _BROWSER_PROCS = {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
                      "brave.exe", "opera.exe"}
    if domain_tld in _SUSPICIOUS_TLDS and process not in _BROWSER_PROCS and not alerts:
        reason = (
            f"SUSPICIOUS TLD: '{process}' queried '{domain}' "
            f"(non-browser process using suspicious TLD '{domain_tld}')"
        )
        dedup_key = f"dns_tld:{process}:{domain_tld}"
        if not _is_dup(sid, dedup_key):
            a = _alert(
                sid, process, 55, "MEDIUM",
                reason, "T1071.001",
                confidence="MEDIUM"
            )
            _emit(a)
            alerts.append(a)

    return alerts


def _score_dga(domain: str) -> int:
    """
    Score a domain for DGA (Domain Generation Algorithm) likelihood.
    Returns 0–100.  Threshold for alert: >= 70.
    """
    import math

    # Strip subdomains for analysis
    parts = domain.split(".")
    if len(parts) < 2:
        return 0
    label = parts[-2]   # e.g. "xkj3mwqp" from "xkj3mwqp.com"

    if len(label) < 8:
        return 0   # Short names are usually legit

    # Shannon entropy of the label
    freq: dict = {}
    for c in label:
        freq[c] = freq.get(c, 0) + 1
    n = len(label)
    entropy = -sum((f / n) * math.log2(f / n) for f in freq.values())

    # Consonant ratio (DGA domains are often consonant-heavy)
    vowels = set("aeiou")
    consonant_ratio = sum(1 for c in label if c.isalpha() and c not in vowels) / max(n, 1)

    # Digit ratio
    digit_ratio = sum(1 for c in label if c.isdigit()) / max(n, 1)

    score = 0
    if entropy > 3.5:        score += 30
    if entropy > 4.0:        score += 20
    if consonant_ratio > 0.7: score += 20
    if digit_ratio > 0.3:    score += 15
    if len(label) > 16:      score += 15

    return min(score, 100)


# ═════════════════════════════════════════════════════════════════════════════
# Ev17/18 — Named Pipe (Cobalt Strike / lateral movement T1559)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_pipe(event: dict) -> List[dict]:
    """
    Sysmon Events 17/18 — PipeCreated / PipeConnected.
    Matches against known Cobalt Strike default pipe name patterns.
    Also flags suspicious pipe names created by unusual processes.
    """
    sid       = event.get("system_id", "")
    process   = event.get("process", "unknown")
    pipe_name = event.get("pipe_name", "")
    action    = event.get("action", "")

    if not sid or not pipe_name:
        return []

    alerts = []

    # ── Cobalt Strike pipe name check ─────────────────────────────────────
    for pattern in _CS_PIPE_RE:
        if pattern.search(pipe_name):
            reason = (
                f"COBALT STRIKE PIPE: '{process}' {action}d pipe '{pipe_name}' "
                f"— matches known Cobalt Strike named pipe pattern (T1559.001)"
            )
            dedup_key = f"pipe_cs:{pipe_name}"
            if not _is_dup(sid, dedup_key):
                a = _alert(
                    sid, process, 90, "CRITICAL",
                    reason, "T1559.001",
                    confidence="HIGH"
                )
                _emit(a)
                alerts.append(a)
            break

    # ── Generic suspicious pipe from non-system process ───────────────────
    if not alerts:
        _SUSPICIOUS_PIPE_NAMES = [
            "\\psexec", "\\paexec", "\\smbexec",
            "\\remcom", "\\csexec", "\\atsvc",
        ]
        pipe_lower = pipe_name.lower()
        for sp in _SUSPICIOUS_PIPE_NAMES:
            if sp in pipe_lower:
                reason = (
                    f"LATERAL MOVEMENT PIPE: '{process}' {action}d pipe '{pipe_name}' "
                    f"— PsExec/remote exec pattern (T1570)"
                )
                dedup_key = f"pipe_lat:{pipe_name}"
                if not _is_dup(sid, dedup_key):
                    a = _alert(
                        sid, process, 80, "HIGH",
                        reason, "T1570",
                        confidence="MEDIUM"
                    )
                    _emit(a)
                    alerts.append(a)
                break

    return alerts


# ═════════════════════════════════════════════════════════════════════════════
# Ev25 — ProcessTampering (Process Hollowing T1055.012)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_hollowing(event: dict) -> List[dict]:
    """
    Sysmon Event 25 — ProcessTampering.
    Direct kernel-level detection of process hollowing / herpaderping.
    Always CRITICAL — no false positives from legitimate software.
    """
    sid         = event.get("system_id", "")
    process     = event.get("process", "unknown")
    tamper_type = event.get("tamper_type", "")

    if not sid:
        return []

    reason = (
        f"PROCESS HOLLOWING: '{process}' tampered "
        f"({tamper_type}) — T1055.012 (Sysmon Ev25 kernel detection)"
    )
    dedup_key = f"hollow:{process}"
    if _is_dup(sid, dedup_key):
        return []

    a = _alert(
        sid, process, 98, "CRITICAL",
        reason, "T1055.012",
        confidence="HIGH"
    )
    _emit(a)
    return [a]


# ═════════════════════════════════════════════════════════════════════════════
# Ev15 — FileCreateStreamHash (Alternate Data Streams T1564.004)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_ads(event: dict) -> List[dict]:
    """
    Sysmon Event 15 — FileCreateStreamHash.
    Flags ADS (Alternate Data Streams) that are not Zone.Identifier.
    Used by malware to hide payloads inside legitimate files.
    """
    sid       = event.get("system_id", "")
    process   = event.get("process", "unknown")
    file_path = event.get("file_path", "").lower()

    if not sid or not file_path:
        return []

    # Extract the stream name (after the colon)
    stream = ""
    if ":" in file_path:
        stream = ":" + file_path.split(":", 1)[-1]

    # Ignore safe streams
    if stream.lower() in _SAFE_ADS_STREAMS:
        return []

    reason = (
        f"ALTERNATE DATA STREAM: '{process}' created ADS '{file_path}' "
        f"— data hidden inside file stream (T1564.004)"
    )
    dedup_key = f"ads:{file_path}"
    if _is_dup(sid, dedup_key):
        return []

    a = _alert(
        sid, process, 70, "HIGH",
        reason, "T1564.004",
        confidence="MEDIUM"
    )
    _emit(a)
    return [a]


# ═════════════════════════════════════════════════════════════════════════════
# Ev12/13 — Registry (Persistence T1547.001)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_registry(event: dict) -> List[dict]:
    """
    Sysmon Events 12/13 — RegistryObjectAddedOrDeleted / RegistryValueSet.
    Flags writes to persistence-relevant registry keys.
    """
    sid     = event.get("system_id", "")
    process = event.get("process", "unknown").lower()
    reg_key = event.get("reg_key", "").lower()

    if not sid or not reg_key:
        return []

    # Skip trusted updaters
    _SAFE_REG_WRITERS = {
        "msiexec.exe", "trustedinstaller.exe", "tiworker.exe",
        "wuauclt.exe", "svchost.exe", "setup.exe", "install.exe",
    }
    if process in _SAFE_REG_WRITERS:
        return []

    matched_key = ""
    for pk in _PERSIST_KEYS:
        if pk in reg_key:
            matched_key = pk
            break

    if not matched_key:
        return []

    reason = (
        f"REGISTRY PERSISTENCE: '{process}' wrote to '{reg_key}' "
        f"(persistence key match: '{matched_key}') — T1547.001"
    )
    dedup_key = f"reg:{process}:{reg_key[:80]}"
    if _is_dup(sid, dedup_key):
        return []

    # Score higher for Run keys, lower for less critical keys
    score = 85 if "currentversion\\run" in reg_key else 65

    a = _alert(
        sid, process, score,
        "CRITICAL" if score >= 85 else "HIGH",
        reason, "T1547.001",
        confidence="HIGH" if score >= 85 else "MEDIUM"
    )
    _emit(a)
    return [a]


# ═════════════════════════════════════════════════════════════════════════════
# Ev3 — NetworkConnect (feeds L6 + domain IOC check)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_network(event: dict) -> List[dict]:
    """
    Sysmon Event 3 — NetworkConnect.
    Feeds the existing L6 beaconing detector (add_network_event) and
    additionally checks the DNS hostname against the IOC feed.
    """
    sid       = event.get("system_id", "")
    process   = event.get("process", "unknown")
    remote_ip = event.get("remote_ip", "")
    port      = int(event.get("remote_port", 0))
    hostname  = event.get("remote_host", "").lower().rstrip(".")
    is_int    = bool(event.get("is_internal", False))

    if not sid or not remote_ip:
        return []

    # Feed into L6 beaconing detector
    try:
        from behedr_server.core.detector import add_network_event
        add_network_event(sid, process, remote_ip, port, is_internal=is_int)
    except Exception:
        pass

    # DNS hostname IOC check (richer than IP — catches CDN-fronted C2)
    alerts = []
    if hostname:
        dns_ev = {
            "system_id": sid,
            "process":   process,
            "domain":    hostname,
        }
        alerts = handle_sysmon_dns(dns_ev)

    return alerts


# ═════════════════════════════════════════════════════════════════════════════
# Ev7 — ImageLoad (feeds L9 DLL hijacking + unsigned DLL alert)
# ═════════════════════════════════════════════════════════════════════════════

def handle_sysmon_dll(event: dict) -> List[dict]:
    """
    Sysmon Event 7 — ImageLoad (DLL loaded into a process).
    Feeds the existing L9 DLL hijacking check and fires its own alert
    for unsigned DLLs loaded from suspicious paths.
    """
    sid      = event.get("system_id", "")
    process  = event.get("process", "unknown")
    dll_name = event.get("dll_name", "")
    dll_path = event.get("dll_path", "").lower()
    signed   = bool(event.get("signed", True))
    sha256   = event.get("sha256", "")

    if not sid:
        return []

    # Feed into existing L9 DLL hijacking detector
    try:
        from behedr_server.core.dll_monitor import add_dll_event
        add_dll_event(
            system_id=sid,
            process=process,
            dll_name=dll_name,
            dll_path=event.get("dll_path", ""),
            signed=signed,
        )
    except Exception:
        pass

    alerts = []

    # ── Unsigned DLL from suspicious path ─────────────────────────────────
    if not signed:
        _SUSPICIOUS_PATHS = ["\\appdata\\", "\\temp\\", "\\public\\",
                             "\\programdata\\", "\\downloads\\"]
        for sp in _SUSPICIOUS_PATHS:
            if sp in dll_path:
                reason = (
                    f"UNSIGNED DLL: '{process}' loaded unsigned DLL "
                    f"'{dll_name}' from suspicious path '{event.get('dll_path','')}' "
                    f"— possible DLL hijacking T1574.001"
                )
                dedup_key = f"unsigneddll:{dll_path}"
                if not _is_dup(sid, dedup_key):
                    a = _alert(
                        sid, process, 75, "HIGH",
                        reason, "T1574.001",
                        confidence="MEDIUM"
                    )
                    _emit(a)
                    alerts.append(a)
                break

    # ── Hash check on loaded DLL ──────────────────────────────────────────
    if sha256:
        try:
            from behedr_server.core.hash_db import check_hash
            result = check_hash(sha256)
            if result:
                family = result.get("family", "Unknown")
                reason = (
                    f"MALWARE DLL HASH: '{process}' loaded known-malicious DLL "
                    f"'{dll_name}' — {family} [{result.get('source','')}]"
                )
                dedup_key = f"dllhash:{sha256}"
                if not _is_dup(sid, dedup_key):
                    a = _alert(
                        sid, process, 95, "CRITICAL",
                        reason, "T1204.002",
                        confidence="HIGH", ioc_hit=sha256
                    )
                    _emit(a)
                    alerts.append(a)
        except Exception:
            pass

    return alerts


# ═════════════════════════════════════════════════════════════════════════════
# Main dispatcher — called from detector.handle_etw_event()
# ═════════════════════════════════════════════════════════════════════════════

_HANDLER_MAP = {
    "sysmon_inject":       handle_sysmon_inject,
    "sysmon_lsass_access": handle_sysmon_lsass,
    "sysmon_dns":          handle_sysmon_dns,
    "sysmon_pipe":         handle_sysmon_pipe,
    "sysmon_hollowing":    handle_sysmon_hollowing,
    "sysmon_ads":          handle_sysmon_ads,
    "sysmon_registry":     handle_sysmon_registry,
    "sysmon_network":      handle_sysmon_network,
    "sysmon_dll_load":     handle_sysmon_dll,
    # file events just feed existing layers — handled in api.py routing
}


def dispatch(event: dict) -> List[dict]:
    """
    Main entry point.  Called by detector.handle_etw_event() for any
    event whose "source" field starts with "sysmon_".
    """
    etype   = event.get("event", "")
    handler = _HANDLER_MAP.get(etype)
    if handler is None:
        return []
    try:
        return handler(event) or []
    except Exception as e:
        import logging
        logging.getLogger("sysmon_handlers").error(
            "Handler error for %s: %s", etype, e
        )
        return []
