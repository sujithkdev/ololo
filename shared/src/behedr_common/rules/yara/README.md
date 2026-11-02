# YARA Rules

This directory contains YARA detection rules for the EDR engine.

## Bundled Rules (no download required)

| File | Coverage |
|---|---|
| `credential_dumping.yar` | Mimikatz, LaZagne, WCE, LSASS dump (T1003) |
| `ransomware.yar` | WannaCry, Ryuk, LockBit, Conti, REvil, generic patterns (T1486) |
| `lolbins_and_shellcode.yar` | PS encoded cmds, certutil, regsvr32, rundll32, MSBuild, shellcode stubs (T1059/T1218) |
| `c2_and_backdoors.yar` | Cobalt Strike, Metasploit, Sliver, Havoc, Empire, njRAT, AsyncRAT (T1071/T1219) |
| `persistence.yar` | Registry Run, schtasks, WMI subscriptions, service install, startup folder (T1547/T1053) |
| `defense_evasion.yar` | AMSI bypass, ETW patching, Defender disable, UAC bypass, log clearing, process hollowing (T1562/T1070) |
| `test_and_eicar.yar` | EICAR test string + EDR smoke-test marker |

## Updating / Adding Rules

Download optional community rule packs:
```bash
python update_yara_rules.py
```

This downloads from the YaraRules GitHub project and compiles all rules.

## Writing Custom Rules

```yara
rule MyCustomRule {
    meta:
        description = "What this detects"
        author      = "Your Name"
        date        = "2026-01-01"
        mitre       = "T1059.001"
        severity    = "HIGH"

    strings:
        $s1 = "malicious_string" ascii wide nocase
        $b1 = { 4D 5A 90 00 }   // PE header bytes

    condition:
        $s1 or $b1
}
```

Save as `my_rules.yar` in this directory, then recompile:
```bash
python update_yara_rules.py --compile
```

Or the server will recompile automatically on next startup when the bundled
`.yrc` cache is missing or outdated.

## Testing

```bash
python update_yara_rules.py --test
```

This scans the EICAR test string and the EDR smoke-test marker to verify
the YARA pipeline is active.
