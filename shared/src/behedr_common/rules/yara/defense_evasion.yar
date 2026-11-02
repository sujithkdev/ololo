/*
 * defense_evasion.yar
 * Detects defense evasion techniques:
 * AMSI bypass, ETW patching, security product tampering,
 * UAC bypass, log clearing, timestomping.
 */

rule AMSI_Bypass {
    meta:
        description = "Detects AMSI bypass techniques in PowerShell/scripts"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1562.001"
        severity    = "HIGH"

    strings:
        // AmsiScanBuffer patch
        $p1 = "AmsiScanBuffer" ascii wide nocase
        $p2 = "AmsiInitialize" ascii wide nocase
        $p3 = "amsiContext" ascii wide nocase
        // Common PowerShell AMSI bypass strings
        $ps1 = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')" ascii wide
        $ps2 = "'amsiInitFailed'" ascii wide nocase
        $ps3 = "amsiInitFailed" ascii wide
        $ps4 = "Disable-AmsiProvider" ascii wide nocase
        // Patch bytes for AmsiScanBuffer (return 0/AMSI_RESULT_CLEAN)
        $b1 = { B8 57 00 07 80 C3 }   // mov eax,0x80070057; ret
        $b2 = { B8 34 00 07 80 C3 }
        $b3 = { 33 C0 C3 }             // xor eax,eax; ret

    condition:
        ($p1 and ($p2 or $p3)) or 1 of ($ps*) or any of ($b*)
}

rule ETW_Patching {
    meta:
        description = "Detects ETW (Event Tracing for Windows) patching to blind EDR"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1562.006"
        severity    = "CRITICAL"

    strings:
        $s1 = "EtwEventWrite" ascii wide nocase
        $s2 = "EtwEventWriteFull" ascii wide nocase
        $s3 = "NtTraceEvent" ascii wide nocase
        // Patch bytes: ret instruction placed at EtwEventWrite start
        $b1 = { C2 14 00 }             // ret 0x14 (x86 ETW patch)
        $b2 = { C3 }                    // ret (x64 ETW patch — used with WriteProcessMemory)
        $p1 = "WriteProcessMemory" ascii wide
        $p2 = "VirtualProtect" ascii wide

    condition:
        ($s1 and $p1 and $p2) or ($s2 and $p1)
}

rule Windows_Defender_Disable {
    meta:
        description = "Detects Windows Defender being disabled"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1562.001"
        severity    = "HIGH"

    strings:
        $s1 = "Set-MpPreference" ascii wide nocase
        $s2 = "-DisableRealtimeMonitoring $true" ascii wide nocase
        $s3 = "-DisableRealtimeMonitoring 1" ascii wide nocase
        $s4 = "DisableRealtimeMonitoring" ascii wide nocase
        $s5 = "sc stop WinDefend" ascii wide nocase
        $s6 = "sc config WinDefend start=disabled" ascii wide nocase
        $s7 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $s8 = "DisableAntiSpyware" ascii wide nocase

    condition:
        ($s1 and ($s2 or $s3 or $s4)) or $s5 or $s6 or ($s7 and $s8)
}

rule UAC_Bypass {
    meta:
        description = "Detects common UAC bypass techniques"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1548.002"
        severity    = "HIGH"

    strings:
        // Fodhelper bypass
        $f1 = "fodhelper.exe" ascii wide nocase
        $f2 = "ms-settings:" ascii wide nocase
        // eventvwr bypass
        $e1 = "eventvwr.exe" ascii wide nocase
        $e2 = "\\mscfile\\shell\\open\\command" ascii wide nocase
        // sdclt bypass
        $sc1 = "sdclt.exe" ascii wide nocase
        $sc2 = "\\ms-settings\\shell\\open\\command" ascii wide nocase
        // cmstp bypass
        $c1 = "cmstp.exe" ascii wide nocase
        $c2 = ".inf" ascii wide nocase
        // Auto-elevation abuse
        $a1 = "DelegateExecute" ascii wide
        $a2 = "ShellExecute" ascii wide

    condition:
        ($f1 and $f2) or ($e1 and $e2) or ($sc1 and $sc2) or
        ($c1 and $c2) or ($a1 and $a2)
}

rule Event_Log_Clearing {
    meta:
        description = "Detects Windows Event Log clearing (evidence destruction)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1070.001"
        severity    = "HIGH"

    strings:
        $s1 = "wevtutil cl" ascii wide nocase
        $s2 = "wevtutil clear-log" ascii wide nocase
        $s3 = "Clear-EventLog" ascii wide nocase
        $s4 = "clearev" ascii wide nocase    // Meterpreter clearev command
        $s5 = "EvtClearLog" ascii wide
        $s6 = "Security" ascii wide
        $s7 = "System" ascii wide
        $s8 = "Application" ascii wide

    condition:
        1 of ($s1, $s2, $s3, $s4) or
        ($s5 and 1 of ($s6, $s7, $s8))
}

rule Timestomping {
    meta:
        description = "Detects file timestamp modification (anti-forensics)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1070.006"
        severity    = "MEDIUM"

    strings:
        $s1 = "SetFileTime" ascii wide
        $s2 = "NtSetInformationFile" ascii wide
        $s3 = "FileBasicInformation" ascii wide
        $s4 = "timestomp" ascii wide nocase
        $s5 = "touch -t" ascii
        $ps1 = "(Get-Item" ascii wide
        $ps2 = ").CreationTime" ascii wide
        $ps3 = ").LastWriteTime" ascii wide

    condition:
        $s4 or ($s1 and ($s2 or $s3)) or ($ps1 and ($ps2 or $ps3))
}

rule Process_Hollowing {
    meta:
        description = "Detects process hollowing / RunPE technique"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1055.012"
        severity    = "CRITICAL"

    strings:
        $s1 = "NtUnmapViewOfSection" ascii wide
        $s2 = "ZwUnmapViewOfSection" ascii wide
        $s3 = "VirtualAllocEx" ascii wide
        $s4 = "WriteProcessMemory" ascii wide
        $s5 = "SetThreadContext" ascii wide
        $s6 = "ResumeThread" ascii wide
        $s7 = "CREATE_SUSPENDED" ascii wide
        $s8 = "CreateProcess" ascii wide

    condition:
        ($s1 or $s2) and $s3 and $s4 and $s5 and $s6 or
        $s7 and $s8 and $s4 and ($s5 or $s6)
}
