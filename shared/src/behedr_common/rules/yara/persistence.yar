/*
 * persistence.yar
 * Detects common Windows persistence mechanisms:
 * registry Run keys, scheduled tasks, service installation, WMI subscriptions,
 * startup folder abuse, bootkit indicators.
 */

rule Registry_Run_Persistence {
    meta:
        description = "Detects writing to registry Run keys for persistence"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1547.001"
        severity    = "HIGH"

    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $r3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r4 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $w1 = "RegSetValueEx" ascii wide
        $w2 = "RegCreateKeyEx" ascii wide

    condition:
        ($w1 or $w2) and 1 of ($r*)
}

rule Scheduled_Task_Creation {
    meta:
        description = "Detects scheduled task creation via schtasks or COM"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1053.005"
        severity    = "HIGH"

    strings:
        $s1 = "schtasks" ascii wide nocase
        $s2 = "/create" ascii wide nocase
        $s3 = "/sc onlogon" ascii wide nocase
        $s4 = "/sc onstart" ascii wide nocase
        $s5 = "/sc daily" ascii wide nocase
        $s6 = "ITaskService" ascii wide   // COM-based task creation
        $s7 = "TaskScheduler" ascii wide
        $s8 = "/ru SYSTEM" ascii wide nocase
        $s9 = "/rl highest" ascii wide nocase

    condition:
        ($s1 and $s2 and 1 of ($s3, $s4, $s5)) or
        ($s6 and $s7) or
        ($s1 and $s2 and ($s8 or $s9))
}

rule WMI_Event_Subscription {
    meta:
        description = "Detects WMI permanent event subscription (stealthy persistence)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1546.003"
        severity    = "HIGH"

    strings:
        $s1 = "__EventFilter" ascii wide
        $s2 = "__EventConsumer" ascii wide
        $s3 = "__FilterToConsumerBinding" ascii wide
        $s4 = "ActiveScriptEventConsumer" ascii wide
        $s5 = "CommandLineEventConsumer" ascii wide
        $s6 = "Set-WmiInstance" ascii wide nocase
        $s7 = "New-Object Management.ManagementClass" ascii wide

    condition:
        2 of ($s*)
}

rule Service_Installation {
    meta:
        description = "Detects new Windows service installation for persistence"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1543.003"
        severity    = "HIGH"

    strings:
        $s1 = "sc create" ascii wide nocase
        $s2 = "sc config" ascii wide nocase
        $s3 = "OpenSCManager" ascii wide
        $s4 = "CreateService" ascii wide
        $s5 = "StartService" ascii wide
        $s6 = "SYSTEM\\CurrentControlSet\\Services" ascii wide nocase
        $s7 = "binPath=" ascii wide nocase

    condition:
        ($s1 and $s7) or ($s3 and $s4 and $s5) or ($s6 and $s7)
}

rule Startup_Folder_Drop {
    meta:
        description = "Detects file dropped in Windows Startup folder"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1547.001"
        severity    = "HIGH"

    strings:
        $s1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ascii wide nocase
        $s2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ascii wide nocase
        $s3 = "shell:startup" ascii wide nocase
        $s4 = "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase

    condition:
        any of them
}

rule DLL_Side_Loading {
    meta:
        description = "Detects potential DLL side-loading via unsigned DLL in app directory"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1574.002"
        severity    = "MEDIUM"

    strings:
        $s1 = "LoadLibraryA" ascii wide
        $s2 = "LoadLibraryW" ascii wide
        $s3 = "LoadLibraryExA" ascii wide
        $s4 = "LoadLibraryExW" ascii wide
        $p1 = "\\AppData\\" ascii wide nocase
        $p2 = "\\Temp\\" ascii wide nocase
        $p3 = "\\Public\\" ascii wide nocase
        $p4 = "\\ProgramData\\" ascii wide nocase

    condition:
        1 of ($s*) and 2 of ($p*)
}

rule Boot_Record_Modification {
    meta:
        description = "Detects potential bootkit / MBR modification attempt"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1542.003"
        severity    = "CRITICAL"

    strings:
        $s1 = "\\\\.\\PhysicalDrive0" ascii wide nocase
        $s2 = "DeviceIoControl" ascii wide
        $s3 = "IOCTL_DISK_WRITE_RAW" ascii wide
        $s4 = { 33 C0 8E D0 BC 00 7C }   // Classic boot sector code
        $s5 = "bcdedit" ascii wide nocase
        $s6 = "/set {bootmgr}" ascii wide nocase

    condition:
        ($s1 and $s2) or $s4 or ($s5 and $s6)
}
