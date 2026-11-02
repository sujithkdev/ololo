/*
 * credential_dumping.yar
 * Detects common credential-dumping tools and techniques.
 * Covers: Mimikatz, LaZagne, WCE, fgdump, pwdump, procdump LSASS abuse.
 */

rule Mimikatz_Generic {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1003.001"
        severity    = "CRITICAL"

    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "lsadump" ascii wide nocase
        $s4 = "kerberos::list" ascii wide nocase
        $s5 = "privilege::debug" ascii wide nocase
        $s6 = "sekurlsa::logonpasswords" ascii wide nocase
        $s7 = "sekurlsa::wdigest" ascii wide nocase
        $s8 = "lsadump::sam" ascii wide nocase
        $s9 = "crypto::certificates" ascii wide nocase
        $b1 = { 6D 69 6D 69 6B 61 74 7A }   // "mimikatz" bytes

    condition:
        2 of ($s*) or $b1
}

rule Mimikatz_InMemory {
    meta:
        description = "Detects Mimikatz loaded into memory (fileless)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1003.001"
        severity    = "CRITICAL"

    strings:
        $m1 = "MiniDumpWriteDump" ascii wide
        $m2 = "OpenProcess" ascii wide
        $m3 = "sekurlsa" ascii wide nocase
        $m4 = { 6B 69 77 69 41 6E 64 4D 67 6D }   // "kiwiAndMgm"
        $m5 = "kuhl_m_sekurlsa" ascii

    condition:
        ($m1 and $m2 and $m3) or $m4 or $m5
}

rule LaZagne {
    meta:
        description = "Detects LaZagne — multi-platform password recovery tool"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1555"
        severity    = "HIGH"

    strings:
        $s1 = "lazagne" ascii wide nocase
        $s2 = "laZagne" ascii
        $s3 = "The LaZagne Project" ascii
        $s4 = "Password recovery tool" ascii nocase
        $s5 = "__lazagne__" ascii

    condition:
        any of them
}

rule WCE_Credential_Tool {
    meta:
        description = "Detects Windows Credential Editor (WCE)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1003.001"
        severity    = "CRITICAL"

    strings:
        $s1 = "Windows Credentials Editor" ascii wide nocase
        $s2 = "wce.exe" ascii wide nocase
        $s3 = "w3c.exe" ascii wide nocase
        $b1 = { 57 43 45 20 76 }   // "WCE v"

    condition:
        any of them
}

rule LSASS_Dump_Procdump {
    meta:
        description = "Detects ProcDump used to dump LSASS memory"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1003.001"
        severity    = "CRITICAL"

    strings:
        $s1 = "procdump" ascii wide nocase
        $s2 = "lsass" ascii wide nocase
        $s3 = "-ma" ascii
        $s4 = "MiniDump" ascii wide

    condition:
        ($s1 and $s2) or ($s3 and $s4 and $s2)
}

rule Credential_Access_Registry {
    meta:
        description = "Detects registry-based credential access (SAM/SECURITY hive dump)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1003.002"
        severity    = "HIGH"

    strings:
        $r1 = "HKLM\\SAM" ascii wide nocase
        $r2 = "HKLM\\SECURITY" ascii wide nocase
        $r3 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA" ascii wide nocase
        $r4 = "reg save" ascii wide nocase
        $r5 = "reg export" ascii wide nocase

    condition:
        ($r4 or $r5) and ($r1 or $r2 or $r3)
}
