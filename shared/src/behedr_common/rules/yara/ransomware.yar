/*
 * ransomware.yar
 * Detects common ransomware families and generic ransomware behaviour.
 * Covers: WannaCry, Ryuk, LockBit, Conti, REvil/Sodinokibi, generic patterns.
 */

rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry / WannaCrypt ransomware"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1486"
        severity    = "CRITICAL"

    strings:
        $s1 = "WannaCryptDecryptor" ascii wide nocase
        $s2 = "WANACRY!" ascii wide
        $s3 = "msg/m_bulgarian.wnry" ascii
        $s4 = "tasksche.exe" ascii wide nocase
        $s5 = "WNcry@2ol7" ascii
        $s6 = ".WNCRY" ascii wide
        $s7 = "wanna decryptor" ascii wide nocase
        $b1 = { 57 41 4E 41 43 52 59 21 }   // "WANACRY!"

    condition:
        2 of ($s*) or $b1
}

rule Ryuk_Ransomware {
    meta:
        description = "Detects Ryuk ransomware"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1486"
        severity    = "CRITICAL"

    strings:
        $s1 = "RyukReadMe" ascii wide nocase
        $s2 = "RYUK_MASTER_KEY" ascii wide nocase
        $s3 = ".RYK" ascii wide
        $s4 = "lsaas.exe" ascii wide   // Ryuk masquerade
        $s5 = "No system is safe" ascii
        $s6 = "ryukransom" ascii nocase
        $b1 = { 52 59 55 4B }   // "RYUK"

    condition:
        2 of ($s*) or $b1
}

rule LockBit_Ransomware {
    meta:
        description = "Detects LockBit ransomware"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1486"
        severity    = "CRITICAL"

    strings:
        $s1 = "LockBit" ascii wide nocase
        $s2 = "Restore-My-Files.txt" ascii wide nocase
        $s3 = ".lockbit" ascii wide nocase
        $s4 = "lockbit_decryptor" ascii wide nocase
        $s5 = "LockBitDecryptor" ascii wide
        $ibc = { 4C 6F 63 6B 42 69 74 }   // "LockBit"

    condition:
        2 of ($s*) or $ibc
}

rule Conti_Ransomware {
    meta:
        description = "Detects Conti ransomware"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1486"
        severity    = "CRITICAL"

    strings:
        $s1 = "CONTI_LOG.txt" ascii wide nocase
        $s2 = "readme.txt" ascii wide nocase
        $s3 = "conti_v" ascii nocase
        $s4 = "ContiLocker" ascii
        $s5 = { 43 4F 4E 54 49 }   // "CONTI"

    condition:
        2 of ($s*)
}

rule REvil_Sodinokibi {
    meta:
        description = "Detects REvil / Sodinokibi ransomware"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1486"
        severity    = "CRITICAL"

    strings:
        $s1 = "sodinokibi" ascii wide nocase
        $s2 = "REvil" ascii wide
        $s3 = "-readme.txt" ascii wide nocase
        $s4 = "expand 32-byte k" ascii   // Salsa20 key expansion constant
        $s5 = { 72 6B 6E 31 36 }   // "rkn16" (REvil internal marker)

    condition:
        2 of ($s*)
}

rule Generic_Ransomware_Behaviour {
    meta:
        description = "Detects generic ransomware behaviour patterns"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1486"
        severity    = "HIGH"

    strings:
        // Common ransom note filenames
        $n1 = "HOW_TO_DECRYPT" ascii wide nocase
        $n2 = "RECOVERY_KEY" ascii wide nocase
        $n3 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $n4 = "README_FOR_DECRYPT" ascii wide nocase
        $n5 = "RESTORE_FILES" ascii wide nocase

        // Ransom extensions
        $e1 = ".encrypted" ascii wide nocase
        $e2 = ".locked" ascii wide nocase
        $e3 = ".crypt" ascii wide nocase
        $e4 = ".enc" ascii wide nocase

        // VSS deletion commands
        $v1 = "vssadmin delete shadows" ascii wide nocase
        $v2 = "wbadmin delete backup" ascii wide nocase
        $v3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $v4 = "wmic shadowcopy delete" ascii wide nocase

    condition:
        2 of ($n*) or 2 of ($v*) or (1 of ($e*) and 1 of ($v*))
}

rule Ransomware_CryptoAPI_Use {
    meta:
        description = "Detects suspicious use of Windows CryptoAPI (ransomware encryption)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1486"
        severity    = "MEDIUM"

    strings:
        $c1 = "CryptGenRandom" ascii wide
        $c2 = "CryptEncrypt" ascii wide
        $c3 = "CryptAcquireContext" ascii wide
        $c4 = "CryptImportKey" ascii wide
        $f1 = "FindFirstFileW" ascii wide
        $f2 = "FindNextFileW" ascii wide
        $f3 = "WriteFile" ascii wide
        $f4 = "DeleteFile" ascii wide

    condition:
        2 of ($c*) and 3 of ($f*)
}
