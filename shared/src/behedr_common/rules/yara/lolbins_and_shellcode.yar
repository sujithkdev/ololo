/*
 * lolbins_and_shellcode.yar
 * Detects LOLBin abuse, PowerShell obfuscation, shellcode loaders,
 * and process injection patterns.
 */

rule PowerShell_Encoded_Command {
    meta:
        description = "Detects PowerShell running an encoded (base64) command — common malware delivery"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1059.001"
        severity    = "HIGH"

    strings:
        $e1 = "-EncodedCommand" ascii wide nocase
        $e2 = "-enc " ascii wide nocase
        $e3 = "-e " ascii wide nocase
        $b1 = "FromBase64String" ascii wide nocase
        $b2 = "JABj" ascii   // base64 "$c" — common PowerShell variable start
        $b3 = "JABX" ascii   // base64 "$W"
        $b4 = "SQBFAFgA" ascii   // base64 "IEX"

    condition:
        ($e1 or $e2) or ($b1 and 1 of ($b2, $b3, $b4))
}

rule PowerShell_Download_Cradle {
    meta:
        description = "Detects PowerShell download-and-execute cradle (malware staging)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1059.001"
        severity    = "HIGH"

    strings:
        $d1 = "DownloadString" ascii wide nocase
        $d2 = "DownloadFile" ascii wide nocase
        $d3 = "Invoke-Expression" ascii wide nocase
        $d4 = "IEX" ascii wide
        $d5 = "Invoke-WebRequest" ascii wide nocase
        $d6 = "WebClient" ascii wide
        $d7 = "Net.WebClient" ascii wide
        $d8 = "Start-BitsTransfer" ascii wide nocase

    condition:
        ($d1 or $d2 or $d5 or $d8) and ($d3 or $d4)
}

rule PowerShell_Obfuscation {
    meta:
        description = "Detects common PowerShell obfuscation patterns"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1027"
        severity    = "HIGH"

    strings:
        $o1 = "-noprofile" ascii wide nocase
        $o2 = "-noninteractive" ascii wide nocase
        $o3 = "-windowstyle hidden" ascii wide nocase
        $o4 = "-executionpolicy bypass" ascii wide nocase
        $o5 = "set-executionpolicy unrestricted" ascii wide nocase
        $o6 = "[System.Convert]::FromBase64String" ascii wide
        $o7 = "[char[]]" ascii wide
        $o8 = "-join" ascii wide
        $c1 = "([char]" ascii wide

    condition:
        3 of ($o*) or ($c1 and $o6)
}

rule Mshta_Script_Execution {
    meta:
        description = "Detects mshta.exe executing remote scripts (HTA abuse)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1218.005"
        severity    = "HIGH"

    strings:
        $s1 = "mshta.exe" ascii wide nocase
        $s2 = "mshta " ascii wide nocase
        $s3 = "vbscript:" ascii wide nocase
        $s4 = "javascript:" ascii wide nocase
        $s5 = "http://" ascii wide
        $s6 = "https://" ascii wide
        $s7 = "ActiveXObject" ascii wide

    condition:
        ($s1 or $s2) and (($s3 or $s4) or ($s7 and ($s5 or $s6)))
}

rule Certutil_Decode {
    meta:
        description = "Detects certutil.exe used to decode/download files (LOLBin abuse)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1140"
        severity    = "HIGH"

    strings:
        $s1 = "certutil" ascii wide nocase
        $s2 = "-decode" ascii wide nocase
        $s3 = "-decodehex" ascii wide nocase
        $s4 = "-urlcache" ascii wide nocase
        $s5 = "-split" ascii wide nocase
        $s6 = "http://" ascii wide
        $s7 = "https://" ascii wide

    condition:
        $s1 and ($s2 or $s3 or ($s4 and ($s6 or $s7)))
}

rule Regsvr32_Squiblydoo {
    meta:
        description = "Detects regsvr32 Squiblydoo technique — bypasses AppLocker"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1218.010"
        severity    = "HIGH"

    strings:
        $s1 = "regsvr32" ascii wide nocase
        $s2 = "/i:http" ascii wide nocase
        $s3 = "/i:https" ascii wide nocase
        $s4 = "scrobj.dll" ascii wide nocase
        $s5 = "/s /n /u" ascii wide nocase
        $s6 = "sct" ascii wide nocase

    condition:
        $s1 and (($s2 or $s3) or ($s4 and $s6))
}

rule Process_Injection_Shellcode {
    meta:
        description = "Detects classic shellcode injection API sequence"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1055"
        severity    = "CRITICAL"

    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "NtCreateThreadEx" ascii wide
        $a5 = "RtlCreateUserThread" ascii wide
        $a6 = "OpenProcess" ascii wide
        // Common shellcode stubs
        $sh1 = { FC E8 8? 00 00 00 }       // Metasploit shellcode stub
        $sh2 = { 60 89 E5 31 D2 64 8B }    // Classic shellcode prologue
        $sh3 = { FC 48 83 E4 F0 E8 }       // x64 Metasploit stub

    condition:
        ($a1 and $a2 and ($a3 or $a4 or $a5)) or any of ($sh*)
}

rule RunDLL32_Abuse {
    meta:
        description = "Detects rundll32 used with suspicious parameters"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1218.011"
        severity    = "MEDIUM"

    strings:
        $s1 = "rundll32" ascii wide nocase
        $s2 = "javascript:" ascii wide nocase
        $s3 = "vbscript:" ascii wide nocase
        $s4 = "shell32.dll,ShellExec_RunDLL" ascii wide nocase
        $s5 = "advpack.dll,LaunchINFSection" ascii wide nocase
        $s6 = "ieadvpack.dll,LaunchINFSection" ascii wide nocase
        $s7 = "shdocvw.dll,OpenURL" ascii wide nocase
        $s8 = "url.dll,FileProtocolHandler http" ascii wide nocase

    condition:
        $s1 and (1 of ($s2, $s3, $s4, $s5, $s6, $s7, $s8))
}

rule WMIC_Remote_Execution {
    meta:
        description = "Detects WMIC used for remote process creation"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1047"
        severity    = "HIGH"

    strings:
        $s1 = "wmic" ascii wide nocase
        $s2 = "/node:" ascii wide nocase
        $s3 = "process call create" ascii wide nocase
        $s4 = "shadowcopy delete" ascii wide nocase
        $s5 = "wmic shadowcopy" ascii wide nocase

    condition:
        ($s1 and $s2 and $s3) or ($s1 and $s4) or $s5
}

rule MSBuild_Inline_Task {
    meta:
        description = "Detects MSBuild executing inline C# task — AppLocker bypass"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1127.001"
        severity    = "HIGH"

    strings:
        $s1 = "<UsingTask" ascii wide
        $s2 = "TaskFactory=\"CodeTaskFactory\"" ascii wide
        $s3 = "<![CDATA[" ascii wide
        $s4 = "Assembly.Load" ascii wide
        $s5 = "Process.Start" ascii wide

    condition:
        ($s1 and $s2) or ($s3 and ($s4 or $s5))
}
