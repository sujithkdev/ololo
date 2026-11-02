/*
 * c2_and_backdoors.yar
 * Detects command-and-control frameworks and backdoor tools:
 * Cobalt Strike, Metasploit, Sliver, Havoc, Empire, njRAT, AsyncRAT.
 */

rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike Beacon (any variant)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1071.001"
        severity    = "CRITICAL"

    strings:
        // Beacon config markers
        $c1 = "ReflectiveLoader" ascii
        $c2 = "%02d/%02d/%02d %02d:%02d:%02d" ascii    // CS timestamp format
        $c3 = "beacon.dll" ascii nocase
        $c4 = "beacon.x64.dll" ascii nocase
        // CS watermark / pipe name patterns
        $p1 = "\\\\.\\pipe\\MSSE-" ascii
        $p2 = "msagent_" ascii
        $p3 = "\\\\.\\pipe\\postex_" ascii
        // CS metadata keys
        $m1 = "eyJhbGciOiJSUzI1NiJ9" ascii  // base64 "{"alg":"RS256"}" — CS JWT
        $m2 = { 00 00 00 00 00 00 00 00 00 00 00 00 04 00 00 }  // CS config block marker

    condition:
        2 of ($c*) or 1 of ($p*) or $m1
}

rule CobaltStrike_Stager {
    meta:
        description = "Detects Cobalt Strike stager (small download shellcode)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1071.001"
        severity    = "CRITICAL"

    strings:
        // x86 CS stager stub
        $x86 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        // x64 CS stager stub
        $x64 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51 }
        // CS named pipe stager
        $np  = { 68 26 06 18 7B FF D5 }

    condition:
        any of them
}

rule Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter payload"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1059"
        severity    = "CRITICAL"

    strings:
        $s1 = "meterpreter" ascii nocase
        $s2 = "ReflectiveDll" ascii
        $s3 = "Meterpreter" ascii
        $s4 = "stdapi_" ascii
        $s5 = "TlvPacket" ascii
        // Meterpreter reverse_tcp shellcode stubs
        $r1 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $r2 = { 6A 0A 68 ?? ?? ?? ?? 68 02 00 }   // connect() with IP

    condition:
        2 of ($s*) or any of ($r*)
}

rule Sliver_C2 {
    meta:
        description = "Detects Sliver C2 framework implant"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1071"
        severity    = "CRITICAL"

    strings:
        $s1 = "github.com/bishopfox/sliver" ascii
        $s2 = "sliver/protobuf" ascii
        $s3 = "SliverServer" ascii
        $s4 = "implant/sliver" ascii
        $s5 = "WATERMARK" ascii
        $s6 = "pivotListener" ascii nocase

    condition:
        2 of them
}

rule Havoc_Framework {
    meta:
        description = "Detects Havoc C2 framework demon implant"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1071"
        severity    = "CRITICAL"

    strings:
        $s1 = "HavocC2" ascii nocase
        $s2 = "DemonID" ascii
        $s3 = "teamserver" ascii nocase
        $s4 = "Havoc.Demon" ascii
        $h1 = { 48 61 76 6F 63 }   // "Havoc"

    condition:
        2 of ($s*) or ($h1 and 1 of ($s*))
}

rule Empire_PowerShell {
    meta:
        description = "Detects PowerShell Empire agent"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1059.001"
        severity    = "CRITICAL"

    strings:
        $s1 = "empire" ascii wide nocase
        $s2 = "PowerShell Empire" ascii
        $s3 = "Invoke-Empire" ascii
        $s4 = "agents/agent.ps1" ascii nocase
        $s5 = "LISTENERS" ascii
        $s6 = "staging/empire.ps1" ascii nocase

    condition:
        2 of them
}

rule njRAT {
    meta:
        description = "Detects njRAT / Bladabindi remote access trojan"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1219"
        severity    = "CRITICAL"

    strings:
        $s1 = "njRAT" ascii wide nocase
        $s2 = "HoudRat" ascii
        $s3 = "bladabindi" ascii nocase
        $s4 = "|'|'|" ascii   // njRAT C2 delimiter
        $s5 = "njq8" ascii    // njRAT author tag
        $s6 = "cmd.exe /k cd" ascii wide nocase

    condition:
        $s4 or 2 of ($s*)
}

rule AsyncRAT {
    meta:
        description = "Detects AsyncRAT remote access trojan"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1219"
        severity    = "CRITICAL"

    strings:
        $s1 = "AsyncRAT" ascii wide nocase
        $s2 = "AsyncClient" ascii
        $s3 = "Pastebin.com/raw/" ascii nocase
        $s4 = "HKCU\\Software\\AsyncRAT" ascii nocase
        $s5 = "async-rat" ascii nocase

    condition:
        2 of them
}

rule Generic_Reverse_Shell {
    meta:
        description = "Detects generic reverse shell patterns (PowerShell, cmd, bash)"
        author      = "EDR Project"
        date        = "2026-01-01"
        mitre       = "T1059"
        severity    = "HIGH"

    strings:
        $ps1 = "New-Object System.Net.Sockets.TCPClient" ascii wide
        $ps2 = "$stream = $client.GetStream" ascii wide
        $ps3 = "[System.IO.StreamWriter]" ascii wide
        $ps4 = "System.Net.Sockets.NetworkStream" ascii wide
        $cmd = "cmd.exe /c " ascii wide
        $nc  = "ncat.exe" ascii wide nocase
        $nc2 = "nc.exe -e" ascii wide nocase
        $nc3 = "nc -e /bin/bash" ascii

    condition:
        (2 of ($ps*)) or ($nc2) or ($nc3) or ($cmd and 1 of ($ps*))
}
