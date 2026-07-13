/*
    Investigator bundled APT / C2 / offensive-tooling indicators.
    Curated open-source style signatures for scanning process memory.
    These are heuristic and intended to flag candidate regions for analyst + LLM review.
*/

rule CobaltStrike_Beacon_Config
{
    meta:
        description = "Cobalt Strike beacon configuration / MZ reflective markers"
        author = "Investigator"
        attck = "T1071"
        severity = "critical"
    strings:
        $s1 = "%c%c%c%c%c%c%c%cMSSE-%d-server"
        $s2 = "%s as %s\\%s: %d"
        $s3 = "ReflectiveLoader"
        $s4 = "beacon.dll" nocase
        $s5 = "beacon.x64.dll" nocase
        $conf = { 00 01 00 01 00 02 ?? ?? }
    condition:
        any of ($s*) or $conf
}

rule Meterpreter_Payload
{
    meta:
        description = "Metasploit Meterpreter in-memory artifacts"
        author = "Investigator"
        attck = "T1071"
        severity = "critical"
    strings:
        $s1 = "metsrv.dll" nocase
        $s2 = "meterpreter" nocase
        $s3 = "stdapi_"
        $s4 = "core_channel_open"
        $s5 = "PACKET_TYPE_REQUEST"
    condition:
        2 of them
}

rule Reflective_PE_Injection
{
    meta:
        description = "Reflectively loaded PE indicators inside memory region"
        author = "Investigator"
        attck = "T1620"
        severity = "high"
    strings:
        $refl = "ReflectiveLoader"
        $doedhdr = "This program cannot be run in DOS mode"
        $mz = { 4D 5A }
    condition:
        $refl and $mz and $doedhdr
}

rule Mimikatz_Signatures
{
    meta:
        description = "Mimikatz credential theft strings"
        author = "Investigator"
        attck = "T1003.001"
        severity = "critical"
    strings:
        $s1 = "sekurlsa" nocase
        $s2 = "kerberos::golden" nocase
        $s3 = "privilege::debug" nocase
        $s4 = "gentilkiwi" nocase
        $s5 = "logonpasswords" nocase
        $s6 = "wdigest" nocase
    condition:
        2 of them
}

rule PowerShell_Empire_Agent
{
    meta:
        description = "PowerShell Empire / offensive PowerShell agent markers"
        author = "Investigator"
        attck = "T1059.001"
        severity = "critical"
    strings:
        $s1 = "System.Management.Automation" nocase
        $s2 = "Invoke-Empire" nocase
        $s3 = "$shell.Run" nocase
        $s4 = "-EncodedCommand" nocase
        $s5 = "FromBase64String" nocase
        $s6 = "IEX" fullword
    condition:
        3 of them
}

rule Generic_Shellcode_Markers
{
    meta:
        description = "Common shellcode prologues / API hashing indicators"
        author = "Investigator"
        attck = "T1055"
        severity = "high"
    strings:
        $peb1 = { 64 A1 30 00 00 00 }
        $peb2 = { 65 48 8B 04 25 60 00 00 00 }
        $api_hash = { 33 C9 ?? ?? AC 84 C0 }
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 }
    condition:
        any of them
}

rule Known_C2_Frameworks
{
    meta:
        description = "Sliver / Covenant / Brute Ratel / Havoc framework strings"
        author = "Investigator"
        attck = "T1071"
        severity = "critical"
    strings:
        $sliver1 = "sliver" nocase
        $covenant1 = "GruntStager" nocase
        $covenant2 = "Covenant" nocase
        $brute1 = "badger" nocase
        $havoc1 = "demon.x64" nocase
        $havoc2 = "Havoc" fullword
    condition:
        any of them
}

rule Credential_Access_Tools
{
    meta:
        description = "LaZagne / Rubeus / SharpHound in-memory markers"
        author = "Investigator"
        attck = "T1555"
        severity = "critical"
    strings:
        $l1 = "lazagne" nocase
        $r1 = "Rubeus" nocase
        $r2 = "asktgt" nocase
        $s1 = "SharpHound" nocase
        $s2 = "BloodHound" nocase
    condition:
        any of them
}

rule Process_Hollowing_APIs
{
    meta:
        description = "API name cluster associated with process hollowing/injection"
        author = "Investigator"
        attck = "T1055.012"
        severity = "high"
    strings:
        $a1 = "NtUnmapViewOfSection"
        $a2 = "ZwUnmapViewOfSection"
        $a3 = "WriteProcessMemory"
        $a4 = "SetThreadContext"
        $a5 = "ResumeThread"
        $a6 = "NtQueueApcThread"
    condition:
        3 of them
}
