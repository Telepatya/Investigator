rule Suspicious_PE_Indicators
{
    meta:
        description = "Generic static indicators requiring analyst review"
    strings:
        $mz = { 4D 5A }
        $inject = "WriteProcessMemory" ascii wide
        $thread = "CreateRemoteThread" ascii wide
        $download = "URLDownloadToFile" ascii wide
        $powershell = "powershell" ascii wide nocase
    condition:
        $mz at 0 and 2 of ($inject, $thread, $download, $powershell)
}

rule Static_Process_Injection_APIs
{
    meta:
        description = "Multiple APIs associated with remote process memory manipulation"
    strings:
        $open = "OpenProcess" ascii wide
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread = "CreateRemoteThread" ascii wide
        $context = "SetThreadContext" ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule Static_Service_Control_Capability
{
    meta:
        description = "Windows service installation or control capability"
    strings:
        $manager = "OpenSCManager" ascii wide
        $create = "CreateService" ascii wide
        $start = "StartService" ascii wide
        $control = "ControlService" ascii wide
        $delete = "DeleteService" ascii wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule Static_Network_Downloader_Capability
{
    meta:
        description = "Network retrieval APIs or command-line download utilities"
    strings:
        $urlmon = "URLDownloadToFile" ascii wide
        $winhttp = "WinHttpOpen" ascii wide
        $wininet = "InternetOpen" ascii wide
        $curl = "curl " ascii wide nocase
        $powershell = "powershell" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule Static_Anti_Debug_Capability
{
    meta:
        description = "Multiple anti-debugging or timing checks"
    strings:
        $debugger = "IsDebuggerPresent" ascii wide
        $remote = "CheckRemoteDebuggerPresent" ascii wide
        $query = "NtQueryInformationProcess" ascii wide
        $tick = "GetTickCount" ascii wide
        $perf = "QueryPerformanceCounter" ascii wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}
