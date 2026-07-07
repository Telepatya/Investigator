"""Detection rule definitions: LOLBins, suspicious parent/child pairs, persistence, ATT&CK mapping."""

from __future__ import annotations

import re

# LOLBins commonly abused for execution/download/proxy execution -> ATT&CK technique
LOLBINS: dict[str, tuple[str, str]] = {
    "certutil.exe": ("T1105", "Ingress tool transfer / encoded payload handling"),
    "bitsadmin.exe": ("T1197", "BITS jobs abuse"),
    "mshta.exe": ("T1218.005", "Mshta proxy execution"),
    "rundll32.exe": ("T1218.011", "Rundll32 proxy execution"),
    "regsvr32.exe": ("T1218.010", "Regsvr32 proxy execution"),
    "wmic.exe": ("T1047", "WMI execution"),
    "cscript.exe": ("T1059.005", "VBScript execution"),
    "wscript.exe": ("T1059.005", "VBScript execution"),
    "msbuild.exe": ("T1127.001", "MSBuild proxy execution"),
    "installutil.exe": ("T1218.004", "InstallUtil proxy execution"),
    "regasm.exe": ("T1218.009", "Regasm proxy execution"),
    "regsvcs.exe": ("T1218.009", "Regsvcs proxy execution"),
    "cmstp.exe": ("T1218.003", "CMSTP proxy execution"),
    "msiexec.exe": ("T1218.007", "Msiexec proxy execution"),
    "odbcconf.exe": ("T1218.008", "Odbcconf proxy execution"),
    "forfiles.exe": ("T1202", "Indirect command execution"),
    "pcalua.exe": ("T1202", "Indirect command execution"),
    "mavinject.exe": ("T1055", "Process injection via mavinject"),
    "esentutl.exe": ("T1005", "Data staging / credential file copy"),
    "vssadmin.exe": ("T1490", "Shadow copy deletion (ransomware precursor)"),
    "wevtutil.exe": ("T1070.001", "Event log clearing"),
    "bcdedit.exe": ("T1490", "Boot configuration tampering"),
    "schtasks.exe": ("T1053.005", "Scheduled task creation"),
    "at.exe": ("T1053.002", "At job creation"),
    "reg.exe": ("T1112", "Registry modification"),
    "netsh.exe": ("T1090", "Netsh proxy/portforward configuration"),
    "nltest.exe": ("T1482", "Domain trust discovery"),
    "dsquery.exe": ("T1087.002", "Domain account discovery"),
    "whoami.exe": ("T1033", "System owner discovery"),
    "quser.exe": ("T1033", "Session discovery"),
    "psexec.exe": ("T1570", "Lateral tool transfer / remote execution"),
    "curl.exe": ("T1105", "Ingress tool transfer"),
    "ftp.exe": ("T1105", "Ingress tool transfer"),
}

# LOLBins that are also everyday admin/software tooling: a bare invocation (even with
# arguments) is weak signal on its own, so it is reported at "low" rather than "medium".
# The genuinely-abused command lines for these (certutil -urlcache, reg add ...\run,
# schtasks /create, wmic process call create, bitsadmin /transfer, ...) are still caught
# with full severity by SUSPICIOUS_CMDLINE_PATTERNS.
LOW_SIGNAL_LOLBINS: set[str] = {
    "whoami.exe", "quser.exe", "reg.exe",
    "msiexec.exe", "curl.exe", "ftp.exe", "netsh.exe", "schtasks.exe", "wmic.exe",
    "dsquery.exe", "nltest.exe",
}

def _exe(name: str) -> str:
    """Regex prefix for an executable invocation followed by its arguments.

    Real command lines quote full paths ('"C:\\...\\tool.exe" args'): the leading \\b
    lets a path precede the basename (\\b matches after a backslash), `(?:\\.exe)?`
    covers the extension, and an optional closing quote/apostrophe may sit between
    the extension and the argument whitespace. `name` may itself be a small regex
    fragment (e.g. r"sdelete(?:64)?").
    """
    return rf"\b{name}(?:\.exe)?[\"']?\s+"


# Suspicious command-line patterns -> (compiled regex, technique, description, severity).
# Matched against lowercased text. Word boundaries and co-occurring context tokens keep
# ordinary words ("bypass", "empire", "covenant", "chisel") and bare mentions of lsass
# from firing on their own. Tool-plus-arguments patterns are built with _exe() so
# quoted invocations ('"C:\\Windows\\System32\\tool.exe" args') match too.
SUSPICIOUS_CMDLINE_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"-enc\b"), "T1059.001", "PowerShell encoded command", "high"),
    (re.compile(r"-encodedcommand\b"), "T1059.001", "PowerShell encoded command", "high"),
    (re.compile(r"-nop\b"), "T1059.001", "PowerShell no-profile execution", "medium"),
    (re.compile(r"-noprofile\b"), "T1059.001", "PowerShell no-profile execution", "medium"),
    (re.compile(r"-(?:executionpolicy|exec|ep)[\s:]+bypass\b"), "T1059.001", "PowerShell execution policy bypass", "medium"),
    (re.compile(r"\bdownloadstring\b"), "T1059.001", "PowerShell in-memory download cradle", "critical"),
    (re.compile(r"\bdownloadfile\b"), "T1105", "PowerShell file download", "high"),
    (re.compile(r"\biex\s*\("), "T1059.001", "PowerShell invoke-expression cradle", "critical"),
    (re.compile(r"\biex\s+[^\s(]"), "T1059.001", "PowerShell invoke-expression", "high"),
    (re.compile(r"\binvoke-expression\b"), "T1059.001", "PowerShell invoke-expression", "high"),
    (re.compile(r"\binvoke-webrequest\b"), "T1105", "PowerShell web download", "medium"),
    (re.compile(r"\bfrombase64string\b"), "T1140", "Base64 payload decoding", "high"),
    (re.compile(r"\bmimikatz\b"), "T1003", "Mimikatz credential theft", "critical"),
    (re.compile(r"\bsekurlsa\b"), "T1003.001", "LSASS credential extraction", "critical"),
    # "lsass" alone matches every benign mention; require a dump tool/verb in the same text
    (re.compile(r"(?=.*\blsass\b)(?=.*(?:procdump|comsvcs|minidump|nanodump|out-minidump|createdump|rundll32|\.dmp\b))"),
     "T1003.001", "LSASS memory dump activity", "critical"),
    (re.compile(r"\bprocdump(?:64)?\b"), "T1003.001", "Process memory dumping tool", "medium"),
    (re.compile(r"comsvcs(?:\.dll)?\b.{0,120}(?:minidump|#24)"), "T1003.001", "LSASS dump via comsvcs MiniDump", "critical"),
    (re.compile(_exe("vssadmin") + r"delete\s+shadows"), "T1490", "Shadow copy deletion", "critical"),
    (re.compile(_exe("wbadmin") + r"delete\s+catalog"), "T1490", "Backup catalog deletion", "critical"),
    (re.compile(_exe("bcdedit") + r"/set\b"), "T1490", "Boot configuration tampering", "high"),
    (re.compile(_exe("wevtutil") + r"cl\b"), "T1070.001", "Event log clearing", "critical"),
    (re.compile(r"\bclear-eventlog\b"), "T1070.001", "Event log clearing", "critical"),
    (re.compile(_exe("net1?") + r"user\b.{0,120}/add\b"), "T1136.001", "Local account creation", "high"),
    (re.compile(_exe("net1?") + r"localgroup\s+administrators\b"), "T1098", "Admin group manipulation", "high"),
    (re.compile(_exe("reg") + r"add\s+[\"']?(?:hklm|hkcu|hkey_local_machine|hkey_current_user)\\software\\microsoft\\windows\\currentversion\\run"),
     "T1547.001", "Run key persistence", "high"),
    (re.compile(r"\battrib\b.{0,40}\+h\b"), "T1564.001", "File hiding", "medium"),
    # Bare "icacls" (read/list ACLs) is benign; only an actual ACL change is signal.
    (re.compile(r"\bicacls\b.{0,200}(?:/grant|/deny|/setowner|/reset|/inheritance:[re]|/remove)"),
     "T1222", "Permission modification", "low"),
    (re.compile(r"\brundll32(?:\.exe)?[\s\"']+javascript:"), "T1218.011", "Rundll32 JavaScript execution", "critical"),
    (re.compile(r"\bscrobj\.dll\b"), "T1218.010", "Squiblydoo scriptlet execution", "critical"),
    (re.compile(r"-urlcache\b"), "T1105", "Certutil URL cache download", "critical"),
    (re.compile(r"\bcertutil(?:\.exe)?\b.{0,120}-decode\b"), "T1140", "Certutil payload decode", "high"),
    (re.compile(_exe("schtasks") + r"/create\b"), "T1053.005", "Scheduled task creation", "medium"),
    (re.compile(_exe("mshta") + r".{0,300}?(?:https?://|\\\\)"),
     "T1218.005", "Mshta remote payload execution", "critical"),
    (re.compile(r"\bregsvr32[^\n]{0,80}/i:https?://"),
     "T1218.010", "Regsvr32 remote scriptlet execution (Squiblydoo)", "critical"),
    # JScript instantiating a shell COM object: both halves must co-occur. The space
    # may be URL-encoded ("new%20ActiveXObject") in rundll32 javascript: one-liners.
    (re.compile(r"(?=.*\bnew(?:\s|%+20)+activexobject\s*\()(?=.*(?:wscript\.shell|shell\.application))"),
     "T1059.007", "JScript ActiveX shell execution", "high"),
    (re.compile(r"-w(?:indowstyle)?\s+hidden\b"), "T1564.003", "PowerShell hidden window execution", "medium"),
    (re.compile(_exe("wmic") + r"process\s+call\s+create"), "T1047", "WMI process creation", "high"),
    (re.compile(_exe("wmic") + r"/node:"), "T1047", "Remote WMI execution", "high"),
    (re.compile(r"\bpsexec(?:64)?(?:\.exe)?\b"), "T1570", "PsExec lateral movement", "high"),
    (re.compile(r"\bntdsutil\b"), "T1003.003", "NTDS.dit extraction", "critical"),
    (re.compile(r"\bntds\.dit\b"), "T1003.003", "NTDS.dit access", "critical"),
    (re.compile(_exe("reg") + r"save\s+[\"']?hklm\\sam\b"), "T1003.002", "SAM hive dump", "critical"),
    (re.compile(_exe("reg") + r"save\s+[\"']?hklm\\system\b"), "T1003.002", "SYSTEM hive dump", "critical"),
    (re.compile(r"\bdcsync\b"), "T1003.006", "DCSync replication attack", "critical"),
    # mimikatz's own golden-ticket verb: unambiguous, fires on its own.
    (re.compile(r"kerberos::golden\b"), "T1558.001", "Golden ticket (mimikatz kerberos::golden)", "critical"),
    # The bare phrase "golden ticket" collides with everyday text (raffles, promos,
    # Willy Wonka, a URL like /golden-ticket-promo). Require a Kerberos-attack context
    # token to co-occur so only real forged-TGT tradecraft fires.
    (re.compile(r"(?=.*golden[\s_-]?ticket)(?=.*(?:krbtgt|mimikatz|rubeus|kerberos::|\.kirbi|/aes256|/rc4|/ptt|sid:s-1-5-21))"),
     "T1558.001", "Golden ticket attack", "critical"),
    (re.compile(r"\bkerberoast"), "T1558.003", "Kerberoasting", "critical"),
    (re.compile(r"\brubeus\b"), "T1558", "Rubeus Kerberos abuse", "critical"),
    # "bloodhound" alone is a dog breed / common word; match the tool's invocation
    # forms or its collection flag instead of any bare mention.
    (re.compile(r"\binvoke-bloodhound\b|\bbloodhound\.(?:exe|ps1|py)\b|\bbloodhound-python\b|\bbloodhound\b.{0,60}-collectionmethod"),
     "T1087", "BloodHound AD reconnaissance", "high"),
    (re.compile(r"\bsharphound\b"), "T1087", "SharpHound AD reconnaissance", "high"),
    (re.compile(r"cobalt[\s_-]?strike"), "T1071", "Cobalt Strike C2", "critical"),
    (re.compile(r"\bbeacon\.dll\b"), "T1071", "Cobalt Strike beacon", "critical"),
    (re.compile(r"\bmeterpreter\b"), "T1071", "Meterpreter C2", "critical"),
    (re.compile(r"\bempire\.(?:exe|ps1|dll|py)\b|\binvoke-empire\b|" + _exe("powershell") + r"empire\b"),
     "T1059.001", "PowerShell Empire tooling", "high"),
    (re.compile(r"\bcovenant\.(?:exe|dll)\b|\bgruntstager\b|\bgrunthttp\b"), "T1071", "Covenant C2 tooling", "high"),
    (re.compile(r"\bnishang\b"), "T1059.001", "Nishang offensive PowerShell", "critical"),
    (re.compile(r"\bpowersploit\b"), "T1059.001", "PowerSploit framework", "critical"),
    (re.compile(r"\blazagne\b"), "T1555", "LaZagne credential harvesting", "critical"),
    (re.compile(_exe("chisel") + r"(?:client|server)\b"), "T1572", "Chisel tunneling", "high"),
    (re.compile(r"\bngrok\b"), "T1572", "Ngrok tunneling", "high"),
    (re.compile(r"\bplink(?:\.exe)?\b"), "T1572", "Plink SSH tunneling", "medium"),
    # --- Defense tampering ---
    (re.compile(r"set-mppreference\b.{0,200}-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|intrusionpreventionsystem|scriptscanning|blockatfirstseen|archivescanning)"),
     "T1562.001", "Defender protection disabled via Set-MpPreference", "high"),
    (re.compile(r"(?:add|set)-mppreference\b.{0,200}-exclusion(?:path|process|extension)\b"),
     "T1562.001", "Defender exclusion added via MpPreference", "high"),
    (re.compile(_exe("sc") + r"(?:stop|config|delete|pause)\s+(?:windefend|sense|wscsvc|securityhealthservice|mpssvc|wuauserv)\b"),
     "T1562.001", "Security service stopped/reconfigured via sc", "high"),
    (re.compile(_exe("net1?") + r"stop\s+(?:windefend|sense|wscsvc|securityhealthservice|mpssvc|wuauserv)\b"),
     "T1562.001", "Security service stopped via net stop", "high"),
    (re.compile(_exe("auditpol") + r"/clear\b"), "T1562.002", "Audit policy cleared", "high"),
    (re.compile(_exe("auditpol") + r"/set\b.{0,160}(?:/success|/failure):disable\b"),
     "T1562.002", "Audit policy logging disabled", "high"),
    (re.compile(_exe("fsutil") + r"usn\s+deletejournal\b"), "T1070", "USN change journal deletion", "high"),
    (re.compile(_exe("netsh") + r"advfirewall\s+set\s+(?:allprofiles|currentprofile|domainprofile|privateprofile|publicprofile)\s+state\s+off\b"),
     "T1562.004", "Windows Firewall disabled via netsh", "high"),
    # --- Anti-forensics / wipe indicators (context-bounded: require a switch, not the bare word) ---
    (re.compile(_exe(r"sdelete(?:64)?") + r"[-/]"), "T1485", "Secure-delete tool usage (sdelete)", "medium"),
    (re.compile(_exe("cipher") + r"/w(?::|\b)"), "T1070.004", "Free-space wipe via cipher /w", "medium"),
    # --- WMI event-subscription persistence: both halves must co-occur in the same text ---
    (re.compile(r"(?=.*eventfilter)(?=.*commandlineeventconsumer)"),
     "T1546.003", "WMI event subscription persistence (EventFilter + CommandLineEventConsumer)", "critical"),
    (re.compile(_exe("bitsadmin") + r"/transfer\b.{0,300}https?://"),
     "T1197", "BITS transfer download from URL", "high"),
]

# Expected parent for common system processes (lowercase)
EXPECTED_PARENTS: dict[str, set[str]] = {
    "svchost.exe": {"services.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "csrss.exe": {"smss.exe"},
    "smss.exe": {"system", "smss.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "spoolsv.exe": {"services.exe"},
    "lsaiso.exe": {"wininit.exe"},
}

# Parent/child pairs that are suspicious regardless (office spawning shells etc.)
SUSPICIOUS_PARENT_CHILD: list[tuple[str, str, str, str]] = [
    ("winword.exe", "cmd.exe", "T1204.002", "Word spawning command shell"),
    ("winword.exe", "powershell.exe", "T1204.002", "Word spawning PowerShell"),
    ("winword.exe", "wscript.exe", "T1204.002", "Word spawning script host"),
    ("winword.exe", "mshta.exe", "T1204.002", "Word spawning mshta"),
    ("excel.exe", "cmd.exe", "T1204.002", "Excel spawning command shell"),
    ("excel.exe", "powershell.exe", "T1204.002", "Excel spawning PowerShell"),
    ("excel.exe", "wscript.exe", "T1204.002", "Excel spawning script host"),
    ("powerpnt.exe", "cmd.exe", "T1204.002", "PowerPoint spawning shell"),
    ("powerpnt.exe", "powershell.exe", "T1204.002", "PowerPoint spawning PowerShell"),
    ("outlook.exe", "cmd.exe", "T1204.002", "Outlook spawning shell"),
    ("outlook.exe", "powershell.exe", "T1204.002", "Outlook spawning PowerShell"),
    ("acrord32.exe", "cmd.exe", "T1204.002", "Adobe Reader spawning shell"),
    ("acrord32.exe", "powershell.exe", "T1204.002", "Adobe Reader spawning PowerShell"),
    ("w3wp.exe", "cmd.exe", "T1505.003", "IIS worker spawning shell (webshell)"),
    ("w3wp.exe", "powershell.exe", "T1505.003", "IIS worker spawning PowerShell (webshell)"),
    ("tomcat.exe", "cmd.exe", "T1505.003", "Tomcat spawning shell (webshell)"),
    ("java.exe", "cmd.exe", "T1505.003", "Java spawning shell (possible webshell)"),
    ("sqlservr.exe", "cmd.exe", "T1505", "SQL Server spawning shell (xp_cmdshell)"),
    ("mysqld.exe", "cmd.exe", "T1505", "MySQL spawning shell"),
    ("explorer.exe", "mshta.exe", "T1218.005", "Explorer spawning mshta"),
    ("svchost.exe", "cmd.exe", "T1543.003", "Service host spawning shell"),
    ("lsass.exe", "cmd.exe", "T1003", "LSASS spawning shell (highly anomalous)"),
    ("wmiprvse.exe", "powershell.exe", "T1047", "WMI provider spawning PowerShell"),
    ("wmiprvse.exe", "cmd.exe", "T1047", "WMI provider spawning shell"),
]

# (parent, child) -> (technique, description) for O(1) lookup in the per-process
# detection loop. Pairs are exact lowercase names and unique, so this is an exact
# substitute for a linear scan of SUSPICIOUS_PARENT_CHILD.
SUSPICIOUS_PARENT_CHILD_MAP: dict[tuple[str, str], tuple[str, str]] = {
    (parent, child): (technique, desc)
    for parent, child, technique, desc in SUSPICIOUS_PARENT_CHILD
}

# System process names that should only run from system paths
SYSTEM_PROCESS_PATHS: dict[str, str] = {
    "svchost.exe": r"\windows\system32",
    "lsass.exe": r"\windows\system32",
    "services.exe": r"\windows\system32",
    "csrss.exe": r"\windows\system32",
    "winlogon.exe": r"\windows\system32",
    "explorer.exe": r"\windows",
    "smss.exe": r"\windows\system32",
    "wininit.exe": r"\windows\system32",
    "taskhostw.exe": r"\windows\system32",
    "spoolsv.exe": r"\windows\system32",
}

SUSPICIOUS_EXECUTION_DIRS = [
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\users\public",
    r"\programdata",
    r"\windows\temp",
    r"\recycler",
    r"\$recycle.bin",
    r"\perflogs",
    r"\intel\logs",
]

# Script hosts / LOLBins whose presence as a scheduled-task action warrants cmdline scrutiny
# (matched against the action's basename with the extension stripped)
SCHEDULED_TASK_SCRIPT_HOSTS: set[str] = {
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
}

# Task names masquerading as vendor updaters -> expected path fragment for the action binary.
# The name fragment is matched against the lowered task-name basename; the expected fragment
# against the normalized action path. A mismatch is one suspicion signal, not a finding.
TASK_UPDATER_MASQUERADES: list[tuple[str, str]] = [
    ("googleupdate", "\\google\\"),
    ("google update", "\\google\\"),
    ("adobeupdate", "\\adobe\\"),
    ("adobe update", "\\adobe\\"),
    ("adobearm", "\\adobe\\"),
    ("acrobat update", "\\adobe\\"),
    ("edgeupdate", "\\microsoft\\edgeupdate"),
    ("msoffice", "\\microsoft"),
    ("officeupdate", "\\microsoft"),
    ("office update", "\\microsoft"),
    ("office automatic update", "\\microsoft"),
    ("onedriveupdate", "\\onedrive"),
    ("onedrive_", "\\onedrive"),
    ("onedrive standalone update", "\\onedrive"),
    ("mozillaupdate", "\\mozilla\\"),
    ("firefox default browser agent", "\\mozilla\\"),
    ("dropboxupdate", "\\dropbox\\"),
    ("teamsupdate", "\\teams"),
]

# Registry persistence locations
PERSISTENCE_REGISTRY_PATHS = [
    (r"currentversion\run", "T1547.001", "Run key persistence"),
    (r"currentversion\runonce", "T1547.001", "RunOnce key persistence"),
    (r"currentversion\policies\explorer\run", "T1547.001", "Policies Run key persistence"),
    (r"winlogon\shell", "T1547.004", "Winlogon shell replacement"),
    (r"winlogon\userinit", "T1547.004", "Winlogon userinit hijack"),
    (r"image file execution options", "T1546.012", "IFEO debugger hijack"),
    (r"appinit_dlls", "T1546.010", "AppInit DLL injection"),
    (r"appcertdlls", "T1546.009", "AppCert DLL injection"),
    (r"netsh\helper", "T1546.007", "Netsh helper DLL"),
    (r"silentprocessexit", "T1546.012", "SilentProcessExit persistence"),
    (r"currentversion\shellserviceobjectdelayload", "T1547", "SSODL persistence"),
    (r"activesetup\installed components", "T1547.014", "Active Setup persistence"),
]

# Web access-log attack indicators, matched (case-insensitive) against the request line.
# An entry's pattern is either a plain substring (fast `in` test) or a compiled regex
# (used where a bare substring is too broad -- e.g. a benign "/powershell-docs/" path or
# the "eval(" inside "retrieval(").
WEB_ATTACK_PATTERNS: list[tuple[str | re.Pattern[str], str, str, str]] = [
    ("..%2f", "T1083", "Path traversal (encoded ../)", "high"),
    ("..%5c", "T1083", "Path traversal (encoded ..\\)", "high"),
    ("%2e%2e", "T1083", "Path traversal (encoded dots)", "high"),
    ("../", "T1083", "Path traversal", "medium"),
    ("..\\", "T1083", "Path traversal", "medium"),
    ("etc/passwd", "T1083", "Local file inclusion (/etc/passwd)", "high"),
    ("boot.ini", "T1083", "Local file inclusion (boot.ini)", "high"),
    ("win.ini", "T1083", "Local file inclusion (win.ini)", "high"),
    ("<script", "T1059.007", "Reflected XSS attempt", "medium"),
    ("document.cookie", "T1059.007", "XSS cookie theft attempt", "high"),
    ("onerror=", "T1059.007", "XSS event-handler injection", "medium"),
    ("union select", "T1190", "SQL injection (UNION SELECT)", "high"),
    ("union+select", "T1190", "SQL injection (UNION SELECT)", "high"),
    ("' or '1'='1", "T1190", "SQL injection (auth bypass)", "high"),
    ("or 1=1", "T1190", "SQL injection (tautology)", "high"),
    ("sleep(", "T1190", "SQL injection (time-based)", "medium"),
    ("benchmark(", "T1190", "SQL injection (time-based)", "medium"),
    ("/bin/sh", "T1059.004", "Command injection (shell)", "critical"),
    ("/bin/bash", "T1059.004", "Command injection (shell)", "critical"),
    (";cmd", "T1059", "Command injection", "high"),
    ("cmd.exe", "T1059.003", "Command injection (cmd.exe)", "high"),
    # Bare "powershell" matches benign paths (/powershell-docs/, ?lang=powershell);
    # require a shell-injection delimiter (raw or percent-encoded ; & | ` $( ) right
    # before it so only command-injection-shaped requests fire.
    (re.compile(r"(?:[;&|`]|%3b|%26|%7c|\$\()\s*'?\"?powershell"),
     "T1059.001", "Command injection (PowerShell)", "high"),
    ("wget ", "T1105", "Remote payload download (wget)", "high"),
    ("curl ", "T1105", "Remote payload download (curl)", "high"),
    ("cmd.jsp", "T1505.003", "JSP web shell access", "critical"),
    ("shell.jsp", "T1505.003", "JSP web shell access", "critical"),
    ("cmd.asp", "T1505.003", "ASP web shell access", "critical"),
    ("shell.php", "T1505.003", "PHP web shell access", "critical"),
    ("c99.php", "T1505.003", "c99 PHP web shell", "critical"),
    ("r57.php", "T1505.003", "r57 PHP web shell", "critical"),
    # \b anchors "eval" to a token boundary so "retrieval(" / "medieval(" don't match.
    (re.compile(r"\beval\s*\("), "T1505.003", "Web shell eval() payload", "medium"),
    ("base64_decode", "T1140", "Encoded payload (base64_decode)", "high"),
    ("/manager/html", "T1190", "Tomcat Manager access (deploy vector)", "low"),
    ("/manager/deploy", "T1505.003", "Tomcat Manager app deployment", "high"),
    ("/manager/upload", "T1505.003", "Tomcat Manager app upload", "high"),
    (".war", "T1505.003", "WAR archive deployment (webshell vector)", "high"),
]

# Scanner/attack-tool signatures that live in the *User-Agent* header, not the request
# line. Matching these against the URL produced both false positives (a benign
# "/nmap-tutorial" path) and false negatives (a scanner sending a normal-looking URL
# with a tell-tale UA). Matched case-insensitively against the user_agent field.
WEB_USER_AGENT_PATTERNS: list[tuple[str, str, str, str]] = [
    ("sqlmap", "T1595", "sqlmap scanner user-agent", "medium"),
    ("nikto", "T1595", "Nikto scanner user-agent", "medium"),
    ("nessus", "T1595", "Nessus scanner user-agent", "medium"),
    ("acunetix", "T1595", "Acunetix scanner user-agent", "medium"),
    ("nuclei", "T1595", "Nuclei scanner user-agent", "medium"),
    ("dirbuster", "T1595", "DirBuster content-discovery user-agent", "medium"),
    ("gobuster", "T1595", "Gobuster content-discovery user-agent", "medium"),
    ("wpscan", "T1595", "WPScan user-agent", "medium"),
    ("masscan", "T1595", "Masscan probe user-agent", "low"),
    ("nmap", "T1595", "Nmap probe user-agent", "low"),
    ("zgrab", "T1595", "zgrab banner-grab user-agent", "low"),
]

MITRE_TECHNIQUE_NAMES: dict[str, str] = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1003.003": "NTDS",
    "T1003.006": "DCSync",
    "T1005": "Data from Local System",
    "T1036.005": "Match Legitimate Name or Location",
    "T1204": "User Execution",
    "T1033": "System Owner/User Discovery",
    "T1047": "Windows Management Instrumentation",
    "T1053.002": "At",
    "T1053.005": "Scheduled Task",
    "T1055": "Process Injection",
    "T1055.012": "Process Hollowing",
    "T1059.001": "PowerShell",
    "T1059.005": "Visual Basic",
    "T1070.001": "Clear Windows Event Logs",
    "T1071": "Application Layer Protocol",
    "T1087": "Account Discovery",
    "T1087.002": "Domain Account",
    "T1090": "Proxy",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1112": "Modify Registry",
    "T1127.001": "MSBuild",
    "T1136.001": "Create Local Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs",
    "T1202": "Indirect Command Execution",
    "T1204.002": "Malicious File",
    "T1218.003": "CMSTP",
    "T1218.004": "InstallUtil",
    "T1218.005": "Mshta",
    "T1218.007": "Msiexec",
    "T1218.008": "Odbcconf",
    "T1218.009": "Regsvcs/Regasm",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
    "T1222": "File and Directory Permissions Modification",
    "T1482": "Domain Trust Discovery",
    "T1490": "Inhibit System Recovery",
    "T1505": "Server Software Component",
    "T1505.003": "Web Shell",
    "T1543.003": "Windows Service",
    "T1546.007": "Netsh Helper DLL",
    "T1546.009": "AppCert DLLs",
    "T1546.010": "AppInit DLLs",
    "T1546.012": "Image File Execution Options Injection",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547.004": "Winlogon Helper DLL",
    "T1547.014": "Active Setup",
    "T1555": "Credentials from Password Stores",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.001": "Golden Ticket",
    "T1558.003": "Kerberoasting",
    "T1564.001": "Hidden Files and Directories",
    "T1564.003": "Hidden Window",
    "T1570": "Lateral Tool Transfer",
    "T1572": "Protocol Tunneling",
    "T1620": "Reflective Code Loading",
    "T1014": "Rootkit",
    "T1573": "Encrypted Channel",
    "T1083": "File and Directory Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1059.007": "JavaScript",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1190": "Exploit Public-Facing Application",
    "T1595": "Active Scanning",
    "T1553.006": "Code Signing Policy Modification",
    "T1006": "Direct Volume Access",
    "T1021.001": "Remote Desktop Protocol",
    "T1053": "Scheduled Task/Job",
    "T1070": "Indicator Removal",
    "T1070.004": "File Deletion",
    "T1485": "Data Destruction",
    "T1546.003": "Windows Management Instrumentation Event Subscription",
    "T1562.001": "Disable or Modify Tools",
    "T1562.002": "Disable Windows Event Logging",
    "T1562.004": "Disable or Modify System Firewall",
}
