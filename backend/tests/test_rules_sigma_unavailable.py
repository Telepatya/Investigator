from __future__ import annotations

# ruff: noqa: E402
#
# Regression coverage for a shipped outage: `pysigma` was added to requirements.in
# but the lock files were never regenerated, so it was never installed. Because
# app/main.py imports the rules router at module scope, and that reaches a top-level
# `from sigma.collection import ...`, the entire backend failed to start — cases,
# evidence, timeline, and Reverse included — over a package only custom rules need.
#
# These tests pin the contract that came out of that: pySigma is required to author
# custom Sigma rules, and required for nothing else. Built-in rule management and
# detection runs keep working without it.
#
# The import guard itself is verified in a subprocess. Blocking `sigma` in-process
# would mean reloading a web of interdependent modules, leaving two live copies of
# `sigma_compile` and contaminating later tests. Everything downstream of the guard
# is exercised by patching the availability flag, which those code paths read at
# call time.

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select

from app.rules import database as rules_database
from app.rules import profile as profile_module
from app.rules import sigma_compile
from app.store import cases, database
from app.store.database import Finding, Process

BACKEND_ROOT = Path(__file__).resolve().parent.parent

# Installed as a meta-path hook in the subprocess so `import sigma` fails exactly as
# it would on a machine where the package was never installed.
_BLOCK_SIGMA = """
import sys


class _Blocker:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "sigma" or fullname.startswith("sigma."):
            raise ImportError("No module named %r" % fullname)
        return None


sys.meta_path.insert(0, _Blocker())
"""


def _run_without_pysigma(body: str) -> dict:
    """Run `body` in a subprocess where pySigma cannot be imported."""
    script = textwrap.dedent(_BLOCK_SIGMA) + textwrap.dedent(body)
    with tempfile.TemporaryDirectory() as home:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=BACKEND_ROOT,
            capture_output=True,
            text=True,
            timeout=180,
            env={
                **{key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP") if key in os.environ},
                "HOME": home,
                "USERPROFILE": home,
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "PYTHONPATH": str(BACKEND_ROOT),
            },
        )
    if completed.returncode != 0:
        raise AssertionError(
            f"subprocess failed ({completed.returncode}):\n{completed.stderr[-3000:]}"
        )
    return json.loads(completed.stdout.strip().splitlines()[-1])


class ImportGuardTests(unittest.TestCase):
    """The backend must start when pySigma is absent. This is the reported crash."""

    def test_backend_application_starts_without_pysigma(self) -> None:
        result = _run_without_pysigma(
            """
            from fastapi.testclient import TestClient
            from app.main import app
            from app.rules import sigma_compile

            with TestClient(app, base_url="http://127.0.0.1:8400") as client:
                health = client.get("/api/health").json()
                rules = client.get("/api/rules").json()
                import json
                print(json.dumps({
                    "available": sigma_compile.sigma_available(),
                    "reason": sigma_compile.sigma_unavailable_reason(),
                    "health_sigma": health["sigma"],
                    "health_status": health["status"],
                    "builtin_total": rules["builtin_total"],
                    "sigma_available": rules["sigma_available"],
                    "sigma_error": rules["sigma_error"],
                }))
            """
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["health_status"], "ok")
        self.assertFalse(result["health_sigma"])
        self.assertIn("pysigma", result["reason"])
        # The catalog is unaffected: every built-in rule is still manageable.
        self.assertGreater(result["builtin_total"], 250)
        self.assertFalse(result["sigma_available"])
        self.assertIn("pysigma", result["sigma_error"])

    def test_builtin_rules_are_still_togglable_without_pysigma(self) -> None:
        result = _run_without_pysigma(
            """
            from fastapi.testclient import TestClient
            from app.main import app

            with TestClient(app, base_url="http://127.0.0.1:8400") as client:
                patched = client.patch(
                    "/api/rules/builtin/lolbin.certutil", json={"enabled": False}
                )
                listing = client.get("/api/rules?source=builtin").json()
                states = {item["id"]: item["enabled"] for item in listing["rules"]}
                created = client.post(
                    "/api/rules/custom", json={"yaml_source": "title: x\\nid: 1\\n"}
                )
                forked = client.post(
                    "/api/rules/builtin/lolbin.mshta/fork", json={"disable_builtin": True}
                )
                validated = client.post(
                    "/api/rules/validate", json={"yaml_source": "title: x"}
                ).json()
                import json
                print(json.dumps({
                    "toggle_status": patched.status_code,
                    "certutil_enabled": states["lolbin.certutil"],
                    "mshta_enabled": states["lolbin.mshta"],
                    "create_status": created.status_code,
                    "create_detail": created.json().get("detail", ""),
                    "fork_status": forked.status_code,
                    "validate_ok": validated["ok"],
                    "validate_error": validated["error"],
                }))
            """
        )
        # Built-in management is fully functional.
        self.assertEqual(result["toggle_status"], 200)
        self.assertFalse(result["certutil_enabled"])
        self.assertTrue(result["mshta_enabled"])
        # Authoring is refused with 503 — a server capability problem, not bad input.
        self.assertEqual(result["create_status"], 503)
        self.assertIn("pysigma", result["create_detail"])
        self.assertEqual(result["fork_status"], 503)
        self.assertFalse(result["validate_ok"])
        self.assertIn("pysigma", result["validate_error"])


class AvailabilityContractTests(unittest.TestCase):
    def test_pysigma_is_installed_in_this_environment(self) -> None:
        """Guards the guard: the dependency locks must actually install pySigma.

        This is the assertion that would have failed on the stale locks.
        """
        self.assertTrue(
            sigma_compile.sigma_available(),
            "pysigma is not installed — run backend/scripts/update-locks.sh",
        )

    def test_unavailability_is_a_rule_error_so_callers_skip_gracefully(self) -> None:
        """Subclassing SigmaRuleError is what keeps a detection run alive."""
        self.assertTrue(
            issubclass(sigma_compile.SigmaUnavailableError, sigma_compile.SigmaRuleError)
        )

    def test_parsing_reports_the_missing_package(self) -> None:
        with patch.object(sigma_compile, "SIGMA_AVAILABLE", False):
            with self.assertRaises(sigma_compile.SigmaUnavailableError) as caught:
                sigma_compile.parse_rules("title: anything\n")
        self.assertIn("pysigma", str(caught.exception))


class DegradedDetectionTests(unittest.TestCase):
    """A detection run completes without pySigma; custom rules are simply skipped."""

    def setUp(self) -> None:
        self.cases_tmp = tempfile.TemporaryDirectory()
        self.rules_tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.cases_tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(
                cases, "case_db_path", side_effect=lambda cid: self.root / cid / "case.db"
            ),
            patch.object(
                rules_database, "get_rules_dir", return_value=Path(self.rules_tmp.name)
            ),
        ]
        for item in self.patches:
            item.start()
        rules_database.dispose_rules_db()
        profile_module.invalidate_cache()

    def tearDown(self) -> None:
        database.dispose_all_db_engines()
        rules_database.dispose_rules_db()
        profile_module.invalidate_cache()
        for item in reversed(self.patches):
            item.stop()
        self.cases_tmp.cleanup()
        self.rules_tmp.cleanup()

    def _store_custom_rule(self) -> None:
        source = "title: stored while pysigma was available\n"
        session = rules_database.get_rules_session()
        try:
            session.add(
                rules_database.CustomRule(
                    id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    slug="stored",
                    title="Stored",
                    enabled=True,
                    severity="high",
                    techniques=[],
                    yaml_source=source,
                    content_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
                    compile_status="ok",
                )
            )
            session.commit()
        finally:
            session.close()

    def test_run_completes_and_builtin_state_still_applies(self) -> None:
        from app.detect import engine
        from app.rules import store as rules_store

        self._store_custom_rule()
        rules_store.set_builtin_state("lolbin.certutil", enabled=False)

        case = cases.create_case("no-sigma")
        session = cases.get_session(case["id"])
        try:
            session.add(
                Process(
                    pid=1, ppid=4, name="powershell.exe",
                    path=r"C:\Windows\powershell.exe",
                    cmdline="powershell.exe -enc AAAA", session_id="default",
                )
            )
            session.add(
                Process(
                    pid=2, ppid=4, name="certutil.exe",
                    path=r"C:\Windows\certutil.exe",
                    cmdline="certutil.exe -urlcache -f http://x/a.exe a.exe",
                    session_id="default",
                )
            )
            session.commit()
        finally:
            session.close()

        with patch.object(sigma_compile, "SIGMA_AVAILABLE", False):
            profile_module.invalidate_cache()
            # Must not raise, despite an enabled custom rule that cannot be compiled.
            engine.run_detections_sync(case["id"])

        session = cases.get_session(case["id"])
        try:
            titles = [item.title for item in session.scalars(select(Finding))]
        finally:
            session.close()

        # Built-in detection is unaffected, and the disabled built-in stayed disabled.
        self.assertIn("PowerShell encoded command", titles)
        self.assertNotIn("LOLBin activity: certutil.exe", titles)


if __name__ == "__main__":
    unittest.main()
