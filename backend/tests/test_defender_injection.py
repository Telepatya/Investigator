from __future__ import annotations

# ruff: noqa: E402
#
# Defender DeviceEvents cross-process access/injection (CreateRemoteThreadApiCall,
# WriteToLsassProcessMemory, ...) are mapped to the synthetic Sysmon EID 8/10 keys
# the engine's existing _check_cross_process_event detection reads, so the
# "Remote thread creation" / "Suspicious process access" findings fire on Defender
# data with the correct source and target processes -- no engine change.

import json
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
from app.detect.engine import run_detections_sync
from app.ingest.pipeline import ingest_file_sync
from app.store import cases
from app.store import database
from app.store.database import Finding


def _noop(*_a, **_k) -> None:
    return None


class DefenderInjectionTests(unittest.TestCase):
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

    def _run(self, rows: list[dict]) -> list[Finding]:
        path = self.root / "DeviceEvents.json"
        path.write_text(json.dumps(rows), encoding="utf-8")
        case = cases.create_case("inj")
        ingest_file_sync(case["id"], path, _noop)
        run_detections_sync(case["id"])
        s = cases.get_session(case["id"])
        try:
            return list(s.scalars(select(Finding)))
        finally:
            s.close()

    def test_remote_thread_creation(self) -> None:
        findings = self._run([{
            "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
            "ActionType": "CreateRemoteThreadApiCall",
            "FileName": "victim.exe", "FolderPath": "C:\\Windows\\System32\\victim.exe",
            "InitiatingProcessFileName": "malware.exe",
            "InitiatingProcessFolderPath": "C:\\Users\\v\\malware.exe",
            "InitiatingProcessId": 1337,
            "AdditionalFields": json.dumps({"TargetProcessId": 4242, "StartAddress": "0x7ff000"}),
        }])
        finding = next((f for f in findings if f.title == "Remote thread creation"), None)
        self.assertIsNotNone(finding, f"missing injection finding; titles={[f.title for f in findings]}")
        self.assertIn("malware.exe", finding.evidence.get("source_image", ""))
        self.assertIn("victim.exe", finding.evidence.get("target_image", ""))

    def test_lsass_memory_access(self) -> None:
        findings = self._run([{
            "Timestamp": "2026-07-06T10:01:00Z", "DeviceName": "WKS-01",
            "ActionType": "WriteToLsassProcessMemory",
            "FileName": "lsass.exe", "FolderPath": "C:\\Windows\\System32\\lsass.exe",
            "InitiatingProcessFileName": "mimikatz.exe",
            "InitiatingProcessFolderPath": "C:\\Users\\v\\mimikatz.exe",
            "InitiatingProcessId": 6666,
            "AdditionalFields": json.dumps({"TargetProcessId": 700, "DesiredAccess": "0x1010"}),
        }])
        finding = next((f for f in findings if f.title == "Suspicious process access"), None)
        self.assertIsNotNone(finding, f"missing lsass-access finding; titles={[f.title for f in findings]}")
        self.assertIn("lsass.exe", finding.evidence.get("target_image", ""))

    def test_non_injection_deviceevent_is_not_misclassified(self) -> None:
        # An ordinary DeviceEvents row must not be turned into an injection finding.
        findings = self._run([{
            "Timestamp": "2026-07-06T10:02:00Z", "DeviceName": "WKS-01",
            "ActionType": "AntivirusScanCompleted",
            "InitiatingProcessFileName": "MsMpEng.exe",
        }])
        self.assertFalse(
            any(f.title in ("Remote thread creation", "Suspicious process access") for f in findings),
            f"benign DeviceEvent wrongly flagged; titles={[f.title for f in findings]}",
        )


if __name__ == "__main__":
    unittest.main()
