from __future__ import annotations

# ruff: noqa: E402
#
# DeviceFileEvents substitutes for the NTFS USN journal on Defender cases: a
# downloaded file can be followed across a FileRenamed (masquerade) into the name
# it was executed under, and a FileDeleted after execution is flagged as cleanup.
# This reuses the existing USN provenance machinery via synthetic USN keys plus a
# single-row Defender rename collector -- the USN-journal path is untouched.

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


class DefenderFileLifecycleTests(unittest.TestCase):
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

    def _write(self, name: str, rows: list[dict]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(rows), encoding="utf-8")
        return path

    def _run(self, case_id: str, files: list[Path]) -> list[Finding]:
        for f in files:
            ingest_file_sync(case_id, f, _noop)
        run_detections_sync(case_id)
        s = cases.get_session(case_id)
        try:
            return list(s.scalars(select(Finding)))
        finally:
            s.close()

    def test_rename_chain_follows_download_to_execution(self) -> None:
        downloaded = "C:\\Users\\v\\Downloads\\invoice_9f2.pdf.exe"
        renamed = "C:\\Users\\v\\AppData\\Roaming\\wsusupd_helper.exe"
        files = [
            self._write("DeviceFileEvents.json", [
                {
                    "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
                    "ActionType": "FileCreated", "FileName": "invoice_9f2.pdf.exe",
                    "FolderPath": downloaded, "SHA256": "hash-1",
                    "FileOriginUrl": "https://evil.example/invoice_9f2.pdf.exe",
                    "InitiatingProcessFileName": "chrome.exe",
                },
                {
                    "Timestamp": "2026-07-06T10:01:00Z", "DeviceName": "WKS-01",
                    "ActionType": "FileRenamed", "FileName": "wsusupd_helper.exe",
                    "FolderPath": renamed,
                    "PreviousFileName": "invoice_9f2.pdf.exe",
                    "PreviousFolderPath": downloaded, "SHA256": "hash-1",
                    "InitiatingProcessFileName": "explorer.exe",
                },
            ]),
            self._write("DeviceProcessEvents.json", [{
                "Timestamp": "2026-07-06T10:02:00Z", "DeviceName": "WKS-01",
                "ActionType": "ProcessCreated", "FileName": "wsusupd_helper.exe",
                "FolderPath": renamed, "ProcessId": 7777,
                "ProcessCommandLine": "wsusupd_helper.exe", "AccountName": "v",
                "InitiatingProcessId": 900, "InitiatingProcessFileName": "explorer.exe",
            }]),
        ]
        case = cases.create_case("rename")
        findings = self._run(case["id"], files)
        titles = [f.title for f in findings]
        self.assertTrue(
            any("later executed" in t and "renamed" in t for t in titles),
            f"expected a renamed download->execution chain; titles={titles}",
        )
        # evidence records the rename chain old->new path
        chain = next(f for f in findings if "renamed" in f.title)
        self.assertIn("invoice_9f2.pdf.exe", chain.evidence.get("renamed_from", ""))
        self.assertIn("wsusupd_helper.exe", chain.evidence.get("renamed_to", ""))

    def test_delete_after_execution_flags_cleanup(self) -> None:
        path = "C:\\Users\\v\\Downloads\\dropper_x1.exe"
        files = [
            self._write("DeviceFileEvents.json", [
                {
                    "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
                    "ActionType": "FileCreated", "FileName": "dropper_x1.exe",
                    "FolderPath": path, "SHA256": "hash-2",
                    "FileOriginUrl": "https://evil.example/dropper_x1.exe",
                    "InitiatingProcessFileName": "chrome.exe",
                },
                {
                    "Timestamp": "2026-07-06T10:10:00Z", "DeviceName": "WKS-01",
                    "ActionType": "FileDeleted", "FileName": "dropper_x1.exe",
                    "FolderPath": path, "SHA256": "hash-2",
                    "InitiatingProcessFileName": "dropper_x1.exe",
                },
            ]),
            self._write("DeviceProcessEvents.json", [{
                "Timestamp": "2026-07-06T10:02:00Z", "DeviceName": "WKS-01",
                "ActionType": "ProcessCreated", "FileName": "dropper_x1.exe",
                "FolderPath": path, "ProcessId": 8888,
                "ProcessCommandLine": "dropper_x1.exe", "AccountName": "v",
                "InitiatingProcessId": 900, "InitiatingProcessFileName": "explorer.exe",
            }]),
        ]
        case = cases.create_case("delete")
        findings = self._run(case["id"], files)
        titles = [f.title for f in findings]
        self.assertTrue(
            any("later executed" in t and "deleted" in t for t in titles),
            f"expected a download->execution->delete cleanup finding; titles={titles}",
        )
        chain = next(f for f in findings if "deleted" in f.title)
        self.assertTrue(chain.evidence.get("deleted_after_execution"))


if __name__ == "__main__":
    unittest.main()
