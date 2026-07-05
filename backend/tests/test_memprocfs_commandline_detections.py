from __future__ import annotations

import tempfile
import sys
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
    get_password=lambda *_args, **_kwargs: None,
    set_password=lambda *_args, **_kwargs: None,
    delete_password=lambda *_args, **_kwargs: None,
    errors=types.SimpleNamespace(PasswordDeleteError=Exception),
))
sys.modules.setdefault("pydantic", types.SimpleNamespace(
    BaseModel=_BaseModel,
    Field=lambda default=None, default_factory=None, **_kwargs: default_factory() if default_factory else default,
))

from app.detect.engine import run_detections_sync
from app.store import cases, database
from app.store.database import Event, Finding, MemoryResult, Process


class MemProcFSCommandlineDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda case_id: self.root / case_id / "case.db"),
        ]
        for p in self.patches:
            p.start()
        self.case = cases.create_case("cmdlines")
        self.session = cases.get_session(self.case["id"])

    def tearDown(self) -> None:
        self.session.close()
        database.dispose_all_db_engines()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_process_commandline_and_memprocfs_task_commandline_detect(self) -> None:
        self.session.add(Process(
            pid=10,
            ppid=4,
            name="qTbZGdHw.exe",
            path=r"C:\Windows\qTbZGdHw.exe",
            cmdline=r"C:\Windows\qTbZGdHw.exe -nop -enc AAAA",
            session_id="mem-test",
            flags=[],
            severity="info",
            extra={},
        ))
        self.session.add(Event(
            timestamp=None,
            host=None,
            source="mem-test:forensic/csv/tasks.csv",
            category="persistence",
            entity="BadTask",
            severity="info",
            summary="MemProcFS tasks row",
            raw={
                "TaskName": "BadTask",
                "TaskPath": r"\BadTask",
                "CommandLine": "powershell.exe",
                "Parameters": "-nop -enc AAAA",
                "memprocfs_csv": "tasks.csv",
            },
        ))
        self.session.commit()

        added = run_detections_sync(self.case["id"])

        titles = {f.title for f in self.session.query(Finding)}
        self.assertGreaterEqual(added, 4)
        self.assertIn("PowerShell encoded command", titles)
        self.assertIn("Random-looking executable in Windows root: qTbZGdHw.exe", titles)
        self.assertTrue(any(t.startswith("Scheduled task with suspicious property") for t in titles))

    def test_timeline_file_path_is_not_scanned_as_commandline(self) -> None:
        self.session.add(Event(
            timestamp=None,
            host=None,
            source="mem-test:forensic/csv/timeline_all.csv",
            category="filesystem",
            entity=r"\Windows\System32\scrobj.dll",
            severity="info",
            summary="MemProcFS NTFS: scrobj.dll",
            raw={
                "Type": "NTFS",
                "Action": "MOD",
                "Text": r"\1\Windows\System32\scrobj.dll",
                "memprocfs_csv": "timeline_all.csv",
            },
        ))
        self.session.commit()

        run_detections_sync(self.case["id"])

        titles = {f.title for f in self.session.query(Finding)}
        self.assertNotIn("Squiblydoo scriptlet execution", titles)

    def test_passive_staging_executable_timeline_row_is_not_a_finding(self) -> None:
        self.session.add(Event(
            timestamp=None,
            host=None,
            source="mem-atlas:forensic/csv/timeline_all.csv",
            category="filesystem",
            entity=r"\Users\roeif\AppData\Local\Temp\tool.exe",
            severity="info",
            summary="MemProcFS NTFS: tool.exe",
            raw={
                "Type": "NTFS",
                "Action": "CRE",
                "Text": r"\1\Users\roeif\AppData\Local\Temp\tool.exe",
                "memprocfs_csv": "timeline_all.csv",
            },
        ))
        self.session.commit()

        run_detections_sync(self.case["id"])

        findings = list(self.session.query(Finding))
        titles = {f.title for f in findings}
        self.assertNotIn("MemProcFS timeline: executable artifact in staging path", titles)
        event = self.session.query(Event).filter(Event.entity.like("%tool.exe")).one()
        self.assertEqual(event.severity, "low")

    def test_weak_memprocfs_findevil_rows_are_context_not_findings(self) -> None:
        self.session.add(MemoryResult(
            plugin="memprocfs_findevil",
            pid=1234,
            process_name="Codex.exe",
            summary="findevil: HIGH_ENTROPY in Codex.exe",
            data={"row": {"Type": "HIGH_ENTROPY", "Process": "Codex.exe"}},
            severity="high",
        ))
        self.session.commit()

        run_detections_sync(self.case["id"])

        titles = {f.title for f in self.session.query(Finding)}
        self.assertFalse(any(t.startswith("Memory forensic indicator: memprocfs_findevil") for t in titles))

    def test_memprocfs_ifeo_registry_requires_value_level_evidence(self) -> None:
        self.session.add_all([
            Event(
                timestamp=None,
                host=None,
                source="mem-atlas:forensic/csv/timeline_all.csv",
                category="registry",
                entity=r"Image File Execution Options\foo.exe",
                severity="info",
                summary="MemProcFS REG: IFEO root",
                raw={
                    "Type": "REG",
                    "Action": "MOD",
                    "Text": (
                        r"\REGISTRY\MACHINE\Software\Microsoft\Windows NT\CurrentVersion"
                        r"\Image File Execution Options\foo.exe"
                    ),
                    "memprocfs_csv": "timeline_all.csv",
                },
            ),
            Event(
                timestamp=None,
                host=None,
                source="mem-atlas:forensic/csv/timeline_all.csv",
                category="registry",
                entity=r"Image File Execution Options\bar.exe\Debugger",
                severity="info",
                summary="MemProcFS REG: IFEO debugger",
                raw={
                    "Type": "REG",
                    "Action": "MOD",
                    "Text": (
                        r"\REGISTRY\MACHINE\Software\Microsoft\Windows NT\CurrentVersion"
                        r"\Image File Execution Options\bar.exe\Debugger"
                    ),
                    "memprocfs_csv": "timeline_all.csv",
                },
            ),
        ])
        self.session.commit()

        run_detections_sync(self.case["id"])

        findings = list(self.session.query(Finding))
        titles = [f.title for f in findings]
        self.assertEqual(titles.count("MemProcFS timeline: IFEO debugger hijack"), 1)
        self.assertTrue(any("bar.exe" in (f.evidence or {}).get("text", "") for f in findings))

    def test_sysmon_remote_thread_and_dangerous_process_access_detect(self) -> None:
        self.session.add_all([
            Event(
                timestamp=None,
                host=None,
                source="sysmon.evtx",
                category="process",
                entity="injector.exe",
                severity="info",
                summary="CreateRemoteThread: injector.exe -> notepad.exe",
                raw={
                    "EventID": "8",
                    "SourceImage": r"C:\Tools\injector.exe",
                    "TargetImage": r"C:\Windows\System32\notepad.exe",
                    "StartAddress": "0x1000",
                },
            ),
            Event(
                timestamp=None,
                host=None,
                source="sysmon.evtx",
                category="process",
                entity="procdump.exe",
                severity="info",
                summary="ProcessAccess: procdump.exe -> lsass.exe",
                raw={
                    "EventID": "10",
                    "SourceImage": r"C:\Tools\procdump.exe",
                    "TargetImage": r"C:\Windows\System32\lsass.exe",
                    "GrantedAccess": "0x1fffff",
                },
            ),
        ])
        self.session.commit()

        run_detections_sync(self.case["id"])

        titles = {f.title for f in self.session.query(Finding)}
        self.assertIn("Remote thread creation", titles)
        self.assertIn("Suspicious process access", titles)

    def test_high_risk_memory_handle_detects(self) -> None:
        self.session.add(Event(
            timestamp=None,
            host=None,
            source="memory:handles",
            category="handle",
            entity="tool.exe",
            severity="high",
            summary="tool.exe handle Process -> lsass.exe",
            raw={
                "plugin": "handles",
                "session_id": "mem-test",
                "PID": 44,
                "Process": "tool.exe",
                "Type": "Process",
                "Name": "lsass.exe",
                "TargetPID": 500,
                "TargetProcess": "lsass.exe",
                "Access": "0x143a",
                "risk": "critical",
                "risk_reasons": ["target appears sensitive"],
            },
        ))
        self.session.commit()

        run_detections_sync(self.case["id"])

        titles = {f.title for f in self.session.query(Finding)}
        self.assertIn("Suspicious cross-process handle", titles)


if __name__ == "__main__":
    unittest.main()
