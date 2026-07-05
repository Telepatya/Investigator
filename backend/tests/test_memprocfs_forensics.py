from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.memory.forensics import ingest_memprocfs_artifacts_sync
from app.store import database
from app.store.database import Event, MemoryResult, Process


def _progress(_phase, _percent, _message, _done, _error):
    return None


class MemProcFSForensicsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        factory = database.init_db(self.root / "case.db")
        self.session = factory()

    def tearDown(self) -> None:
        self.session.close()
        database.dispose_all_db_engines()
        self.tmp.cleanup()

    def test_timeline_all_is_canonical_and_findevil_creates_memory_result(self) -> None:
        artifact_dir = self.root / "derived"
        csv_dir = artifact_dir / "forensic" / "csv"
        csv_dir.mkdir(parents=True)
        (csv_dir / "timeline_all.csv").write_text(
            "Time,Type,Name\n2024-01-01 00:00:00,Process,evil.exe\n",
            encoding="utf-8",
        )
        (csv_dir / "timeline_process.csv").write_text(
            "Time,Type,Name\n2024-01-01 00:00:01,Process,duplicate.exe\n",
            encoding="utf-8",
        )
        (csv_dir / "process.csv").write_text(
            "PID,PPID,Name,Path,Cmdline,CreateTime\n123,4,evil.exe,C:\\Temp\\evil.exe,evil -x,2024-01-01 00:00:00\n",
            encoding="utf-8",
        )
        (csv_dir / "findevil.csv").write_text(
            "PID,Process,Reason\n123,evil.exe,injected\n",
            encoding="utf-8",
        )

        stats = ingest_memprocfs_artifacts_sync(self.session, "sample", artifact_dir, None, _progress)

        sources = sorted(e.source for e in self.session.query(Event).all())
        self.assertIn("mem-sample:forensic/csv/timeline_all.csv", sources)
        self.assertNotIn("mem-sample:forensic/csv/timeline_process.csv", sources)
        self.assertEqual(self.session.query(Process).filter_by(session_id="mem-sample", pid=123).count(), 1)
        self.assertEqual(self.session.query(MemoryResult).filter_by(plugin="memprocfs_findevil").count(), 1)
        self.assertEqual(stats["files"], 3)

    def test_individual_timelines_are_used_when_timeline_all_is_missing(self) -> None:
        artifact_dir = self.root / "derived"
        csv_dir = artifact_dir / "forensic" / "csv"
        csv_dir.mkdir(parents=True)
        (csv_dir / "timeline_net.csv").write_text(
            "Time,Type,RemoteAddress\n2024-01-01 00:00:00,Net,8.8.8.8\n",
            encoding="utf-8",
        )

        ingest_memprocfs_artifacts_sync(self.session, "sample", artifact_dir, None, _progress)

        event = self.session.query(Event).one()
        self.assertEqual(event.source, "mem-sample:forensic/csv/timeline_net.csv")
        self.assertEqual(event.category, "network")


if __name__ == "__main__":
    unittest.main()
