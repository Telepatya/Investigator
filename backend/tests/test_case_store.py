from __future__ import annotations

# ruff: noqa: E402

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from threading import Event as ThreadEvent, Thread
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

from app.ingest import evidence
from app.memory import forensics
from app.memory import pipeline as memory_pipeline
from app.store import cases
from app.store import database
from app.store.database import Event, MemoryResult, Process


class CaseStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda case_id: self.root / case_id / "case.db"),
            patch.object(forensics, "get_cases_dir", return_value=self.root),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        database.dispose_all_db_engines()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_delete_case_removes_directory_after_session_pool_used(self) -> None:
        case = cases.create_case("delete me")
        case_dir = self.root / case["id"]

        session = cases.get_session(case["id"])
        session.close()

        self.assertTrue(cases.delete_case(case["id"]))
        self.assertFalse(case_dir.exists())

        registry = json.loads((self.root / "registry.json").read_text(encoding="utf-8"))
        self.assertNotIn(case["id"], registry["cases"])

    def test_get_session_reuses_cached_engine(self) -> None:
        case = cases.create_case("cache me")
        db_path = (self.root / case["id"] / "case.db").resolve()

        first = cases.get_session(case["id"])
        first.close()
        second = cases.get_session(case["id"])
        second.close()

        self.assertIn(db_path, database._ENGINE_CACHE)
        self.assertEqual(len(database._ENGINE_CACHE), 1)

    def test_startup_recovers_only_transient_case_statuses(self) -> None:
        ingesting = cases.create_case("interrupted ingest")
        analyzing = cases.create_case("interrupted analysis")
        ready = cases.create_case("already ready")
        cases.update_case_meta(ingesting["id"], include_stats=False, status="ingesting")
        cases.update_case_meta(analyzing["id"], include_stats=False, status="analyzing")
        cases.update_case_meta(ready["id"], include_stats=False, status="ready")

        recovered = cases.recover_interrupted_case_operations()

        self.assertCountEqual(recovered, [ingesting["id"], analyzing["id"]])
        registry = json.loads((self.root / "registry.json").read_text(encoding="utf-8"))
        self.assertEqual(registry["cases"][ingesting["id"]]["status"], "ready")
        self.assertEqual(registry["cases"][analyzing["id"]]["status"], "ready")
        self.assertEqual(registry["cases"][ready["id"]]["status"], "ready")

    def test_case_writes_are_serialized_until_commit(self) -> None:
        case = cases.create_case("serialized writes")
        first = cases.get_session(case["id"])
        first.add(Event(
            timestamp=None, host=None, source="first", category="test",
            entity=None, severity="info", summary="first writer", raw={},
        ))
        first.flush()

        started = ThreadEvent()
        flushed = ThreadEvent()
        errors: list[Exception] = []

        def second_writer() -> None:
            session = cases.get_session(case["id"])
            try:
                session.add(Event(
                    timestamp=None, host=None, source="second", category="test",
                    entity=None, severity="info", summary="second writer", raw={},
                ))
                started.set()
                session.flush()
                flushed.set()
                session.commit()
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)
            finally:
                session.close()

        worker = Thread(target=second_writer, daemon=True)
        worker.start()
        self.assertTrue(started.wait(1.0))
        self.assertFalse(flushed.wait(0.1), "second writer should wait for the first transaction")
        first.commit()
        first.close()
        self.assertTrue(flushed.wait(2.0))
        worker.join(timeout=2.0)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])

        session = cases.get_session(case["id"])
        try:
            self.assertEqual(session.query(Event).count(), 2)
        finally:
            session.close()

    def test_cleanup_orphan_case_dirs_removes_only_safe_orphans(self) -> None:
        registered = "a1b2c3d4"
        orphan = "deadbeef"
        unrelated = "not-a-case"
        registry = {"cases": {registered: {"id": registered, "name": "kept"}}}
        (self.root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
        (self.root / registered / "uploads").mkdir(parents=True)
        (self.root / orphan / "uploads").mkdir(parents=True)
        (self.root / unrelated).mkdir()

        result = cases.cleanup_orphan_case_dirs()

        self.assertEqual(result, [{"case_id": orphan, "status": "removed"}])
        self.assertTrue((self.root / registered).exists())
        self.assertFalse((self.root / orphan).exists())
        self.assertTrue((self.root / unrelated).exists())

    def test_cleanup_stale_case_artifacts_removes_unreferenced_derived_and_extracts(self) -> None:
        case = cases.create_case("stale artifacts")
        case_dir = self.root / case["id"]
        uploads = case_dir / "uploads"
        (uploads / "keep.raw").write_bytes(b"raw")
        (uploads / "archive.zip").write_bytes(b"zip")
        keep_derived = case_dir / "derived" / "memprocfs" / "keep"
        stale_derived = case_dir / "derived" / "memprocfs" / "gone"
        keep_extract = uploads / "archive_extracted"
        stale_extract = uploads / "old_extracted"
        keep_derived.mkdir(parents=True)
        stale_derived.mkdir(parents=True)
        keep_extract.mkdir()
        stale_extract.mkdir()

        removed = cases.cleanup_stale_case_artifacts()

        removed_kinds = {(row["kind"], Path(row["path"]).name) for row in removed}
        self.assertIn(("stale_memprocfs_derived", "gone"), removed_kinds)
        self.assertIn(("stale_zip_extract", "old_extracted"), removed_kinds)
        self.assertTrue(keep_derived.exists())
        self.assertTrue(keep_extract.exists())
        self.assertFalse(stale_derived.exists())
        self.assertFalse(stale_extract.exists())

    def test_memory_purge_removes_memprocfs_artifacts_and_sources(self) -> None:
        case = cases.create_case("memory cleanup")
        uploads = self.root / case["id"] / "uploads"
        dump = uploads / "sample.raw"
        dump.write_bytes(b"raw")
        derived = self.root / case["id"] / "derived" / "memprocfs" / "sample"
        derived.mkdir(parents=True)
        (derived / "manifest.json").write_text("{}", encoding="utf-8")

        session = cases.get_session(case["id"])
        try:
            cases.add_event(
                session,
                timestamp=None,
                host=None,
                source="mem-sample:forensic/csv/timeline_all.csv",
                category="process",
                entity="evil.exe",
                severity="info",
                summary="derived event",
                raw={},
            )
            cases.add_event(
                session,
                timestamp=None,
                host=None,
                source="memory:netscan",
                category="network",
                entity="evil.exe",
                severity="info",
                summary="legacy memory event",
                raw={},
            )
            session.add(Process(pid=123, ppid=None, name="evil.exe", session_id="mem-sample"))
            session.add(MemoryResult(plugin="diagnostics", summary="test", data={}, severity="low"))
            session.commit()
        finally:
            session.close()

        with (
            patch.object(cases, "get_case_stats", side_effect=AssertionError("stats read during purge")),
            patch.object(evidence, "compact_db") as compact,
        ):
            removed = evidence.purge_file_data(case["id"], dump)

        self.assertEqual(removed["events"], 2)
        self.assertEqual(removed["derived_artifacts"], 1)
        compact.assert_called_once()
        self.assertFalse(derived.exists())
        session = cases.get_session(case["id"])
        try:
            self.assertEqual(session.query(Event).count(), 0)
            self.assertEqual(session.query(Process).count(), 0)
            self.assertEqual(session.query(MemoryResult).count(), 0)
        finally:
            session.close()

    def test_yara_hits_are_attributed_to_process_regions_when_possible(self) -> None:
        case = cases.create_case("yara attribution")
        dump = self.root / case["id"] / "uploads" / "sample.raw"
        dump.write_bytes(b"raw memory")
        session = cases.get_session(case["id"])
        try:
            session.add(Process(
                pid=123,
                ppid=4,
                name="evil.exe",
                session_id="mem-sample",
                flags=[],
                severity="info",
            ))
            session.commit()

            class FakeScanner:
                def scan_bytes(self, data):
                    return [{
                        "rule": "RegionRule",
                        "tags": ["apt"],
                        "meta": {"severity": "high", "description": "region hit"},
                        "strings": ["$a"],
                    }] if data == b"evil-bytes" else []

                def scan_file(self, _path):
                    return [
                        {"rule": "RegionRule", "tags": ["apt"], "meta": {"severity": "high", "description": "region hit"}},
                        {"rule": "DumpOnlyRule", "tags": [], "meta": {"severity": "medium", "description": "dump hit"}},
                    ]

            results = {"malfind": [{
                "PID": 123,
                "Process": "evil.exe",
                "Start": "0x1000",
                "End": "0x1fff",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "BytesSample": b"evil-bytes",
            }]}
            stats = {"yara_hits": 0}
            with patch.object(memory_pipeline, "get_scanner", return_value=FakeScanner()):
                memory_pipeline._yara_scan_processes(
                    session, dump, "mem-sample", stats, lambda *_args: None, results
                )
            session.commit()

            rows = session.query(MemoryResult).filter_by(plugin="yara").all()
            by_rule = {row.data["rule"]: row for row in rows}
            proc = session.query(Process).filter_by(pid=123).one()

            self.assertEqual(stats["yara_hits"], 2)
            self.assertEqual(by_rule["RegionRule"].pid, 123)
            self.assertEqual(by_rule["RegionRule"].process_name, "evil.exe")
            self.assertEqual(by_rule["RegionRule"].data["attribution"]["type"], "process_memory_region")
            self.assertEqual(by_rule["DumpOnlyRule"].pid, None)
            self.assertEqual(by_rule["DumpOnlyRule"].data["attribution"]["type"], "raw_memory_dump")
            self.assertIn("yara-hit", proc.flags)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
