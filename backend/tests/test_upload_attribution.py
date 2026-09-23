from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select

import app.config as config
from app.ingest import evidence, pipeline
from app.memory import explorer, forensics
from app.memory.identity import memory_upload_key
from app.store import cases, database
from app.store.database import Event, Finding, MemoryResult, Process


class UploadAttributionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(config, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda cid: self.root / cid / "case.db"),
            patch.object(evidence, "case_uploads_path", side_effect=lambda cid: self.root / cid / "uploads"),
            patch.object(explorer, "case_uploads_path", side_effect=lambda cid: self.root / cid / "uploads"),
            patch("app.detect.engine.run_detections_sync"),
        ]
        for item in self.patches:
            item.start()
        self.case_id = cases.create_case("Synthetic attribution")["id"]
        self.uploads = self.root / self.case_id / "uploads"

    def tearDown(self):
        database.dispose_all_db_engines()
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def _archive(self, name: str, pid: int):
        path = self.uploads / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("results/processes.jsonl", json.dumps({
                "Timestamp": "2026-01-01T00:00:00Z", "Pid": pid, "Name": f"example-{pid}.exe",
            }) + "\n")
        pipeline.ingest_file_sync(self.case_id, path, lambda *_args: None)
        return path

    def _add_unrelated_finding(self) -> int:
        session = cases.get_session(self.case_id)
        try:
            finding = Finding(
                title="Unrelated validated finding",
                description="Must survive replacement failure",
                severity="high",
                source="unrelated",
                evidence={"entity": "unrelated"},
            )
            session.add(finding)
            session.commit()
            return finding.id
        finally:
            session.close()

    def _assert_finding_present(self, finding_id: int) -> None:
        session = cases.get_session(self.case_id)
        try:
            self.assertEqual(
                session.get(Finding, finding_id).title,
                "Unrelated validated finding",
            )
        finally:
            session.close()

    def test_overlapping_archive_sources_remain_independently_deletable(self):
        first = self._archive("first.zip", 101)
        self._archive("second.zip", 202)
        listed = {row["name"]: row for row in evidence.list_evidence(self.case_id)}
        self.assertEqual(listed["first.zip"]["event_count"], 1)
        self.assertEqual(listed["second.zip"]["event_count"], 1)
        evidence.prepare_reingest(self.case_id, first.name)
        pipeline.ingest_file_sync(self.case_id, first, lambda *_args: None)
        evidence.delete_evidence(self.case_id, first.name)
        session = cases.get_session(self.case_id)
        try:
            events = list(session.scalars(select(Event)))
            processes = list(session.scalars(select(Process)))
            self.assertEqual([(row.source, row.upload_name) for row in events], [("processes", "second.zip")])
            self.assertEqual([(row.pid, row.upload_name) for row in processes], [(202, "second.zip")])
            self.assertEqual(len(cases.search_events(session, "example")), 1)
        finally:
            session.close()

    def test_ambiguous_legacy_sources_refuse_mutation(self):
        first = self._archive("first.zip", 101)
        self._archive("second.zip", 202)
        session = cases.get_session(self.case_id)
        try:
            for event in session.scalars(select(Event)):
                event.upload_name = None
            session.commit()
        finally:
            session.close()
        with self.assertRaises(evidence.LegacyEvidenceAttributionError):
            evidence.delete_evidence(self.case_id, first.name)
        self.assertTrue(first.exists())
        with self.assertRaises(evidence.LegacyEvidenceAttributionError):
            evidence.validate_purge_attribution(self.case_id, first)

    def test_replacement_commit_failure_restores_file_and_database(self):
        destination = self.uploads / "same.json"
        staged = self.uploads / ".investigator-upload-replacement.part"
        destination.write_bytes(b"old")
        staged.write_bytes(b"new")
        session = cases.get_session(self.case_id)
        try:
            session.info["upload_name"] = "same.json"
            cases.add_event(session,
                source="same.json", upload_name="same.json", category="test",
                summary="preserved", raw={}, severity="info",
            )
            session.commit()
        finally:
            session.close()

        failing_session = cases.get_session(self.case_id)
        with (
            patch.object(evidence.case_store, "get_session", return_value=failing_session),
            patch.object(failing_session, "commit", side_effect=RuntimeError("commit failed")),
            self.assertRaisesRegex(RuntimeError, "commit failed"),
        ):
            evidence.replace_file_data(self.case_id, destination, staged)

        self.assertEqual(destination.read_bytes(), b"old")
        self.assertFalse(any(
            path.name.endswith(".previous") for path in self.uploads.iterdir()
        ))
        session = cases.get_session(self.case_id)
        try:
            self.assertEqual(session.query(Event).count(), 1)
            self.assertEqual(session.query(Event).one().summary, "preserved")
        finally:
            session.close()

    def test_replacement_rename_failure_restores_file_and_database(self):
        destination = self.uploads / "same.json"
        staged = self.uploads / ".investigator-upload-replacement.part"
        destination.write_bytes(b"old")
        staged.write_bytes(b"new")
        session = cases.get_session(self.case_id)
        try:
            session.info["upload_name"] = "same.json"
            cases.add_event(
                session,
                source="same.json",
                category="test",
                summary="preserved",
                raw={},
                severity="info",
            )
            session.commit()
        finally:
            session.close()

        real_replace = os.replace
        calls = 0

        def fail_new_generation(source, target):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("replacement rename failed")
            return real_replace(source, target)

        with (
            patch.object(evidence.os, "replace", side_effect=fail_new_generation),
            self.assertRaisesRegex(OSError, "replacement rename failed"),
        ):
            evidence.replace_file_data(self.case_id, destination, staged)

        self.assertEqual(destination.read_bytes(), b"old")
        session = cases.get_session(self.case_id)
        try:
            self.assertEqual(session.query(Event).count(), 1)
            self.assertEqual(session.query(Event).one().summary, "preserved")
        finally:
            session.close()

    def test_artifact_parse_failure_rebuilds_without_dropping_unrelated_finding(self):
        finding_id = self._add_unrelated_finding()
        manager = pipeline.IngestionManager()
        manager.require_detection_rebuild(self.case_id, full=True)
        with (
            patch.object(pipeline, "ingest_file_sync", side_effect=RuntimeError("parse failed")),
            patch("app.detect.engine.run_detections_sync", return_value=0) as rebuild,
            patch.object(pipeline.case_store, "update_case_meta"),
            patch.object(pipeline.traceback, "print_exc"),
        ):
            asyncio.run(manager._run_ingestion_locked(
                self.case_id,
                self.uploads / "replacement.json",
                "artifact",
            ))
        rebuild.assert_called_once_with(self.case_id, rebuild=True)
        self._assert_finding_present(finding_id)
        self.assertNotIn(self.case_id, manager._full_rebuild_pending)

    def test_memory_analysis_failure_rebuilds_without_dropping_unrelated_finding(self):
        finding_id = self._add_unrelated_finding()
        manager = pipeline.IngestionManager()
        manager.require_detection_rebuild(self.case_id, full=True)
        with (
            patch(
                "app.memory.pipeline.analyze_memory_dump_sync",
                side_effect=RuntimeError("memory analysis failed"),
            ),
            patch("app.detect.engine.run_detections_sync", return_value=0) as rebuild,
            patch.object(pipeline.case_store, "update_case_meta"),
            patch.object(pipeline.traceback, "print_exc"),
        ):
            asyncio.run(manager._run_ingestion_locked(
                self.case_id,
                self.uploads / "replacement.raw",
                "memory",
            ))
        rebuild.assert_called_once_with(self.case_id, rebuild=True)
        self._assert_finding_present(finding_id)
        self.assertNotIn(self.case_id, manager._full_rebuild_pending)

    def test_detection_failure_retries_full_rebuild_and_preserves_prior_results(self):
        finding_id = self._add_unrelated_finding()
        manager = pipeline.IngestionManager()
        manager.require_detection_rebuild(self.case_id, full=True)
        with (
            patch.object(
                pipeline,
                "ingest_file_sync",
                return_value={"events": 1, "processes": 0, "files": 1},
            ),
            patch(
                "app.detect.engine.run_detections_sync",
                side_effect=[RuntimeError("detection failed"), 0],
            ) as rebuild,
            patch.object(pipeline.case_store, "update_case_meta"),
            patch.object(pipeline.traceback, "print_exc"),
        ):
            asyncio.run(manager._run_ingestion_locked(
                self.case_id,
                self.uploads / "replacement.json",
                "artifact",
            ))
        self.assertEqual(rebuild.call_count, 2)
        for call in rebuild.call_args_list:
            self.assertEqual(call.args, (self.case_id,))
            self.assertEqual(call.kwargs, {"rebuild": True})
        self._assert_finding_present(finding_id)
        self.assertNotIn(self.case_id, manager._full_rebuild_pending)

    def test_same_stem_memory_uploads_resolve_and_purge_independently(self):
        names = ("capture.raw", "capture.dmp")
        session = cases.get_session(self.case_id)
        try:
            for name in names:
                (self.uploads / name).write_bytes(b"synthetic")
                session.info["upload_name"] = name
                cases.add_event(session, timestamp=None, source="memory:test", category="memory", summary=name, raw={})
                session.add(Process(pid=100, name="example.exe", session_id=f"mem-{memory_upload_key(name)}", upload_name=name))
                session.add(MemoryResult(plugin="test", pid=100, summary=name, upload_name=name))
                artifact_dir = forensics.memprocfs_artifact_dir(self.case_id, memory_upload_key(name))
                artifact_dir.mkdir(parents=True)
                (artifact_dir / "synthetic.txt").write_text(name)
            session.commit()
        finally:
            session.close()
        dumps = explorer.list_memory_dumps(self.case_id)
        self.assertEqual(len({item["session_id"] for item in dumps}), 2)
        for item in dumps:
            self.assertEqual(explorer.resolve_memory_dump(self.case_id, item["session_id"]).filename, item["filename"])
        with self.assertRaises(explorer.MemoryExplorerError) as caught:
            explorer.resolve_memory_dump(self.case_id, "mem-capture")
        self.assertEqual(caught.exception.status_code, 409)
        evidence.delete_evidence(self.case_id, names[0])
        session = cases.get_session(self.case_id)
        try:
            for model in (Event, Process, MemoryResult):
                self.assertEqual([row.upload_name for row in session.scalars(select(model))], [names[1]])
        finally:
            session.close()
        self.assertTrue(cases.get_case(self.case_id)["has_memory_dump"])
        self.assertTrue(forensics.memprocfs_artifact_dir(self.case_id, memory_upload_key(names[1])).exists())

    def test_forensic_ingestion_uses_trusted_upload_identity(self):
        session = cases.get_session(self.case_id)
        try:
            session.info["upload_name"] = "capture.raw"
            artifact_dir = self.root / "synthetic-artifacts"
            csv_dir = artifact_dir / "forensic" / "csv"
            csv_dir.mkdir(parents=True)
            (csv_dir / "process.csv").write_text("PID,PPID,Name\n100,4,example.exe\n")
            (csv_dir / "findevil.csv").write_text("PID,Process,Reason\n100,example.exe,synthetic\n")
            result = forensics.ingest_memprocfs_artifacts_sync(
                session, memory_upload_key("capture.raw"), artifact_dir, None, lambda *_args: None,
            )
            self.assertEqual(result["events"], 2)
            self.assertEqual(result["processes"], 1)
            self.assertEqual(result["memory_results"], 1)
            for model in (Event, Process, MemoryResult):
                rows = list(session.scalars(select(model)))
                self.assertTrue(rows)
                self.assertTrue(all(row.upload_name == "capture.raw" for row in rows))
        finally:
            session.close()

    def test_legacy_schema_migration_preserves_rows_and_adds_nullable_identity(self):
        path = self.root / self.case_id / "case.db"
        database.dispose_db(path)
        connection = sqlite3.connect(path)
        try:
            for table in ("events", "processes", "memory_results"):
                connection.execute(f"DROP INDEX ix_{table}_upload_name")
                connection.execute(f"ALTER TABLE {table} DROP COLUMN upload_name")
            connection.execute("INSERT INTO events(source,category,summary,raw,severity) VALUES ('legacy','test','preserved','{}','info')")
            connection.commit()
        finally:
            connection.close()
        session = cases.get_session(self.case_id)
        try:
            row = session.scalars(select(Event)).one()
            self.assertEqual(row.summary, "preserved")
            self.assertIsNone(row.upload_name)
        finally:
            session.close()
