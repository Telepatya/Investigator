from __future__ import annotations

# ruff: noqa: E402
#
# Download->execution provenance using the NTFS $UsnJrnl:$J journal:
#   - follow a downloaded file across a rename (same FileReferenceNumber) to the
#     name/path it was executed under, and
#   - flag the file being deleted after execution (cleanup / anti-forensics).

import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
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
from app.detect import entity_graph
from app.detect import engine
from app.detect.engine import run_detections_sync
from app.store import cases
from app.store import database
from app.store.database import Finding, Process


def _edges(graph):
    return {(e["source"], e["verb"], e["target"]) for e in graph["edges"]}


class UsnProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda cid: self.root / cid / "case.db"),
        ]
        for p in self.patches:
            p.start()
        self.t0 = datetime(2026, 7, 6, 9, 0, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        database.dispose_all_db_engines()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _download(self, s, path, ts):
        cases.add_event(
            s, timestamp=ts, host="H", source="Windows.Detection.EvidenceOfDownload",
            category="filesystem", entity=path, severity="info", summary=f"Downloaded {path}",
            raw={"DownloadedFilePath": path,
                 "_ZoneIdentifierContent": "[ZoneTransfer]\nZoneId=3\nHostUrl=https://cdn.example/pkg"},
        )

    def _usn(self, s, path, tokens, frn, ts):
        cases.add_event(
            s, timestamp=ts, host="H", source="Windows.Forensics.Usn", category="filesystem",
            entity=path, severity="info", summary=f"$J {tokens} {path}",
            raw={"usn_journal": True, "UsnReasonTokens": tokens, "UsnPath": path,
                 "UsnFileReference": frn},
        )

    def _fake_event(self, event_id: int, ts: datetime):
        return types.SimpleNamespace(id=event_id, timestamp=ts)

    def _artifact(self, path: str, event_id: int, ts: datetime) -> dict:
        return {
            "event": self._fake_event(event_id, ts),
            "path": path,
            "base": engine._basename(path),
            "kind": "download",
            "origin": None,
        }

    def _delete(self, path: str, event_id: int, ts: datetime, frn: str = "") -> dict:
        return {
            "path": path,
            "base": engine._basename(path),
            "frn": frn,
            "timestamp": ts,
            "event": self._fake_event(event_id, ts),
        }

    def _rename(self, old_path: str, new_path: str, event_id: int, ts: datetime, frn: str = "") -> dict:
        return {
            "old_path": old_path,
            "old_base": engine._basename(old_path),
            "new_path": new_path,
            "new_base": engine._basename(new_path),
            "frn": frn,
            "timestamp": ts,
            "event": self._fake_event(event_id, ts),
        }

    def test_lifecycle_indexes_skip_irrelevant_delete_volume(self) -> None:
        artifacts = [
            self._artifact(f"C:\\Users\\v\\Downloads\\app{i}.exe", i, self.t0)
            for i in range(100)
        ]
        deletes = [
            self._delete(f"C:\\Users\\v\\Temp\\noise{i}.exe", 1000 + i, self.t0 + timedelta(minutes=20))
            for i in range(1000)
        ]
        deletes.append(
            self._delete(
                "C:\\Users\\v\\Downloads\\app42.exe",
                3000,
                self.t0 + timedelta(minutes=30),
            )
        )

        with patch.object(engine, "_candidate_matches_delete", wraps=engine._candidate_matches_delete) as wrapped:
            candidates = engine._artifact_lifecycles(artifacts, [], deletes)

        by_base = {c["base"]: c for c in candidates}
        self.assertEqual([d["path"] for d in by_base["app42.exe"]["deletes"]], ["C:\\Users\\v\\Downloads\\app42.exe"])
        self.assertEqual(sum(len(c["deletes"]) for c in candidates), 1)
        self.assertLess(wrapped.call_count, 200)

    def test_lifecycle_indexes_skip_irrelevant_rename_volume(self) -> None:
        artifacts = [
            self._artifact(f"C:\\Users\\v\\Downloads\\pkg{i}.exe", i, self.t0)
            for i in range(100)
        ]
        renames = [
            self._rename(
                f"C:\\Users\\v\\Temp\\noise{i}.exe",
                f"C:\\Users\\v\\Temp\\noise{i}.tmp",
                1000 + i,
                self.t0 + timedelta(minutes=2),
            )
            for i in range(1000)
        ]
        renames.append(
            self._rename(
                "C:\\Users\\v\\Downloads\\pkg17.exe",
                "C:\\Users\\v\\AppData\\Local\\Temp\\payload.exe",
                3000,
                self.t0 + timedelta(minutes=3),
                "500:1",
            )
        )

        with patch.object(engine, "_candidate_matches_rename", wraps=engine._candidate_matches_rename) as wrapped:
            candidates = engine._artifact_lifecycles(artifacts, renames, [])

        by_base = {c["base"]: c for c in candidates}
        self.assertEqual(by_base["pkg17.exe"]["segments"][-1]["base"], "payload.exe")
        self.assertEqual(by_base["pkg17.exe"]["frn"], "500:1")
        self.assertEqual(sum(len(c["renames"]) for c in candidates), 1)
        self.assertLess(wrapped.call_count, 200)

    def test_lifecycle_basename_delete_fallback_keeps_generic_names_out(self) -> None:
        artifacts = [
            self._artifact("C:\\Users\\v\\Downloads\\tool.exe", 1, self.t0),
            self._artifact("C:\\Users\\v\\Downloads\\setup.exe", 2, self.t0),
        ]
        deletes = [
            self._delete("D:\\Other\\tool.exe", 3, self.t0 + timedelta(minutes=15)),
            self._delete("D:\\Other\\setup.exe", 4, self.t0 + timedelta(minutes=15)),
        ]

        candidates = engine._artifact_lifecycles(artifacts, [], deletes)
        by_base = {c["base"]: c for c in candidates}

        self.assertEqual([d["path"] for d in by_base["tool.exe"]["deletes"]], ["D:\\Other\\tool.exe"])
        self.assertEqual(by_base["setup.exe"]["deletes"], [])

    def test_download_renamed_then_executed(self) -> None:
        case = cases.create_case("rename")
        s = cases.get_session(case["id"])
        dl = "C:\\Users\\v\\Downloads\\update_pkg.exe"
        new = "C:\\Users\\v\\AppData\\Local\\Temp\\payload.exe"
        try:
            self._download(s, dl, self.t0)
            self._usn(s, dl, ["RENAME_OLD_NAME"], "100:1", self.t0 + timedelta(minutes=2))
            self._usn(s, new, ["RENAME_NEW_NAME"], "100:1", self.t0 + timedelta(minutes=2))
            s.add(Process(pid=71, ppid=None, name="payload.exe", path=new,
                          cmdline="payload.exe", session_id="live", flags=[], severity="low",
                          start_time=self.t0 + timedelta(minutes=10)))
            s.commit()
        finally:
            s.close()

        run_detections_sync(case["id"])
        s = cases.get_session(case["id"])
        try:
            f = [f for f in s.scalars(select(Finding))
                 if f.title.startswith("File artifact later executed")]
            self.assertTrue(f, "no download->execution finding")
            fin = f[0]
            self.assertIn("(renamed)", fin.title)
            self.assertEqual(fin.evidence["match_confidence"], "usn-rename-chain")
            self.assertEqual(fin.evidence["renamed_to"], new)
        finally:
            s.close()

        edges = _edges(entity_graph.build_entity_graph(case["id"]))
        self.assertTrue(any(s_ == "file::update_pkg.exe" and v == "renamed to" and d == "file::payload.exe"
                            for s_, v, d in edges), edges)
        self.assertTrue(any(s_ == "file::payload.exe" and d == "process::payload.exe"
                            for s_, v, d in edges), edges)

    def test_download_multi_rename_chain_then_executed(self) -> None:
        case = cases.create_case("multirename")
        s = cases.get_session(case["id"])
        dl = "C:\\Users\\v\\Downloads\\stage1.exe"
        mid = "C:\\Users\\v\\AppData\\Local\\Temp\\stage2.exe"
        final = "C:\\Users\\v\\AppData\\Local\\Temp\\payload.exe"
        try:
            self._download(s, dl, self.t0)
            self._usn(s, dl, ["RENAME_OLD_NAME"], "900:1", self.t0 + timedelta(minutes=2))
            self._usn(s, mid, ["RENAME_NEW_NAME"], "900:1", self.t0 + timedelta(minutes=2))
            self._usn(s, mid, ["RENAME_OLD_NAME"], "900:1", self.t0 + timedelta(minutes=3))
            self._usn(s, final, ["RENAME_NEW_NAME"], "900:1", self.t0 + timedelta(minutes=3))
            s.add(Process(pid=72, ppid=None, name="payload.exe", path=final,
                          cmdline="payload.exe", session_id="live", flags=[], severity="low",
                          start_time=self.t0 + timedelta(minutes=8)))
            s.commit()
        finally:
            s.close()

        run_detections_sync(case["id"])
        s = cases.get_session(case["id"])
        try:
            fins = [
                f for f in s.scalars(select(Finding))
                if f.title.startswith("File artifact later executed")
                and f.evidence.get("artifact_path") == dl
            ]
            self.assertTrue(fins, "no download lifecycle finding")
            fin = fins[0]
            self.assertEqual(fin.evidence["match_confidence"], "usn-rename-chain")
            self.assertEqual(fin.evidence["renamed_from"], dl)
            self.assertEqual(fin.evidence["renamed_to"], final)
            self.assertEqual(len(fin.evidence["rename_chain"]), 2)
        finally:
            s.close()

        edges = _edges(entity_graph.build_entity_graph(case["id"]))
        self.assertIn(("file::stage1.exe", "renamed to", "file::stage2.exe"), edges)
        self.assertIn(("file::stage2.exe", "renamed to", "file::payload.exe"), edges)
        self.assertTrue(any(s_ == "file::payload.exe" and d == "process::payload.exe"
                            for s_, v, d in edges), edges)

    def test_download_without_execution_stays_context_only(self) -> None:
        case = cases.create_case("noexec")
        s = cases.get_session(case["id"])
        dl = "C:\\Users\\v\\Downloads\\never_run.exe"
        renamed = "C:\\Users\\v\\Downloads\\never_run_renamed.exe"
        try:
            self._download(s, dl, self.t0)
            self._usn(s, dl, ["RENAME_OLD_NAME"], "901:1", self.t0 + timedelta(minutes=2))
            self._usn(s, renamed, ["RENAME_NEW_NAME"], "901:1", self.t0 + timedelta(minutes=2))
            s.commit()
        finally:
            s.close()

        run_detections_sync(case["id"])
        s = cases.get_session(case["id"])
        try:
            fins = [
                f for f in s.scalars(select(Finding))
                if f.title.startswith("File artifact later executed")
            ]
            self.assertEqual(fins, [])
        finally:
            s.close()

        graph = entity_graph.build_entity_graph(case["id"])
        self.assertFalse(any(n["type"] == "file" and "never_run" in n["value"] for n in graph["nodes"]))

    def test_download_executed_then_deleted(self) -> None:
        case = cases.create_case("delete")
        s = cases.get_session(case["id"])
        exe = "C:\\Users\\v\\AppData\\Local\\Temp\\dropper.exe"
        try:
            self._download(s, exe, self.t0)
            s.add(Process(pid=88, ppid=None, name="dropper.exe", path=exe,
                          cmdline="dropper.exe", session_id="live", flags=[], severity="low",
                          start_time=self.t0 + timedelta(minutes=5)))
            self._usn(s, exe, ["FILE_DELETE"], "200:1", self.t0 + timedelta(minutes=20))
            s.commit()
        finally:
            s.close()

        run_detections_sync(case["id"])
        s = cases.get_session(case["id"])
        try:
            fin = [f for f in s.scalars(select(Finding))
                   if f.title.startswith("File artifact later executed")][0]
            self.assertIn("then deleted", fin.title)
            self.assertTrue(fin.evidence["deleted_after_execution"])
        finally:
            s.close()

        edges = _edges(entity_graph.build_entity_graph(case["id"]))
        self.assertTrue(any(s_ == "process::dropper.exe" and v == "then deleted"
                            for s_, v, d in edges), edges)

    def test_delete_before_execution_not_flagged(self) -> None:
        # A delete that predates the execution must not be reported as cleanup.
        case = cases.create_case("predelete")
        s = cases.get_session(case["id"])
        exe = "C:\\Users\\v\\AppData\\Local\\Temp\\tool.exe"
        try:
            self._download(s, exe, self.t0)
            self._usn(s, exe, ["FILE_DELETE"], "300:1", self.t0 + timedelta(minutes=1))
            s.add(Process(pid=99, ppid=None, name="tool.exe", path=exe,
                          cmdline="tool.exe", session_id="live", flags=[], severity="low",
                          start_time=self.t0 + timedelta(minutes=10)))
            s.commit()
        finally:
            s.close()

        run_detections_sync(case["id"])
        s = cases.get_session(case["id"])
        try:
            fins = [f for f in s.scalars(select(Finding))
                    if f.title.startswith("File artifact later executed")]
            # correlation still fires (exact path), but not marked deleted-after
            self.assertTrue(fins)
            self.assertFalse(fins[0].evidence["deleted_after_execution"])
            self.assertNotIn("then deleted", fins[0].title)
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
