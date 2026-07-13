from __future__ import annotations

# ruff: noqa: E402
#
# The download->execution provenance correlation must surface in the entity map
# as explicit nodes/edges: the downloaded file (and its origin URL when known)
# linked to the process that later ran it -- not just a finding on the process.

import json
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

from app.detect import entity_graph
from app.detect.engine import run_detections_sync
from app.llm.tools import list_downloads
from app.store import cases
from app.store import database
from app.store.database import Finding, Process


class DownloadCorrelationTests(unittest.TestCase):
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

    def test_download_execution_shows_file_url_and_edges(self) -> None:
        case = cases.create_case("dl")
        s = cases.get_session(case["id"])
        t0 = datetime(2026, 7, 6, 10, 0, 0, tzinfo=timezone.utc)
        dlpath = "C:\\Users\\v\\Downloads\\velociraptor.exe"
        try:
            cases.add_event(
                s, timestamp=t0, host="H",
                source="Windows.Detection.EvidenceOfDownload", category="filesystem",
                entity=dlpath, severity="info", summary=f"Downloaded {dlpath}",
                raw={
                    "DownloadedFilePath": dlpath,
                    "_ZoneIdentifierContent": (
                        "[ZoneTransfer]\nZoneId=3\n"
                        "HostUrl=https://dl.chrome-download.example/velociraptor.exe"
                    ),
                },
            )
            s.add(Process(
                pid=555, ppid=None, name="velociraptor.exe", path=dlpath,
                cmdline="velociraptor.exe gui", session_id="live",
                flags=["icacls"], severity="low", start_time=t0 + timedelta(minutes=5),
            ))
            s.commit()
        finally:
            s.close()

        run_detections_sync(case["id"])
        graph = entity_graph.build_entity_graph(case["id"])

        types_present = {n["type"] for n in graph["nodes"]}
        self.assertIn("file", types_present)
        self.assertIn("url", types_present)

        edges = {(e["source"], e["verb"], e["target"]) for e in graph["edges"]}
        # downloaded file linked to the process that ran it
        self.assertTrue(
            any(src == "file::velociraptor.exe" and dst == "process::velociraptor.exe"
                for src, _verb, dst in edges),
            f"missing download->execution edge; edges={edges}",
        )
        # origin URL linked to the downloaded file
        self.assertTrue(
            any(src.startswith("url::") and dst == "file::velociraptor.exe"
                for src, _verb, dst in edges),
            f"missing url->file edge; edges={edges}",
        )
        # the process node is the flagged one (finding attached to the same node)
        proc = next(n for n in graph["nodes"] if n["id"] == "process::velociraptor.exe")
        self.assertTrue(any("later executed" in f["title"] for f in proc["findings"]))

    def test_list_downloads_returns_file_url_and_event_id(self) -> None:
        case = cases.create_case("download inventory")
        session = cases.get_session(case["id"])
        try:
            event = cases.add_event(
                session, timestamp=None, host="H",
                source="Windows.Analysis.EvidenceOfDownload.json",
                category="filesystem", entity=r"C:\Downloads\payload.exe",
                severity="info", summary="Downloaded payload.exe",
                raw={
                    "FullPath": r"C:\Downloads\payload.exe",
                    "Url": "https://downloads.example/payload.exe",
                },
            )
            session.commit()

            result = json.loads(list_downloads(session, {"limit": 200}))
        finally:
            session.close()

        self.assertEqual(result["total_count"], 1)
        self.assertEqual(result["downloads"][0]["event_id"], event.id)
        self.assertEqual(
            result["downloads"][0]["url"],
            "https://downloads.example/payload.exe",
        )

    def test_list_downloads_includes_finding_provenance_and_prioritizes_binary(self) -> None:
        case = cases.create_case("finding download inventory")
        session = cases.get_session(case["id"])
        binary = r"\\.\C:\Users\analyst\Downloads\Collector_velociraptor.exe"
        internal_url = (
            "https://127.0.0.1:8889/api/v1/DownloadVFSFile?"
            "fs_components=Collector_velociraptor.exe"
        )
        try:
            # A web asset would sort first alphabetically, but notable binaries
            # must be prioritized before high-volume browser artifacts.
            cases.add_event(
                session, timestamp=None, host="H",
                source="Windows.Analysis.EvidenceOfDownload.json",
                category="filesystem", entity="a.js", severity="info",
                summary="Downloaded web asset",
                raw={"FullPath": "a.js", "Url": "https://static.example/a.js"},
            )
            finding = Finding(
                title="File artifact later executed: Collector_velociraptor.exe",
                description="download then execution", severity="medium",
                mitre_techniques=["T1105"], source="correlation",
                evidence={
                    "artifact_kind": "download",
                    "artifact_path": binary,
                    "artifact_event_id": 9,
                    "origin_url": internal_url,
                },
            )
            session.add(finding)
            session.commit()

            result = json.loads(list_downloads(session, {"limit": 1}))
        finally:
            session.close()

        self.assertEqual(result["returned_count"], 1)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["downloads"][0]["path"], binary)
        self.assertEqual(result["downloads"][0]["finding_id"], finding.id)
        self.assertEqual(result["downloads"][0]["url"], internal_url)

    def test_velociraptor_evidenceofdownload_fields(self) -> None:
        # Velociraptor Windows.Detection.EvidenceOfDownload emits FullPath + URL /
        # Referrer columns (no DownloadedFilePath, no Zone.Identifier blob). This
        # shape must be recognized as a download and correlate to the execution.
        case = cases.create_case("velo")
        s = cases.get_session(case["id"])
        t0 = datetime(2026, 7, 6, 10, 0, 0, tzinfo=timezone.utc)
        path = "C:\\Users\\v\\Downloads\\rclone.exe"
        try:
            cases.add_event(
                s, timestamp=t0, host="H",
                source="Windows.Detection.EvidenceOfDownload", category="filesystem",
                entity=path, severity="info", summary="evidence of download",
                raw={"FullPath": path, "URL": "https://cdn.evil.example/rclone.exe",
                     "Referrer": "https://mail.google.com/"},
            )
            s.add(Process(
                pid=606, ppid=None, name="rclone.exe", path=path, cmdline="rclone.exe",
                session_id="live", flags=[], severity="low", start_time=t0 + timedelta(minutes=6),
            ))
            s.commit()
        finally:
            s.close()

        run_detections_sync(case["id"])
        graph = entity_graph.build_entity_graph(case["id"])
        types_present = {n["type"] for n in graph["nodes"]}
        self.assertIn("file", types_present)
        self.assertIn("url", types_present)
        edges = {(e["source"], e["target"]) for e in graph["edges"]}
        self.assertIn(("file::rclone.exe", "process::rclone.exe"), edges)
        self.assertTrue(any(s_.startswith("url::") and d == "file::rclone.exe" for s_, d in edges))

    def test_download_correlates_with_velociraptor_startup_argv_event(self) -> None:
        # The live Velociraptor Application log records startup as EventID 1000
        # "Velociraptor startup ARGV", not as Sysmon 1 / Security 4688. That is
        # still execution evidence for download provenance.
        case = cases.create_case("velo-argv")
        s = cases.get_session(case["id"])
        t0 = datetime(2026, 7, 4, 17, 22, 28, tzinfo=timezone.utc)
        name = "velociraptor-v0.77.1-windows-amd64.exe"
        dlpath = f"\\\\.\\C:\\Users\\analyst\\Downloads\\{name}"
        runpath = f"C:\\Users\\analyst\\Desktop\\velociraptor\\{name}"
        try:
            cases.add_event(
                s, timestamp=t0, host="Atlas",
                source="Windows.Analysis.EvidenceOfDownload.json",
                category="artifact", entity=None, severity="info",
                summary=f"DownloadedFilePath={dlpath}",
                raw={
                    "DownloadedFilePath": dlpath,
                    "_ZoneIdentifierContent": (
                        "[ZoneTransfer]\r\nZoneId=3\r\n"
                        "ReferrerUrl=https://docs.velociraptor.app/\r\n"
                        f"HostUrl=https://release-assets.githubusercontent.com/{name}\r\n"
                    ),
                },
            )
            cases.add_event(
                s, timestamp=t0 + timedelta(seconds=46), host="Atlas",
                source="Windows.EventLogs.Evtx.json", category="eventlog",
                entity="EventID 1000 (Application)", severity="info",
                summary=f'Velociraptor startup ARGV: ["{runpath}"]',
                raw={
                    "EventID": 1000,
                    "Channel": "Application",
                    "Provider": "Velociraptor",
                    "Message": f'Velociraptor startup ARGV: ["{runpath}"]',
                    "Data": [f'Velociraptor startup ARGV: ["{runpath}"]\n'],
                },
            )
            s.commit()
        finally:
            s.close()

        run_detections_sync(case["id"])
        graph = entity_graph.build_entity_graph(case["id"])

        edges = {(e["source"], e["target"]) for e in graph["edges"]}
        self.assertIn((f"file::{name}", f"process::{name}"), edges)
        self.assertTrue(any(s_.startswith("url::") and d == f"file::{name}" for s_, d in edges))


if __name__ == "__main__":
    unittest.main()
