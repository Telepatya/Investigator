from __future__ import annotations

# ruff: noqa: E402
#
# End-to-end: Microsoft Defender Advanced Hunting exports (DeviceFileEvents +
# DeviceProcessEvents + DeviceNetworkEvents) are ingested through the real
# pipeline and the existing correlation engine reconstructs the download chain
# URL -> downloaded file -> executed process -> network connection. Because
# Defender data is multi-device, the correlation is host-scoped: a download on
# one device must not link to a same-named execution on another.

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
from app.detect import entity_graph
from app.detect.engine import run_detections_sync
from app.ingest.pipeline import ingest_file_sync
from app.store import cases
from app.store import database
from app.store.database import Finding


def _noop(*_a, **_k) -> None:
    return None


class DefenderDownloadChainTests(unittest.TestCase):
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

    def _ingest_all(self, case_id: str, files: list[Path]) -> None:
        for f in files:
            ingest_file_sync(case_id, f, _noop)
        run_detections_sync(case_id)

    def test_reconstructs_url_file_process_network_chain(self) -> None:
        path = "C:\\Users\\v\\Downloads\\payload.exe"
        files = [
            self._write("DeviceFileEvents.json", [{
                "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
                "ActionType": "FileCreated", "FileName": "payload.exe",
                "FolderPath": path, "SHA256": "abc123",
                "FileOriginUrl": "https://evil.example/payload.exe",
                "FileOriginReferrerUrl": "https://evil.example/",
                "InitiatingProcessFileName": "chrome.exe",
            }]),
            self._write("DeviceProcessEvents.json", [{
                "Timestamp": "2026-07-06T10:02:00Z", "DeviceName": "WKS-01",
                "ActionType": "ProcessCreated", "FileName": "payload.exe",
                "FolderPath": path, "ProcessId": 4242,
                "ProcessCommandLine": "payload.exe -run", "AccountName": "v",
                "InitiatingProcessId": 900, "InitiatingProcessFileName": "explorer.exe",
                "InitiatingProcessFolderPath": "C:\\Windows\\explorer.exe",
            }]),
            self._write("DeviceNetworkEvents.json", [{
                "Timestamp": "2026-07-06T10:03:00Z", "DeviceName": "WKS-01",
                "ActionType": "ConnectionSuccess", "RemoteIP": "203.0.113.5",
                "RemotePort": 443, "Protocol": "Tcp", "RemoteUrl": "evil-c2.example",
                "InitiatingProcessFileName": "payload.exe",
                "InitiatingProcessFolderPath": path, "InitiatingProcessId": 4242,
            }]),
        ]
        case = cases.create_case("chain")
        self._ingest_all(case["id"], files)

        s = cases.get_session(case["id"])
        try:
            titles = [f.title for f in s.scalars(select(Finding))]
        finally:
            s.close()
        self.assertTrue(
            any("File artifact later executed: payload.exe" in t for t in titles),
            f"missing download->execution finding; titles={titles}",
        )

        graph = entity_graph.build_entity_graph(case["id"])
        node_ids = {n["id"] for n in graph["nodes"]}
        edges = {(e["source"], e["verb"], e["target"]) for e in graph["edges"]}

        # URL -> downloaded file -> executed process
        self.assertTrue(
            any(src.startswith("url::") and dst == "file::payload.exe"
                for src, _v, dst in edges),
            f"missing url->file edge; edges={edges}",
        )
        self.assertTrue(
            any(src == "file::payload.exe" and dst == "process::payload.exe"
                for src, _v, dst in edges),
            f"missing file->process edge; edges={edges}",
        )
        # the outbound network connection surfaces the C2 IP, connected to the
        # process that made it (not only to the device)
        self.assertIn("ip::203.0.113.5", node_ids, f"missing C2 ip node; nodes={node_ids}")
        self.assertTrue(
            any(src == "process::payload.exe" and dst == "ip::203.0.113.5"
                for src, _v, dst in edges),
            f"missing process->ip edge; edges={edges}",
        )

    def test_download_and_execution_on_different_hosts_do_not_chain(self) -> None:
        # Same-named file downloaded on WKS-A but executed on WKS-B: host-scoping
        # must prevent a false cross-device download->execution chain.
        dl_path = "C:\\Users\\v\\Downloads\\payload.exe"
        exec_path = "C:\\Users\\other\\payload.exe"
        files = [
            self._write("DeviceFileEvents.json", [{
                "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-A",
                "ActionType": "FileCreated", "FileName": "payload.exe",
                "FolderPath": dl_path, "SHA256": "abc123",
                "FileOriginUrl": "https://evil.example/payload.exe",
                "InitiatingProcessFileName": "chrome.exe",
            }]),
            self._write("DeviceProcessEvents.json", [{
                "Timestamp": "2026-07-06T10:02:00Z", "DeviceName": "WKS-B",
                "ActionType": "ProcessCreated", "FileName": "payload.exe",
                "FolderPath": exec_path, "ProcessId": 4242,
                "ProcessCommandLine": "payload.exe -run", "AccountName": "other",
                "InitiatingProcessId": 900, "InitiatingProcessFileName": "explorer.exe",
            }]),
        ]
        case = cases.create_case("crosshost")
        self._ingest_all(case["id"], files)

        s = cases.get_session(case["id"])
        try:
            titles = [f.title for f in s.scalars(select(Finding))]
        finally:
            s.close()
        self.assertFalse(
            any("File artifact later executed" in t for t in titles),
            f"cross-host download/execution should NOT chain; titles={titles}",
        )


if __name__ == "__main__":
    unittest.main()
