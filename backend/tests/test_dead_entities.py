from __future__ import annotations

# ruff: noqa: E402
#
# Dead process / service support: log-derived process-exit events mark the
# process terminated, detections still run on terminated processes, and the
# entity graph surfaces meta.dead / meta.flags (and service state) so the
# entity-map "show terminated" toggle and badge have data to act on.

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
from app.ingest.pipeline import _apply_evtx_exits, _evtx_process_exit, ingest_file_sync
from app.store import cases
from app.store import database
from app.store.database import Finding, Process

_SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _noop(*_a, **_k) -> None:
    return None


class DeadEntityTests(unittest.TestCase):
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

    def test_evtx_process_exit_detection(self) -> None:
        self.assertEqual(
            _evtx_process_exit({"EventID": "5", "Channel": _SYSMON, "ProcessId": "1234"}), 1234
        )
        self.assertEqual(
            _evtx_process_exit({
                "EventID": "4689", "Channel": "Security", "ProcessId": "0x4d2"
            }), 1234
        )
        # not an exit event
        self.assertIsNone(_evtx_process_exit({"EventID": "1", "Channel": _SYSMON, "ProcessId": "1"}))
        self.assertIsNone(_evtx_process_exit({"EventID": "5", "Channel": "Application"}))

    def test_apply_exits_only_matching_session(self) -> None:
        case = cases.create_case("exits")
        s = cases.get_session(case["id"])
        try:
            s.add(Process(pid=1234, ppid=None, name="evil.exe", session_id="evtx-a", flags=[]))
            s.add(Process(pid=1234, ppid=None, name="evil.exe", session_id="evtx-b", flags=[]))
            s.commit()
            marked = _apply_evtx_exits(s, {("evtx-a", 1234): "2021-01-01T00:00:00+00:00"})
            s.commit()
            self.assertEqual(marked, 1)
            a = s.scalars(select(Process).where(Process.session_id == "evtx-a")).one()
            b = s.scalars(select(Process).where(Process.session_id == "evtx-b")).one()
            self.assertIn("terminated", a.flags)
            self.assertEqual(a.extra.get("exit_time"), "2021-01-01T00:00:00+00:00")
            self.assertNotIn("terminated", b.flags)
        finally:
            s.close()

    def test_ingest_marks_terminated_and_detects(self) -> None:
        rows = [
            {
                "EventID": "1", "Channel": _SYSMON, "Image": "C:\\Users\\x\\evil.exe",
                "ProcessId": "1234", "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentProcessId": "900",
                "CommandLine": "evil.exe -enc SQBFAFgA", "UtcTime": "2021-05-03 12:00:00",
            },
            {
                "EventID": "5", "Channel": _SYSMON, "Image": "C:\\Users\\x\\evil.exe",
                "ProcessId": "1234", "UtcTime": "2021-05-03 12:05:00",
            },
        ]
        path = self.root / "sysmon.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

        case = cases.create_case("ingest")
        ingest_file_sync(case["id"], path, _noop)
        run_detections_sync(case["id"])

        s = cases.get_session(case["id"])
        try:
            proc = s.scalars(
                select(Process).where(Process.pid == 1234, Process.session_id == "evtx-sysmon")
            ).one()
            self.assertIn("terminated", proc.flags)
            self.assertEqual(proc.extra.get("exit_time"), "2021-05-03T12:05:00+00:00")
            # detection still fires on the (now terminated) process's command line
            titles = [f.title for f in s.scalars(select(Finding))]
            self.assertTrue(
                any("encoded command" in t.lower() for t in titles),
                f"expected an encoded-command finding, got {titles}",
            )
        finally:
            s.close()

        # entity graph marks the canonical process node (the one carrying the
        # process-table pids) dead and surfaces its flags.
        graph = entity_graph.build_entity_graph(case["id"])
        proc_nodes = [
            n for n in graph["nodes"]
            if n["type"] == "process" and n["label"] == "evil.exe" and n["meta"].get("pids")
        ]
        self.assertTrue(proc_nodes, "canonical evil.exe process node missing")
        node = proc_nodes[0]
        self.assertTrue(node["meta"].get("dead"))
        self.assertIn("terminated", node["meta"].get("flags", []))

    def test_svcscan_service_node_has_state(self) -> None:
        case = cases.create_case("svc")
        s = cases.get_session(case["id"])
        try:
            cases.add_event(
                s, timestamp=None, host=None, source="memory:svcscan",
                category="persistence", entity="EvilSvc", severity="medium",
                summary="Service: EvilSvc [Stopped] -> c:\\temp\\evil.exe",
                raw={"service": "EvilSvc", "binary": "c:\\temp\\evil.exe",
                     "state": "Stopped", "plugin": "svcscan"},
            )
            s.commit()
        finally:
            s.close()

        graph = entity_graph.build_entity_graph(case["id"])
        svc = [n for n in graph["nodes"] if n["type"] == "service" and n["value"] == "EvilSvc"]
        self.assertTrue(svc, "service node missing")
        self.assertEqual(svc[0]["meta"].get("state"), "Stopped")
        self.assertTrue(svc[0]["meta"].get("dead"))
        # relationship to the binary is present so the toggle can reveal it
        files = [n for n in graph["nodes"] if n["type"] == "file"]
        self.assertTrue(any("evil.exe" in n["value"] for n in files))

    def test_suspicious_running_service_not_dead(self) -> None:
        # A flagged (non-info) service that is currently running: node appears,
        # state recorded, but not marked dead.
        case = cases.create_case("svc2")
        s = cases.get_session(case["id"])
        try:
            cases.add_event(
                s, timestamp=None, host=None, source="memory:svcscan",
                category="persistence", entity="BadSvc", severity="medium",
                summary="Service: BadSvc [Running] -> c:\\temp\\bad.exe",
                raw={"service": "BadSvc", "binary": "c:\\temp\\bad.exe",
                     "state": "Running", "plugin": "svcscan"},
            )
            s.commit()
        finally:
            s.close()
        graph = entity_graph.build_entity_graph(case["id"])
        svc = [n for n in graph["nodes"] if n["type"] == "service" and n["value"] == "BadSvc"][0]
        self.assertEqual(svc["meta"].get("state"), "Running")
        self.assertFalse(svc["meta"].get("dead"))

    def test_benign_svcscan_services_do_not_flood_graph(self) -> None:
        # Regression guard: info-severity svcscan rows (every benign Windows
        # service) must NOT create service/file nodes, or they flood the map and
        # evict the interesting nodes under the max_nodes cap.
        case = cases.create_case("svc3")
        s = cases.get_session(case["id"])
        try:
            for i in range(200):
                cases.add_event(
                    s, timestamp=None, host=None, source="memory:svcscan",
                    category="persistence", entity=f"Svc{i}", severity="info",
                    summary=f"Service: Svc{i} [Running] -> c:\\windows\\system32\\s{i}.exe",
                    raw={"service": f"Svc{i}", "binary": f"c:\\windows\\system32\\s{i}.exe",
                         "state": "Running", "plugin": "svcscan"},
                )
            s.commit()
        finally:
            s.close()
        graph = entity_graph.build_entity_graph(case["id"])
        svc_nodes = [n for n in graph["nodes"] if n["type"] == "service"]
        self.assertEqual(svc_nodes, [], "benign svcscan services should not create nodes")


if __name__ == "__main__":
    unittest.main()
