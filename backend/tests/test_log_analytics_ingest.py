from __future__ import annotations

# ruff: noqa: E402
#
# Log Analytics / Sentinel "Export to JSON" produces a columnar envelope
# {"tables":[{"columns":[...],"rows":[[...]]}]} rather than an array of row
# dicts. These tests assert the envelope is flattened per-row, timestamps are
# populated (so events reach the timeline), and — for SecurityEvent rows — the
# existing Windows EventID detections fire end-to-end.

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
from app.detect import engine
from app.ingest.parsers import parse_file
from app.store import cases, database
from app.store.database import Finding


def _envelope(table_name: str, columns: list[str], rows: list[list]) -> dict:
    return {"tables": [{
        "name": table_name,
        "columns": [{"name": c, "type": "string"} for c in columns],
        "rows": rows,
    }]}


_SECURITYEVENT_COLS = ["TimeGenerated", "Computer", "EventID", "Account",
                       "Activity", "IpAddress", "LogonType"]


def _securityevent_envelope() -> dict:
    rows = []
    # 12 failed logons (4625) for the same account/source
    for i in range(12):
        rows.append([f"7/8/2026, 11:5{i % 10}:31.000 AM", "DC01", "4625",
                     "CONTOSO\\admin", "4625 - failed logon", "203.0.113.5", "3"])
    # a successful logon (4624) for the same pairing
    rows.append(["7/8/2026, 12:10:00.000 PM", "DC01", "4624", "CONTOSO\\admin",
                 "4624 - logon", "203.0.113.5", "3"])
    # security log cleared (1102)
    rows.append(["7/8/2026, 12:20:00.000 PM", "DC01", "1102", "CONTOSO\\admin",
                 "1102 - log cleared", "", ""])
    return _envelope("PrimaryResult", _SECURITYEVENT_COLS, rows)


class LogAnalyticsEnvelopeTests(unittest.TestCase):
    def test_single_line_envelope_flattens_and_timestamps(self) -> None:
        env = _securityevent_envelope()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "export.json"
            p.write_text(json.dumps(env))  # single-line (portal) form
            events = list(parse_file(p, "SecurityEvent"))
        self.assertEqual(len(events), 14)
        self.assertTrue(all(e["timestamp"] is not None for e in events),
                        "every row must have a parsed timestamp (else it vanishes from the timeline)")

    def test_pretty_printed_envelope_also_parses(self) -> None:
        env = _securityevent_envelope()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "export.json"
            p.write_text(json.dumps(env, indent=2))  # pretty form -> parse_json hook
            events = list(parse_file(p, "SecurityEvent"))
        self.assertEqual(len(events), 14)

    def test_pretty_envelope_parses_when_metadata_precedes_tables(self) -> None:
        env = {"statistics": {"query": {"executionTime": 0.1}},
               **_securityevent_envelope()}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "export.json"
            p.write_text(json.dumps(env, indent=2))
            events = list(parse_file(p, "SecurityEvent"))
        self.assertEqual(len(events), 14)

    def test_generic_table_name_not_stamped(self) -> None:
        env = _securityevent_envelope()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "export.json"
            p.write_text(json.dumps(env))
            events = list(parse_file(p, "SecurityEvent"))
        self.assertNotIn("_TableName", events[0]["raw"])


class LogAnalyticsDetectionTests(unittest.TestCase):
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

    def _ingest_and_detect(self, env: dict) -> set[str]:
        case = cases.create_case("la")
        cid = case["id"]
        p = self.root / "SecurityEvent.json"
        p.write_text(json.dumps(env))
        session = cases.get_session(cid)
        try:
            rows = [
                {k: e[k] for k in ("timestamp", "host", "source", "category",
                                   "entity", "severity", "summary", "raw")}
                for e in parse_file(p, "SecurityEvent")
            ]
            cases.add_events_bulk(session, rows)
            session.commit()
        finally:
            session.close()
        engine.run_detections_sync(cid)
        session = cases.get_session(cid)
        try:
            return {f.title for f in session.scalars(select(Finding))}
        finally:
            session.close()

    def test_securityevent_brute_force_and_log_clear(self) -> None:
        titles = self._ingest_and_detect(_securityevent_envelope())
        self.assertTrue(any("Brute force followed by successful logon" in t for t in titles),
                        f"expected brute-force finding, got {titles}")
        self.assertIn("Security event log cleared", titles)


if __name__ == "__main__":
    unittest.main()
