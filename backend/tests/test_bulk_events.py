from __future__ import annotations

# ruff: noqa: E402

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

from sqlalchemy import select, text
from app.store import cases
from app.store import database
from app.store.database import Event


class BulkEventsTests(unittest.TestCase):
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

    def _rows(self, n: int) -> list[dict]:
        return [
            {
                "timestamp": None,
                "host": f"host{i % 3}",
                "source": "memory:svcscan",
                "category": "persistence",
                "entity": f"svc{i}.exe",
                "severity": "info",
                "summary": f"service {i} referencing evil{i}.exe",
                "raw": {"i": i, "plugin": "svcscan"},
            }
            for i in range(n)
        ]

    def test_bulk_matches_per_row_add_event(self) -> None:
        # add_events_bulk (batch path) must yield the same events + FTS index
        # as the per-row add_event path used elsewhere.
        case_bulk = cases.create_case("bulk")
        case_ref = cases.create_case("ref")
        rows = self._rows(2500)  # spans more than one batch in real ingest

        s_bulk = cases.get_session(case_bulk["id"])
        try:
            cases.add_events_bulk(s_bulk, rows)
            s_bulk.commit()
        finally:
            s_bulk.close()

        s_ref = cases.get_session(case_ref["id"])
        try:
            for row in rows:
                cases.add_event(s_ref, **row)
            s_ref.commit()
        finally:
            s_ref.close()

        def dump(cid):
            s = cases.get_session(cid)
            try:
                events = [
                    (e.source, e.category, e.entity, e.summary, e.severity, e.host)
                    for e in s.scalars(select(Event).order_by(Event.id))
                ]
                fts = s.execute(
                    text("SELECT rowid, summary, entity, source, category FROM events_fts ORDER BY rowid")
                ).all()
                return events, [tuple(r) for r in fts]
            finally:
                s.close()

        bulk_events, bulk_fts = dump(case_bulk["id"])
        ref_events, ref_fts = dump(case_ref["id"])
        self.assertEqual(bulk_events, ref_events)
        self.assertEqual(bulk_fts, ref_fts)
        self.assertEqual(len(bulk_events), 2500)

    def test_fts_search_finds_bulk_inserted_rows(self) -> None:
        case = cases.create_case("search")
        s = cases.get_session(case["id"])
        try:
            cases.add_events_bulk(s, self._rows(50))
            s.commit()
            hits = cases.search_events(s, "evil7", limit=10)
            self.assertTrue(any("evil7.exe" in (h.summary or "") for h in hits))
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
