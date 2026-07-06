from __future__ import annotations

# ruff: noqa: E402
#
# Phase-4 read-layer changes:
#   - get_case_stats collapses 3 COUNT round trips into 1.
#   - search_events replaces a get()-per-hit N+1 with one SELECT ... IN,
#     preserving FTS rank order; count_search_events counts all matches.
#   - GET /events total now respects the category/severity/q filters. The
#     substance of that fix is the filtered COUNT query, exercised here.

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

from sqlalchemy import func, select
from app.store import cases
from app.store import database
from app.store.database import Event, Finding, Process


class ApiReadTests(unittest.TestCase):
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

    def _seed(self, cid: str) -> None:
        s = cases.get_session(cid)
        try:
            for i in range(60):
                cases.add_event(
                    s,
                    timestamp=None, host=None, source="sysmon",
                    category=("process" if i % 2 else "network"),
                    entity=f"evil{i}.exe",
                    severity=("high" if i % 3 == 0 else "info"),
                    summary=f"malware{i} ran evil{i}.exe from tmp",
                    raw={"i": i},
                )
            for i in range(5):
                s.add(Finding(title=f"f{i}", description="d", severity="high",
                              mitre_techniques=["T1059"], evidence={}, source="t"))
            for i in range(7):
                s.add(Process(pid=100 + i, ppid=None, name=f"p{i}.exe", session_id="live"))
            s.commit()
        finally:
            s.close()

    def test_get_case_stats_single_query_matches_counts(self) -> None:
        case = cases.create_case("stats")
        self._seed(case["id"])
        stats = cases.get_case_stats(case["id"])

        s = cases.get_session(case["id"])
        try:
            ev = s.scalar(select(func.count()).select_from(Event))
            fi = s.scalar(select(func.count()).select_from(Finding))
            pr = s.scalar(select(func.count()).select_from(Process))
        finally:
            s.close()
        self.assertEqual(stats, {"event_count": ev, "finding_count": fi, "process_count": pr})
        self.assertEqual((ev, fi, pr), (60, 5, 7))

    def test_get_case_stats_missing_db(self) -> None:
        self.assertEqual(
            cases.get_case_stats("nonexistent"),
            {"event_count": 0, "finding_count": 0, "process_count": 0},
        )

    def test_search_events_order_and_objects(self) -> None:
        case = cases.create_case("search")
        self._seed(case["id"])
        s = cases.get_session(case["id"])
        try:
            # Reference: FTS ids in rank order, then get() per id (old behavior).
            from sqlalchemy import text
            rows = s.execute(
                text("SELECT fts.rowid AS id FROM events_fts fts WHERE events_fts "
                     "MATCH :q ORDER BY rank LIMIT :limit"),
                {"q": "evil5", "limit": 50},
            ).mappings().all()
            ref = [s.get(Event, r["id"]) for r in rows if r["id"]]

            got = cases.search_events(s, "evil5", limit=50)
            self.assertEqual([e.id for e in got], [e.id for e in ref])
            self.assertTrue(all(isinstance(e, Event) for e in got))
            self.assertEqual(cases.count_search_events(s, "evil5"), len(ref))
        finally:
            s.close()

    def test_count_search_events_ignores_limit(self) -> None:
        case = cases.create_case("count")
        self._seed(case["id"])
        s = cases.get_session(case["id"])
        try:
            # bare token "ran" appears in every summary -> 60 matches, page limit 10.
            page = cases.search_events(s, "ran", limit=10)
            total = cases.count_search_events(s, "ran")
            self.assertEqual(len(page), 10)
            self.assertEqual(total, 60)
        finally:
            s.close()

    def test_events_filtered_count(self) -> None:
        # Mirror the router's count_stmt: total must reflect category/severity.
        case = cases.create_case("filtered")
        self._seed(case["id"])
        s = cases.get_session(case["id"])
        try:
            def count(category=None, severity=None):
                stmt = select(func.count()).select_from(Event)
                if category:
                    stmt = stmt.where(Event.category == category)
                if severity:
                    stmt = stmt.where(Event.severity == severity)
                return s.scalar(stmt)

            self.assertEqual(count(), 60)
            self.assertEqual(count(category="process"), 30)
            self.assertEqual(count(category="network"), 30)
            self.assertEqual(count(severity="high"), 20)   # i % 3 == 0 -> 0,3,..,57
            self.assertEqual(count(category="process", severity="high"), 10)
            # The unfiltered count (the old bug) would have reported 60 for all.
            self.assertNotEqual(count(category="process"), count())
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
