from __future__ import annotations

# ruff: noqa: E402
#
# Regression test for severity taint propagation. _propagate_flagged_entities
# iterates its events argument twice, so run_detections_sync must hand it a
# materialized list; a single-use streaming result would be exhausted after the
# first pass and escalate nothing. This exercises the end-to-end wiring: a benign
# event that names a flagged process must inherit that severity.

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
from app.detect.engine import _PROPAGATION_MARKER, run_detections_sync
from app.store import cases
from app.store import database
from app.store.database import Event, Process


class PropagationTests(unittest.TestCase):
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

    def test_flagged_process_name_escalates_matching_event(self) -> None:
        case = cases.create_case("prop")
        s = cases.get_session(case["id"])
        try:
            # A process whose command line trips a critical rule -> gets flagged,
            # so its distinctive name becomes a taint source.
            s.add(Process(
                pid=4242, ppid=None, name="beacon-x.exe",
                path="C:\\Users\\v\\beacon-x.exe",
                cmdline="beacon-x.exe mimikatz sekurlsa::logonpasswords",
                session_id="live", flags=[], severity="info",
            ))
            # A separate, initially-benign event that merely names that process.
            cases.add_event(
                s, timestamp=None, host=None, source="weblog", category="weblog",
                entity="10.0.0.9", severity="info",
                summary="GET /downloads/beacon-x.exe -> 200",
                raw={"path": "/downloads/beacon-x.exe"},
            )
            s.commit()
            benign_id = s.scalars(select(Event)).one().id
        finally:
            s.close()

        run_detections_sync(case["id"])

        s = cases.get_session(case["id"])
        try:
            ev = s.get(Event, benign_id)
            # propagation raised the benign event above 'info' and recorded why.
            self.assertNotEqual(ev.severity, "info")
            self.assertTrue((ev.severity_reason or "").startswith(_PROPAGATION_MARKER))
            self.assertIn("beacon-x.exe", ev.severity_reason)
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
