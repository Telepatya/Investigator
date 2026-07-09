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

from sqlalchemy import delete as sqldelete, func, select
from app.store import cases
from app.store import database
from app.store.database import Finding
from app.detect import manual, overrides


class ManualFindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda cid: self.root / cid / "case.db"),
        ]
        for p in self.patches:
            p.start()
        self.case = cases.create_case("manual")["id"]

    def tearDown(self) -> None:
        database.dispose_all_db_engines()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _add(self, **kw):
        s = cases.get_session(self.case)
        try:
            item = manual.add_manual_finding(s, **kw)
            manual.apply_manual_findings(s)
            overrides.apply_overrides(s)
            s.commit()
            return item
        finally:
            s.close()

    def test_add_materialises_tagged_finding_and_counts_active(self) -> None:
        self._add(title="Suspicious explorer.exe", severity="high",
                  ref_type="entity", ref_id="e1", ref_label="explorer.exe")
        s = cases.get_session(self.case)
        try:
            rows = list(s.scalars(select(Finding)))
        finally:
            s.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].source, "manual")
        self.assertEqual(rows[0].severity, "high")
        self.assertTrue(rows[0].evidence.get("manual"))
        stats = cases.get_case_stats(self.case)
        self.assertEqual(stats["finding_count"], 1)
        self.assertEqual(stats["active_finding_count"], 1)

    def test_survives_findings_table_wipe(self) -> None:
        item = self._add(title="Manual net beacon", severity="medium",
                         ref_type="event", ref_id="42", ref_label="10.0.0.5")
        # Simulate a detections rebuild wiping the findings table, then the
        # re-materialisation step the engine runs at the end of every pass.
        s = cases.get_session(self.case)
        try:
            s.execute(sqldelete(Finding))
            s.commit()
            self.assertEqual(s.scalar(select(func.count()).select_from(Finding)), 0)
            manual.apply_manual_findings(s)
            s.commit()
            rows = list(s.scalars(select(Finding)))
        finally:
            s.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].evidence.get("manual_id"), item["id"])

    def test_remove_deletes_it(self) -> None:
        item = self._add(title="Temp flag", severity="low",
                         ref_type="entity", ref_id="e9", ref_label="x")
        s = cases.get_session(self.case)
        try:
            self.assertTrue(manual.remove_manual_finding(s, item["id"]))
            manual.apply_manual_findings(s)
            s.commit()
            self.assertEqual(s.scalar(select(func.count()).select_from(Finding)), 0)
        finally:
            s.close()

    def test_manual_finding_colours_matching_entity_node(self) -> None:
        from app.detect.entity_graph import build_entity_graph
        from app.store.database import Process
        s = cases.get_session(self.case)
        try:
            s.add(Process(pid=666, ppid=None, name="evil.exe", session_id="live", severity="info"))
            s.commit()
        finally:
            s.close()
        self._add(title="Manual critical on evil.exe", severity="critical",
                  ref_type="entity", ref_id="process::evil.exe", ref_label="evil.exe",
                  node_type="process", node_value="evil.exe")
        graph = build_entity_graph(self.case, min_severity="info", max_nodes=500)
        procs = [n for n in graph["nodes"] if n["type"] == "process" and n["value"] == "evil.exe"]
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0]["severity"], "critical")
        self.assertTrue(
            any(f.get("title", "").startswith("Manual critical") for f in procs[0]["findings"])
        )

    def test_manual_flag_creates_missing_node_and_links(self) -> None:
        from app.detect.entity_graph import build_entity_graph
        # Nothing about badsite.com exists in the graph yet.
        self._add(title="Manual C2 domain", severity="critical",
                  ref_type="event", ref_id="1", ref_label="badsite.com",
                  node_type="domain", node_value="badsite.com",
                  links=[{"type": "host", "value": "WS-07", "verb": "seen on"}])
        graph = build_entity_graph(self.case, min_severity="info", max_nodes=500)
        by_id = {n["id"]: n for n in graph["nodes"]}
        dom = by_id.get("domain::badsite.com")
        host = by_id.get("host::WS-07")
        self.assertIsNotNone(dom)
        self.assertEqual(dom["severity"], "critical")
        self.assertTrue(dom["meta"].get("manual"))
        self.assertIsNotNone(host)  # link target materialised too
        # The correlation edge exists between the new node and its linked host.
        self.assertTrue(
            any(e["source"] == "domain::badsite.com" and e["target"] == "host::WS-07"
                for e in graph["edges"])
        )

    def test_derive_event_node_infers_type_and_links(self) -> None:
        from app.store.database import Event
        ev = Event(
            timestamp=None, host="WS-07", source="sysmon", category="process",
            entity="evil.exe", severity="info", summary="ran evil.exe",
            raw={"Computer": "WS-07", "SubjectUserName": "victim", "Image": "C:/tmp/evil.exe"},
        )
        ntype, nval, links = manual.derive_event_node(ev)
        self.assertEqual(ntype, "process")
        self.assertEqual(nval, "evil.exe")
        link_types = {lk["type"] for lk in links}
        self.assertIn("host", link_types)
        self.assertIn("user", link_types)

    def test_benign_mark_survives_rematerialisation(self) -> None:
        item = self._add(title="Manual host flag", severity="high",
                         ref_type="entity", ref_id="h1", ref_label="WORKSTATION-07")
        s = cases.get_session(self.case)
        try:
            row = s.scalars(select(Finding)).one()
            overrides.set_finding_benign(
                s, overrides.finding_key(row.title, row.evidence), True
            )
            # Re-materialise (new row) then re-apply overrides: the benign mark,
            # keyed off title + evidence summary, must still catch it.
            manual.apply_manual_findings(s)
            overrides.apply_overrides(s)
            s.commit()
            row = s.scalars(select(Finding)).one()
            self.assertEqual(row.severity, "info")
            self.assertEqual(row.evidence.get("suppressed_from"), "high")
        finally:
            s.close()
        self.assertEqual(cases.get_case_stats(self.case)["active_finding_count"], 0)
        self.assertEqual(item["severity"], "high")


if __name__ == "__main__":
    unittest.main()
