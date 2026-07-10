from __future__ import annotations

# ruff: noqa: E402

import sys
import tempfile
import types
import unittest
from pathlib import Path
from threading import Barrier, Thread
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


class _ManualFindingBase(unittest.TestCase):
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


class ManualFindingTests(_ManualFindingBase):
    def test_flagged_download_event_escalates_exact_path_and_restores_on_delete(self) -> None:
        from datetime import datetime
        from app.detect.entity_graph import build_entity_graph
        from app.store.database import Event

        path = r"C:\Users\roeif\Downloads\go-winpmem_amd64_1.0-rc1_signed.exe"
        device_path = rf"\\.\{path}"
        session = cases.get_session(self.case)
        try:
            referenced = Event(
                timestamp=datetime(2026, 7, 2, 6, 22, 28),
                host="WORKSTATION-01",
                source="Windows.Detection.EvidenceOfDownload",
                category="filesystem",
                entity=None,
                severity="info",
                summary=f"DownloadedFilePath={device_path}; Mtime=2026-07-02T06:22:28Z",
                raw={"DownloadedFilePath": device_path},
            )
            related = Event(
                timestamp=datetime(2026, 7, 2, 6, 23),
                host="WORKSTATION-01",
                source="Windows.Forensics.Usn",
                category="filesystem",
                entity=path,
                severity="low",
                severity_reason="Parser classification",
                summary=f"USN create {path}",
                raw={"TargetFilename": path},
            )
            unrelated = Event(
                timestamp=datetime(2026, 7, 2, 6, 24),
                host="WORKSTATION-01",
                source="Windows.Forensics.Usn",
                category="filesystem",
                entity=r"C:\Temp\go-winpmem_amd64_1.0-rc1_signed.exe",
                severity="info",
                summary="same basename elsewhere",
                raw={"TargetFilename": r"C:\Temp\go-winpmem_amd64_1.0-rc1_signed.exe"},
            )
            session.add_all([referenced, related, unrelated])
            session.commit()
            referenced_id, related_id, unrelated_id = referenced.id, related.id, unrelated.id
        finally:
            session.close()

        item = self._add(
            title="Analyst-flagged event: downloaded go-winpmem",
            severity="critical",
            ref_type="event",
            ref_id=str(referenced_id),
            ref_label=referenced.summary,
        )

        session = cases.get_session(self.case)
        try:
            referenced = session.get(Event, referenced_id)
            related = session.get(Event, related_id)
            unrelated = session.get(Event, unrelated_id)
            stored = next(entry for entry in manual.get_manual_findings(session) if entry["id"] == item["id"])
            finding = session.scalars(select(Finding).where(Finding.source == "manual")).one()
            self.assertEqual(referenced.severity, "critical")
            self.assertEqual(related.severity, "critical")
            self.assertEqual(unrelated.severity, "info")
            self.assertTrue(referenced.severity_reason.startswith("Analyst-flagged event"))
            self.assertEqual(stored["node_type"], "file")
            self.assertEqual(stored["node_value"], path)
            self.assertEqual(finding.evidence["node_type"], "file")
            self.assertEqual(finding.evidence["node_value"], path)
        finally:
            session.close()

        graph = build_entity_graph(self.case, min_severity="info", max_nodes=500)
        node = next(entry for entry in graph["nodes"] if entry["id"] == f"file::{path}")
        self.assertEqual(node["severity"], "critical")

        session = cases.get_session(self.case)
        try:
            finding = session.scalars(select(Finding).where(Finding.source == "manual")).one()
            key = overrides.finding_key(finding.title, finding.evidence)
            overrides.set_finding_benign(session, key, True)
            manual.apply_manual_findings(session)
            overrides.apply_overrides(session)
            session.commit()
            self.assertEqual(session.get(Event, referenced_id).severity, "info")
            self.assertEqual(session.get(Event, related_id).severity, "low")

            overrides.set_finding_benign(session, key, False)
            manual.apply_manual_findings(session)
            overrides.apply_overrides(session)
            session.commit()
            self.assertEqual(session.get(Event, referenced_id).severity, "critical")
            self.assertEqual(session.get(Event, related_id).severity, "critical")

            self.assertTrue(manual.remove_manual_finding(session, item["id"]))
            manual.apply_manual_findings(session)
            session.commit()
            self.assertEqual(session.get(Event, referenced_id).severity, "info")
            restored_related = session.get(Event, related_id)
            self.assertEqual(restored_related.severity, "low")
            self.assertEqual(restored_related.severity_reason, "Parser classification")
            self.assertEqual(session.get(Event, unrelated_id).severity, "info")
        finally:
            session.close()

    def test_concurrent_additions_do_not_lose_metadata_updates(self) -> None:
        worker_count = 8
        barrier = Barrier(worker_count)
        errors: list[BaseException] = []

        def add_finding(index: int) -> None:
            session = cases.get_session(self.case)
            try:
                barrier.wait(timeout=5)
                manual.add_manual_finding(
                    session,
                    title=f"Concurrent finding {index}",
                    severity="low",
                    ref_type="entity",
                    ref_id=f"entity-{index}",
                    ref_label=f"entity-{index}",
                )
                manual.apply_manual_findings(session)
                session.commit()
            except BaseException as exc:
                errors.append(exc)
            finally:
                session.close()

        threads = [Thread(target=add_finding, args=(index,)) for index in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        session = cases.get_session(self.case)
        try:
            stored = manual.get_manual_findings(session)
            materialized = list(session.scalars(select(Finding).where(Finding.source == "manual")))
        finally:
            session.close()
        self.assertEqual(len(stored), worker_count)
        self.assertEqual(len(materialized), worker_count)

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


class ManualFindingCorrelationTests(_ManualFindingBase):
    """Evidence-backed correlation: a flagged entity gets edges to every
    process/user/host that touched it, derived from the ingested events."""

    def _add_event(self, s, ts, raw, *, category="hostlog", severity="info",
                   host="WS-07", entity="", summary=""):
        from app.store.database import Event
        s.add(Event(
            timestamp=ts, host=host, source="sysmon", category=category,
            entity=entity, severity=severity,
            summary=summary or f"event {raw.get('EventID', '')}",
            raw=raw,
        ))

    def test_flagged_file_correlates_processes_users_hosts(self) -> None:
        from datetime import datetime
        from app.detect.entity_graph import build_entity_graph
        s = cases.get_session(self.case)
        try:
            # Sysmon 11: word.exe (run by victim) writes the payload to disk.
            self._add_event(s, datetime(2026, 1, 1, 10, 0), {
                "EventID": "11",
                "TargetFilename": "C:\\tmp\\payload.exe",
                "Image": "C:\\Program Files\\word.exe",
                "SubjectUserName": "victim",
                "Computer": "WS-07",
            }, summary="word.exe created C:\\tmp\\payload.exe")
            # 4688: the payload is later executed.
            self._add_event(s, datetime(2026, 1, 1, 10, 5), {
                "EventID": "4688",
                "NewProcessName": "C:\\tmp\\payload.exe",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "SubjectUserName": "victim",
                "Computer": "WS-07",
            }, category="process", summary="payload.exe executed")
            s.commit()
        finally:
            s.close()

        self._add(title="Analyst-flagged file: payload", severity="high",
                  ref_type="entity", ref_id="file::C:\\tmp\\payload.exe",
                  ref_label="C:\\tmp\\payload.exe",
                  node_type="file", node_value="C:\\tmp\\payload.exe")

        graph = build_entity_graph(self.case, min_severity="info", max_nodes=500)
        by_id = {n["id"]: n for n in graph["nodes"]}
        fid = "file::C:\\tmp\\payload.exe"
        self.assertIn(fid, by_id)
        node = by_id[fid]
        self.assertTrue(node["meta"].get("manual"))
        self.assertGreaterEqual(node["meta"].get("correlated", 0), 3)

        edges = [(e["source"], e["verb"], e["target"]) for e in graph["edges"]]
        # The writing process, with the Sysmon-11 verb.
        self.assertTrue(any(
            src.startswith("process::") and "word.exe" in src.lower()
            and verb == "created file" and dst == fid
            for src, verb, dst in edges))
        # The account involved.
        self.assertTrue(any(
            src == "user::victim" and dst == fid for src, verb, dst in edges))
        # Seen on the host.
        self.assertTrue(any(
            src == fid and verb == "seen on" and dst == "host::WS-07"
            for src, verb, dst in edges))
        # The 4688 marks the parent as having executed the flagged file.
        self.assertTrue(any(
            src.startswith("process::") and "explorer.exe" in src.lower()
            and verb == "executed" and dst == fid
            for src, verb, dst in edges))

    def test_correlation_capped_and_ranked_by_severity(self) -> None:
        from datetime import datetime, timedelta
        from app.detect.entity_graph import build_entity_graph, _MANUAL_CORRELATION_CAP
        base_ts = datetime(2026, 1, 1, 9, 0)
        s = cases.get_session(self.case)
        try:
            for i in range(20):
                self._add_event(s, base_ts + timedelta(minutes=i), {
                    "EventID": "11",
                    "TargetFilename": "C:\\tmp\\shared.dat",
                    "Image": f"C:\\bin\\tool{i:02d}.exe",
                }, severity="info")
            # One high-severity toucher that must survive the cap.
            self._add_event(s, base_ts + timedelta(hours=1), {
                "EventID": "11",
                "TargetFilename": "C:\\tmp\\shared.dat",
                "Image": "C:\\evil\\special.exe",
            }, severity="high")
            s.commit()
        finally:
            s.close()

        self._add(title="Analyst-flagged file: shared.dat", severity="medium",
                  ref_type="entity", ref_id="file::C:\\tmp\\shared.dat",
                  ref_label="C:\\tmp\\shared.dat",
                  node_type="file", node_value="C:\\tmp\\shared.dat")

        graph = build_entity_graph(self.case, min_severity="info", max_nodes=500)
        by_id = {n["id"]: n for n in graph["nodes"]}
        node = by_id["file::C:\\tmp\\shared.dat"]
        self.assertEqual(node["meta"].get("correlated"), _MANUAL_CORRELATION_CAP)
        touching = [e for e in graph["edges"]
                    if e["target"] == "file::C:\\tmp\\shared.dat"
                    and e["source"].startswith("process::")]
        self.assertLessEqual(len(touching), _MANUAL_CORRELATION_CAP)
        self.assertTrue(any("special.exe" in e["source"].lower() for e in touching))

    def test_flag_merges_with_existing_basename_node(self) -> None:
        from app.detect.entity_graph import build_entity_graph
        from app.store.database import Process
        s = cases.get_session(self.case)
        try:
            s.add(Process(pid=101, ppid=None, name="payload.exe",
                          session_id="live", severity="info"))
            s.commit()
        finally:
            s.close()
        self._add(title="Analyst-flagged process: payload", severity="critical",
                  ref_type="entity", ref_id="process::payload.exe",
                  ref_label="C:\\tmp\\payload.exe",
                  node_type="process", node_value="C:\\tmp\\payload.exe")
        graph = build_entity_graph(self.case, min_severity="info", max_nodes=500)
        payload_nodes = [n for n in graph["nodes"] if n["type"] == "process"
                         and n["label"].lower() == "payload.exe"]
        self.assertEqual(len(payload_nodes), 1)
        node = payload_nodes[0]
        self.assertEqual(node["id"], "process::payload.exe")
        self.assertTrue(node["meta"].get("manual"))
        self.assertEqual(node["severity"], "critical")
        self.assertTrue(any(f.get("title", "").startswith("Analyst-flagged")
                            for f in node["findings"]))

    def test_full_path_flag_does_not_correlate_same_basename_elsewhere(self) -> None:
        from datetime import datetime
        from app.detect.entity_graph import build_entity_graph

        session = cases.get_session(self.case)
        try:
            self._add_event(session, datetime(2026, 1, 1, 10, 0), {
                "EventID": "11",
                "TargetFilename": "C:\\Temp\\payload.exe",
                "Image": "C:\\Tools\\temp-writer.exe",
                "SubjectUserName": "temp-user",
                "Computer": "WS-TEMP",
            })
            self._add_event(session, datetime(2026, 1, 1, 10, 1), {
                "EventID": "11",
                "TargetFilename": "C:\\Windows\\payload.exe",
                "Image": "C:\\Tools\\windows-writer.exe",
                "SubjectUserName": "windows-user",
                "Computer": "WS-WINDOWS",
            })
            session.commit()
        finally:
            session.close()

        target = "file::C:\\Temp\\payload.exe"
        self._add(
            title="Flag only the temporary payload",
            severity="high",
            ref_type="entity",
            ref_id=target,
            ref_label="C:\\Temp\\payload.exe",
            node_type="file",
            node_value="C:\\Temp\\payload.exe",
        )
        graph = build_entity_graph(self.case, min_severity="info", max_nodes=500)
        correlated = [
            edge for edge in graph["edges"]
            if edge["source"] == target or edge["target"] == target
        ]
        endpoints = {edge["source"] for edge in correlated} | {edge["target"] for edge in correlated}

        self.assertTrue(any(endpoint.lower().endswith("temp-writer.exe") for endpoint in endpoints))
        self.assertIn("user::temp-user", endpoints)
        self.assertIn("host::WS-TEMP", endpoints)
        self.assertFalse(any(endpoint.lower().endswith("windows-writer.exe") for endpoint in endpoints))
        self.assertNotIn("user::windows-user", endpoints)
        self.assertNotIn("host::WS-WINDOWS", endpoints)

    def test_dossier_trace_aligns_with_correlated_edges(self) -> None:
        from datetime import datetime
        from app.detect.entity_graph import entity_dossier
        s = cases.get_session(self.case)
        try:
            self._add_event(s, datetime(2026, 1, 1, 10, 0), {
                "EventID": "11",
                "TargetFilename": "C:\\tmp\\payload.exe",
                "Image": "C:\\Program Files\\word.exe",
                "SubjectUserName": "victim",
                "Computer": "WS-07",
            }, summary="word.exe created C:\\tmp\\payload.exe")
            s.commit()
        finally:
            s.close()
        self._add(title="Analyst-flagged file: payload", severity="high",
                  ref_type="entity", ref_id="file::C:\\tmp\\payload.exe",
                  ref_label="C:\\tmp\\payload.exe",
                  node_type="file", node_value="C:\\tmp\\payload.exe")
        dossier = entity_dossier(self.case, "file::C:\\tmp\\payload.exe")
        self.assertTrue(dossier)
        # The file branch of _event_mentions surfaces the touching event.
        self.assertEqual(dossier["action_total"], 1)
        self.assertIn("word.exe", dossier["actions"][0]["summary"])
        neighbor_ids = {n["entity"]["id"] for n in dossier["neighbors"]}
        self.assertTrue(any("word.exe" in nid.lower() for nid in neighbor_ids))
        self.assertIn("user::victim", neighbor_ids)
        self.assertIn("host::WS-07", neighbor_ids)


if __name__ == "__main__":
    unittest.main()
