from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app.config as config
from app.reverse.analysis import (
    ReverseAnalysisManager,
    _render_report,
    _tool_request_for_provenance,
)
from app.reverse.database import (
    ReverseArtifact,
    ReverseMessage,
    ReverseProject,
    ReverseProvenanceEntry,
    ReverseRun,
    dispose_reverse_db,
    get_reverse_session,
    init_reverse_db,
)
from app.reverse.store import contained_project_path, create_project
from app.reverse.tools import parse_tool_call


class _Provider:
    def __init__(self, responses: list[str]):
        self.responses = responses

    async def complete(self, _messages, stream=False):
        assert stream is False
        return self.responses.pop(0)


VALID_REPORT = """ANALYSIS COMPLETE

# Forensic Malware Analysis

## Executive Summary
Static evidence is limited.

## Artifact Inventory
- One test artifact.

## Malware Assessment
Verdict: inconclusive
Confidence: low

## Capability Analysis
No capability is established by this fixture.

## Static Reverse-Engineering Evidence
The file-type tool identified the fixture.

## Packing and Anti-Analysis
Not established.

## Indicators of Compromise
- SHA-256 only.

## Limitations
The fixture is not a complete executable.

## Recommended Next Steps
Acquire a valid sample for further static analysis.
"""


VERIFIER_PASS = json.dumps({
    "status": "pass",
    "summary": "The verdict and capabilities match the available static evidence.",
    "unsupported_claims": [],
    "missing_evidence": [],
    "contradictions": [],
    "revision_instructions": "",
})

IOC_RESULT = "- File hash: fixture SHA-256 from the analyzed sample."


def file_tool(artifact_id: str) -> str:
    return json.dumps([{
        "tool": "run_cmd",
        "cmd": ["file", f"/workspace/inputs/{artifact_id}"],
    }])


class ReverseAnalysisTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_dir = config.DEFAULT_CONFIG_DIR
        self.old_file = config.CONFIG_FILE
        config.DEFAULT_CONFIG_DIR = self.root
        config.CONFIG_FILE = self.root / "config.json"
        self.cfg = config.AppConfig()
        self.cfg.llm.provider = "ollama"
        self.cfg.llm.model = "snapshot-model"
        self.cfg.reverse.enabled_tools = ["run_cmd", "read_file", "write_file", "list_dir"]
        self.config_patch = patch.object(config, "load_config", side_effect=lambda: self.cfg)
        self.config_patch.start()
        dispose_reverse_db()
        init_reverse_db()

    async def asyncTearDown(self) -> None:
        dispose_reverse_db()
        self.config_patch.stop()
        config.DEFAULT_CONFIG_DIR = self.old_dir
        config.CONFIG_FILE = self.old_file
        self.temp.cleanup()

    def project_with_artifact(self):
        project = create_project("analysis")
        artifact_id = str(uuid.uuid4())
        data = b"MZ static test"
        relative = f"uploads/{artifact_id}"
        path = contained_project_path(project.id, relative)
        path.write_bytes(data)
        with get_reverse_session() as db:
            db.add(ReverseArtifact(
                id=artifact_id,
                project_id=project.id,
                name="sample.exe",
                relative_path=relative,
                artifact_type="upload",
                content_type="application/octet-stream",
                file_size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            ))
            db.commit()
        return project, artifact_id

    async def test_end_to_end_mocked_provider_creates_signed_report_and_trace(self) -> None:
        project, artifact_id = self.project_with_artifact()
        provider = _Provider([
            file_tool(artifact_id),
            VALID_REPORT,
            IOC_RESULT,
            VERIFIER_PASS,
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", side_effect=lambda: self.cfg),
            patch("app.reverse.sandbox.load_config", side_effect=lambda: self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "test-public-key",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={"file": "test"}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "data", "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id, "identify the format")
            await manager._tasks[project.id]

        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.provider, "ollama")
            self.assertEqual(stored.model, "snapshot-model")
            self.assertIn("Forensic Malware Analysis Report", stored.report_markdown)
            self.assertEqual(stored.report_verification_status, "verified")
            self.assertIn("match", stored.report_verification_summary)
            tool_messages = list(db.query(ReverseMessage).filter(
                ReverseMessage.run_id == run.id,
                ReverseMessage.role == "tool",
            ))
            self.assertEqual(len(tool_messages), 1)
            self.assertIn("data", tool_messages[0].content)
        report_path = contained_project_path(project.id, f"outputs/{run.id}-report.md", must_exist=True)
        self.assertIn("Static evidence is limited", report_path.read_text(encoding="utf-8"))

    async def test_signing_failure_keeps_report_completed_and_retry_is_llm_free(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        provider = _Provider([
            file_tool(_artifact_id),
            VALID_REPORT.replace("Static evidence is limited.", "Persisted before signing."),
            IOC_RESULT,
            VERIFIER_PASS,
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", side_effect=OSError("vault unavailable")),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "data", "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.report_signature_status, "failed")
            self.assertEqual(stored.report_signature_error, "vault unavailable")
            self.assertIsNone(stored.error)
            self.assertIn("Persisted before signing", stored.report_markdown)
        report_path = contained_project_path(
            project.id, f"outputs/{run.id}-report.md", must_exist=True
        )
        self.assertTrue(report_path.is_file())
        self.assertEqual(
            hashlib.sha256(report_path.read_bytes()).hexdigest(),
            hashlib.sha256(stored.report_markdown.encode()).hexdigest(),
        )

        with (
            patch("app.reverse.analysis.sign_bytes", return_value="ed25519:c2ln"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "a" * 64,
            }),
            patch("app.reverse.analysis.get_provider") as provider_after,
        ):
            retried = await manager.retry_report_signature(project.id)
        provider_after.assert_not_called()
        self.assertEqual(retried.report_signature_status, "signed")
        self.assertIsNone(retried.report_signature_error)

    async def test_resume_refuses_a_changed_sandbox_image(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="stopped",
            provider="ollama", model="snapshot-model", image_digest="image@sha256:original",
        )
        with get_reverse_session() as db:
            db.add(run)
            stored_project = db.get(ReverseProject, project.id)
            stored_project.status = "stopped"
            stored_project.active_run_id = run.id
            db.commit()
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:changed")
        with (
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.stop") as stop,
        ):
            with self.assertRaisesRegex(RuntimeError, "image changed"):
                await manager.resume(project.id)
        stop.assert_called_once_with(project.id)

    async def test_chat_snapshots_non_secret_shared_settings_in_provenance(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()
        manager = ReverseAnalysisManager()
        provider = _Provider(["Grounded follow-up answer."])
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
        ):
            reply = await manager.chat(project.id, "What is supported?")
        self.assertEqual(reply.metadata_json["llm_snapshot"]["model"], "snapshot-model")
        with get_reverse_session() as db:
            events = list(db.query(ReverseProvenanceEntry).filter(
                ReverseProvenanceEntry.project_id == project.id,
            ))
        self.assertEqual([entry.event_type for entry in events], ["chat.started", "chat.completed"])
        self.assertNotIn("api_key", json.dumps([entry.payload for entry in events]))

    async def test_follow_up_chat_uses_the_sandbox_tool_loop(self) -> None:
        project, artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()
        provider = _Provider([
            file_tool(artifact_id),
            "CHAT COMPLETE: The sample is identified as a PE32 executable.",
        ])
        manager = ReverseAnalysisManager()
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "PE32 executable", "stderr": "",
                "returncode": 0,
            }) as execute,
        ):
            reply = await manager.chat(project.id, "Confirm the file type with evidence")
        self.assertEqual(reply.content, "The sample is identified as a PE32 executable.")
        self.assertEqual(reply.metadata_json["tool_uses"], 1)
        execute.assert_called_once()
        with get_reverse_session() as db:
            events = list(db.query(ReverseProvenanceEntry).filter(
                ReverseProvenanceEntry.project_id == project.id,
            ))
        self.assertEqual(
            [entry.event_type for entry in events],
            ["chat.started", "chat.tool_executed", "chat.completed"],
        )

    async def test_chat_strips_a_trailing_completion_marker(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()
        provider = _Provider([
            "The installer contacts endpoints supplied by runtime configuration.\n\n"
            "CHAT COMPLETE:",
        ])
        manager = ReverseAnalysisManager()
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
        ):
            reply = await manager.chat(project.id, "Where are its endpoints configured?")
        self.assertEqual(
            reply.content,
            "The installer contacts endpoints supplied by runtime configuration.",
        )
        self.assertNotIn("CHAT COMPLETE", reply.content)

    async def test_completion_marker_overrides_future_tense_in_a_real_answer(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()
        provider = _Provider([
            "CHAT COMPLETE:\nI'll summarize the supported execution flow below.",
        ])
        manager = ReverseAnalysisManager()
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
        ):
            reply = await manager.chat(project.id, "Summarize the execution flow")
        self.assertEqual(reply.content, "I'll summarize the supported execution flow below.")
        self.assertEqual(provider.responses, [])

    async def test_chat_retries_a_completion_marker_without_an_answer(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()
        provider = _Provider([
            "CHAT COMPLETE:",
            "CHAT COMPLETE:\nThe general flow is extraction, validation, then installation.",
        ])
        manager = ReverseAnalysisManager()
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
        ):
            reply = await manager.chat(project.id, "Explain the execution flow")
        self.assertEqual(
            reply.content,
            "The general flow is extraction, validation, then installation.",
        )
        self.assertEqual(provider.responses, [])

    def test_analyst_notes_are_tasking_in_prompt_and_echoed_in_report(self) -> None:
        prompt = ReverseAnalysisManager._system_prompt(
            ["run_cmd"], [], "Which URLs and staging endpoints are embedded?"
        )
        self.assertIn("USER NOTES: Which URLs and staging endpoints are embedded?", prompt)
        self.assertIn("## Analyst Questions", prompt)
        self.assertNotIn(
            "Analyst Questions", ReverseAnalysisManager._system_prompt(["run_cmd"], [])
        )
        helper_prompt = ReverseAnalysisManager._system_prompt(
            ["run_cmd", "write_file"], [], "Decode the custom configuration format"
        )
        self.assertIn("CUSTOM PYTHON HELPER WORKFLOW", helper_prompt)
        self.assertIn('"tool":"write_file"', helper_prompt)
        self.assertIn('"tool":"run_cmd"', helper_prompt)
        self.assertIn('"python3","/workspace/tools/inspect.py"', helper_prompt)
        self.assertIn("two separate tool turns", helper_prompt)
        self.assertIn(
            "CUSTOM PYTHON HELPER WORKFLOW",
            ReverseAnalysisManager._chat_system_prompt(),
        )

        from datetime import datetime, timezone
        project = SimpleNamespace(
            id="11111111-1111-4111-8111-111111111111", name="notes",
            analysis_note="Which URLs and staging endpoints are embedded?",
        )
        run = SimpleNamespace(
            created_at=datetime.now(timezone.utc), provider="ollama", model="m",
            image_digest=None, tool_versions={},
        )
        report = _render_report(project, run, [], "ANALYSIS COMPLETE\n\n## Findings\n\nNone.")
        self.assertIn("## Analyst Tasking", report)
        self.assertIn("Which URLs and staging endpoints are embedded?", report)
        project.analysis_note = None
        self.assertNotIn(
            "## Analyst Tasking",
            _render_report(project, run, [], "ANALYSIS COMPLETE\n\n## Findings\n\nNone."),
        )

    async def test_replay_reuses_the_original_analyst_notes(self) -> None:
        from unittest.mock import AsyncMock

        project, _artifact_id = self.project_with_artifact()
        with get_reverse_session() as db:
            row = db.get(ReverseProject, project.id)
            row.analysis_note = "Which URLs and staging endpoints are embedded?"
            db.add(ReverseRun(
                id=str(uuid.uuid4()), project_id=project.id, status="completed",
                provider="ollama", model="snapshot-model",
            ))
            db.commit()
        manager = ReverseAnalysisManager()
        with patch.object(ReverseAnalysisManager, "start", new_callable=AsyncMock) as start:
            await manager.replay(project.id)
        self.assertEqual(
            start.call_args.args[1], "Which URLs and staging endpoints are embedded?"
        )

    async def test_chat_executes_shorthand_tool_calls_instead_of_echoing_them(self) -> None:
        project, artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()
        provider = _Provider([
            json.dumps([{"run_cmd": f"strings /workspace/inputs/{artifact_id}"}]),
            "CHAT COMPLETE: The binary embeds a hardcoded staging URL.",
        ])
        manager = ReverseAnalysisManager()
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "http://stage.example", "stderr": "", "returncode": 0,
            }) as execute,
        ):
            reply = await manager.chat(project.id, "Find exposed URLs")
        execute.assert_called_once()
        self.assertEqual(execute.call_args.args[1].cmd[0], "strings")
        self.assertEqual(reply.content, "The binary embeds a hardcoded staging URL.")
        self.assertEqual(reply.metadata_json["tool_uses"], 1)

    async def test_chat_executes_argv_shorthand_shown_by_local_models(self) -> None:
        project, artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()
        provider = _Provider([
            json.dumps([{"run_cmd": ["strings", f"/workspace/inputs/{artifact_id}"]}]),
            "CHAT COMPLETE:\nNo download URL is embedded in the sample.",
        ])
        manager = ReverseAnalysisManager()
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "", "stderr": "", "returncode": 0,
            }) as execute,
        ):
            reply = await manager.chat(project.id, "Find download URLs")
        execute.assert_called_once()
        self.assertEqual(execute.call_args.args[1].cmd[0], "strings")
        self.assertEqual(reply.content, "No download URL is embedded in the sample.")

    def test_chat_history_sanitizes_legacy_protocol_artifacts(self) -> None:
        project, artifact_id = self.project_with_artifact()
        with get_reverse_session() as db:
            db.add_all([
                ReverseMessage(
                    project_id=project.id, phase="chat", role="assistant",
                    content="Grounded answer.\n\nCHAT COMPLETE:",
                ),
                ReverseMessage(
                    project_id=project.id, phase="chat", role="assistant",
                    content=json.dumps([{
                        "run_cmd": ["strings", f"/workspace/inputs/{artifact_id}"],
                    }]),
                ),
            ])
            db.commit()
        contents = [
            message["content"] for message in ReverseAnalysisManager.chat_messages(project.id)
        ]
        self.assertEqual(contents[0], "Grounded answer.")
        self.assertNotIn("run_cmd", contents[1])
        self.assertIn("stopped before reaching a final answer", contents[1])

    async def test_chat_never_stores_a_raw_tool_call_as_the_answer(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()
        denied = json.dumps([{"tool": "run_cmd", "cmd": ["curl", "http://evil.example"]}])
        provider = _Provider([denied, denied, denied])
        manager = ReverseAnalysisManager()
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.execute") as execute,
        ):
            reply = await manager.chat(project.id, "Contact the C2 server")
        execute.assert_not_called()
        self.assertNotIn("curl", reply.content)
        self.assertNotIn("{", reply.content)
        self.assertIn("stopped before reaching a final answer", reply.content)

    async def test_cancelled_chat_never_leaves_project_stuck_in_chatting(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        run = ReverseRun(
            id=str(uuid.uuid4()), project_id=project.id, status="completed",
            provider="ollama", model="snapshot-model", report_markdown="# Report",
        )
        with get_reverse_session() as db:
            db.add(run)
            db.commit()

        class _CancelledProvider:
            async def complete(self, _messages, stream=False):
                import asyncio
                raise asyncio.CancelledError()

        manager = ReverseAnalysisManager()
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=_CancelledProvider()),
        ):
            import asyncio
            with self.assertRaises(asyncio.CancelledError):
                await manager.chat(project.id, "Question interrupted by disconnect")
        with get_reverse_session() as db:
            self.assertEqual(db.get(ReverseProject, project.id).status, "completed")

    async def test_stop_cancels_a_pending_model_request_and_marks_run_stopped(self) -> None:
        import asyncio

        project, _artifact_id = self.project_with_artifact()

        class _WaitingProvider:
            def __init__(self):
                self.started = asyncio.Event()

            async def complete(self, _messages, stream=False):
                self.started.set()
                await asyncio.Event().wait()

        provider = _WaitingProvider()
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
        ):
            run = await manager.start(project.id)
            await asyncio.wait_for(provider.started.wait(), timeout=1)
            stopped = await asyncio.wait_for(manager.stop(project.id), timeout=1)
        self.assertTrue(stopped)
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "stopped")
            self.assertEqual(stored.error, "Stopped by analyst")

    async def test_transient_provider_deadline_pauses_run_for_resume(self) -> None:
        project, _artifact_id = self.project_with_artifact()

        class _DeadlineProvider:
            async def complete(self, _messages, stream=False):
                raise RuntimeError(
                    "504 DEADLINE_EXCEEDED: Deadline expired before operation could complete"
                )

        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=_DeadlineProvider()),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "stopped")
            self.assertEqual(stored.turns_used, 0)
            self.assertIn("resume the analysis", stored.error)
            self.assertIn("DEADLINE_EXCEEDED", stored.error)

    async def test_structured_summary_is_not_duplicated_in_the_report(self) -> None:
        project, artifact_id = self.project_with_artifact()
        provider = _Provider([
            file_tool(artifact_id),
            VALID_REPORT,
            IOC_RESULT,
            VERIFIER_PASS,
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "data", "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            report = db.get(ReverseRun, run.id).report_markdown
        # The structured model summary is embedded exactly once, with the
        # completion marker stripped and no duplicate "Detailed Analysis" copy.
        self.assertEqual(report.count("Static evidence is limited."), 1)
        self.assertEqual(report.count("The fixture is not a complete executable."), 1)
        self.assertNotIn("ANALYSIS COMPLETE", report)
        self.assertNotIn("## Detailed Analysis", report)
        self.assertIn("## AI-Extracted IOC Inventory", report)

    async def test_agent_completion_is_not_overridden_by_a_host_checklist(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        provider = _Provider([VALID_REPORT, IOC_RESULT, VERIFIER_PASS])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "PE32 executable", "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            rejections = list(db.query(ReverseMessage).filter(
                ReverseMessage.run_id == run.id,
                ReverseMessage.role == "system",
            ))
            self.assertFalse(any(
                (message.metadata_json or {}).get("finalization_rejected")
                for message in rejections
            ))
            self.assertEqual(db.get(ReverseRun, run.id).status, "completed")

    async def test_verifier_flags_material_issues_without_rewriting_the_report(self) -> None:
        project, artifact_id = self.project_with_artifact()
        revise = json.dumps({
            "status": "revise",
            "summary": "The draft overstates malicious intent.",
            "unsupported_claims": ["Confirmed malware"],
            "missing_evidence": [],
            "contradictions": [],
            "revision_instructions": "Use an inconclusive verdict.",
        })
        provider = _Provider([
            file_tool(artifact_id),
            VALID_REPORT.replace("Verdict: inconclusive", "Verdict: malicious"),
            IOC_RESULT,
            revise,
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "data", "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.report_verification_status, "needs_review")
            self.assertIn("Verdict: malicious", stored.report_markdown)
            checks = list(db.query(ReverseMessage).filter(
                ReverseMessage.run_id == run.id,
                ReverseMessage.phase == "verification",
            ))
            self.assertEqual([row.metadata_json["status"] for row in checks], ["revise"])

    def test_written_helper_content_is_hashed_not_copied_into_provenance(self) -> None:
        source = "import sys\nprint(open(sys.argv[1], 'rb').read(2).hex())"
        encoded = base64.b64encode(source.encode()).decode()
        call = parse_tool_call(json.dumps([{
            "tool": "write_file",
            "path": "/workspace/tools/header.py",
            "content_base64": encoded,
        }]))
        request = _tool_request_for_provenance(call)
        self.assertNotIn("content_base64", request)
        self.assertEqual(request["content_base64_size"], len(encoded.encode()))
        self.assertEqual(
            request["content_base64_sha256"], hashlib.sha256(encoded.encode()).hexdigest()
        )

    async def test_report_format_is_preserved_and_does_not_consume_analysis_turns(self) -> None:
        project, artifact_id = self.project_with_artifact()
        malformed = VALID_REPORT.replace("Confidence: low\n", "")
        provider = _Provider([
            file_tool(artifact_id),
            malformed,
            IOC_RESULT,
            VERIFIER_PASS,
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "data", "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.turns_used, 2)
            self.assertEqual(stored.report_verification_status, "verified")
            self.assertNotIn("Confidence: low", stored.report_markdown)

    async def test_markdown_completion_heading_finalizes_the_substantive_report(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        response = (
            "## Forensic Analysis Report\n\n"
            "### Findings\n\nThe sample is a signed NSIS installer with network capability.\n\n"
            "## ANALYSIS COMPLETE"
        )
        provider = _Provider([response, IOC_RESULT, VERIFIER_PASS])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.turns_used, 1)
            self.assertIn("signed NSIS installer", stored.report_markdown)
            self.assertNotIn("ANALYSIS COMPLETE", stored.report_markdown)

    async def test_bare_completion_marker_uses_the_prior_substantive_report(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        response = (
            "## Forensic Analysis Report\n\n"
            "### Findings\n\nThe available evidence supports a benign installer assessment."
        )
        provider = _Provider([response, "ANALYSIS COMPLETE", IOC_RESULT, VERIFIER_PASS])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.turns_used, 2)
            self.assertIn("benign installer assessment", stored.report_markdown)
            self.assertNotIn("ANALYSIS COMPLETE", stored.report_markdown)

    async def test_bare_completion_markers_without_a_report_request_more_turns(self) -> None:
        project, _artifact_id = self.project_with_artifact()
        provider = _Provider(["ANALYSIS COMPLETE", "ANALYSIS COMPLETE", "ANALYSIS COMPLETE"])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "awaiting_turn_approval")
            self.assertIsNone(stored.report_markdown)
            self.assertIn("stopped making progress", stored.awaiting_reason)

    async def test_three_duplicate_tool_requests_pause_instead_of_corrupting_report(self) -> None:
        project, artifact_id = self.project_with_artifact()
        request = file_tool(artifact_id)
        provider = _Provider([request, request, request, request, IOC_RESULT, VERIFIER_PASS])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "PE32 executable", "stderr": "", "returncode": 0,
            }) as execute,
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        execute.assert_called_once()
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "awaiting_turn_approval")
            self.assertEqual(stored.turns_used, 4)
            self.assertIn("stopped making progress", stored.awaiting_reason)
            self.assertIsNone(stored.report_markdown)

    async def test_oversized_prompt_echo_is_rejected_before_tool_execution(self) -> None:
        project, artifact_id = self.project_with_artifact()
        echoed = (
            file_tool(artifact_id)
            + "\nUSER: TOOL RESULTS:\n[]\nASSISTANT:\n" * 3
            + "x" * 40_000
        )
        provider = _Provider([echoed, VALID_REPORT, IOC_RESULT, VERIFIER_PASS])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute") as execute,
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        execute.assert_not_called()
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            rejected = db.query(ReverseMessage).filter(
                ReverseMessage.run_id == run.id,
                ReverseMessage.phase == "analysis",
                ReverseMessage.role == "assistant",
                ReverseMessage.id > 0,
            ).order_by(ReverseMessage.id).first()
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.turns_used, 2)
            self.assertIn("response_rejected", rejected.metadata_json)
            self.assertLess(len(rejected.content), 5000)

    async def test_turn_limit_requests_extension_instead_of_finalizing_tool_call(self) -> None:
        self.cfg.reverse.analysis_max_turns = 1
        project, artifact_id = self.project_with_artifact()
        # Some local models echo a transcript and a completion marker after a
        # tool request in the same response. The tool request must win: its
        # result has not been observed yet, so this is not a valid final report.
        provider = _Provider([
            file_tool(artifact_id)
            + "\n\nANALYSIS COMPLETE\n# Premature report embedded after the tool request",
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "PE32 executable", "stderr": "",
                "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            current_project = db.get(ReverseProject, project.id)
            events = list(db.query(ReverseProvenanceEntry).filter(
                ReverseProvenanceEntry.project_id == project.id,
            ))
            self.assertEqual(stored.status, "awaiting_turn_approval")
            self.assertEqual(current_project.status, "awaiting_turn_approval")
            self.assertEqual(stored.turns_used, stored.max_turns)
            self.assertIn("turn analysis limit", stored.awaiting_reason)
            self.assertIsNone(stored.report_markdown)
            self.assertEqual(events[-1].event_type, "analysis.extension_requested")

    async def test_discovered_overlay_rejects_basic_report_until_recursively_inspected(self) -> None:
        project, artifact_id = self.project_with_artifact()
        sample = f"/workspace/inputs/{artifact_id}"
        overlay = "/workspace/output/overlay.bin"
        premature = (
            "ANALYSIS COMPLETE\n\n# Findings\n\n"
            "The binary contains an overlay (13,312 bytes) which likely contains "
            "configuration data or secondary payloads."
        )
        final_report = VALID_REPORT.replace(
            "Static evidence is limited.",
            "The 13,312-byte overlay was extracted, classified as raw data, and inspected; "
            "its printable content contains installer metadata and no nested executable.",
        )
        provider = _Provider([
            json.dumps([{"tool": "run_cmd", "cmd": ["pecheck", sample]}]),
            json.dumps([{
                "tool": "run_cmd", "cmd": ["objdump", "-d", "--start-address=4096",
                "--stop-address=4352", sample],
            }]),
            premature,
            json.dumps([{
                "tool": "run_cmd",
                # Reproduce breaker's valid extraction shape: both paths are embedded
                # inside the source argv item rather than passed as separate operands.
                "cmd": [
                    "python3", "-c",
                    f"f=open('{sample}','rb');f.seek(56320);"
                    f"open('{overlay}','wb').write(f.read(13312))",
                ],
            }]),
            json.dumps([{"tool": "run_cmd", "cmd": ["file", overlay]}]),
            json.dumps([{"tool": "run_cmd", "cmd": ["strings", "-n", "6", overlay]}]),
            final_report,
            IOC_RESULT,
            VERIFIER_PASS,
        ])
        tool_results = [
            {
                "success": True,
                "stdout": json.dumps({
                    "overlay": {
                        "offset": 56_320,
                        "size": 13_312,
                        "sha256": "a" * 64,
                    },
                }),
                "stderr": "", "returncode": 0,
            },
            {
                "success": True,
                "stdout": "00001000 <entry>: push ebp; call 0x1040",
                "stderr": "", "returncode": 0,
            },
            {
                "success": True,
                "stdout": "",
                "stderr": "", "returncode": 0,
            },
            {
                "success": True, "stdout": "data", "stderr": "", "returncode": 0,
            },
            {
                "success": True, "stdout": "installer metadata", "stderr": "",
                "returncode": 0,
            },
        ]
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch(
                "app.reverse.analysis.sandbox_manager.execute", side_effect=tool_results
            ) as execute,
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        self.assertEqual(execute.call_count, 5)
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            rejection = db.query(ReverseMessage).filter(
                ReverseMessage.run_id == run.id,
                ReverseMessage.role == "system",
            ).filter(ReverseMessage.metadata_json.is_not(None)).all()
            rejected = [
                row for row in rejection
                if (row.metadata_json or {}).get("finalization_rejected")
            ]
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.turns_used, 7)
            self.assertIn("overlay was extracted", stored.report_markdown)
            self.assertNotIn("likely contains", stored.report_markdown)
            self.assertEqual(len(rejected), 1)
            self.assertIn("13,312-byte PE overlay", rejected[0].content)

    async def test_executable_basic_checks_cannot_replace_code_inspection(self) -> None:
        project, artifact_id = self.project_with_artifact()
        sample = f"/workspace/inputs/{artifact_id}"
        provider = _Provider([
            file_tool(artifact_id),
            VALID_REPORT,
            json.dumps([{
                "tool": "run_cmd", "cmd": [
                    "objdump", "-d", "--start-address=4096", "--stop-address=4352", sample,
                ],
            }]),
            VALID_REPORT.replace(
                "Static evidence is limited.",
                "Targeted entry-point disassembly established the initial control flow.",
            ),
            IOC_RESULT,
            VERIFIER_PASS,
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", side_effect=[
                {
                    "success": True, "stdout": "PE32 executable", "stderr": "",
                    "returncode": 0,
                },
                {
                    "success": True,
                    "stdout": "00001000 <entry>: push ebp; call 0x1040",
                    "stderr": "", "returncode": 0,
                },
            ]) as execute,
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        self.assertEqual(execute.call_count, 2)
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            rejected = db.query(ReverseMessage).filter(
                ReverseMessage.run_id == run.id,
                ReverseMessage.role == "system",
            ).all()
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.turns_used, 4)
            self.assertIn("entry-point disassembly", stored.report_markdown)
            self.assertTrue(any(
                "only reconnaissance/metadata" in row.content for row in rejected
            ))

    async def test_unresolved_overlay_at_turn_limit_requests_extension(self) -> None:
        self.cfg.reverse.analysis_max_turns = 2
        project, artifact_id = self.project_with_artifact()
        sample = f"/workspace/inputs/{artifact_id}"
        provider = _Provider([
            json.dumps([{"tool": "run_cmd", "cmd": ["pecheck", sample]}]),
            (
                "ANALYSIS COMPLETE\n\n# Findings\n\nThe 13,312-byte PE overlay may "
                "contain a secondary payload."
            ),
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True,
                "stdout": json.dumps({
                    "overlay": {"offset": "0xdc00", "size": 13_312},
                }),
                "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            rejected = db.query(ReverseMessage).filter(
                ReverseMessage.run_id == run.id,
                ReverseMessage.role == "system",
            ).all()
            self.assertEqual(stored.status, "awaiting_turn_approval")
            self.assertEqual(stored.turns_used, 2)
            self.assertIsNone(stored.report_markdown)
            self.assertIn("turn analysis limit", stored.awaiting_reason)
            self.assertTrue(any(
                (row.metadata_json or {}).get("finalization_rejected") for row in rejected
            ))

    async def test_approved_extension_resumes_same_run_and_finishes(self) -> None:
        self.cfg.reverse.analysis_max_turns = 1
        self.cfg.reverse.analysis_extension_turns = 3
        project, artifact_id = self.project_with_artifact()
        provider = _Provider([file_tool(artifact_id), VALID_REPORT, IOC_RESULT, VERIFIER_PASS])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes", return_value="signature"),
            patch("app.reverse.analysis.public_key_info", return_value={
                "algorithm": "ed25519", "public_key_pem": "public",
                "fingerprint_sha256": "f" * 64,
            }),
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "data", "stderr": "",
                "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
            resumed = await manager.approve_extension(project.id)
            await manager._tasks[project.id]
        self.assertEqual(resumed.id, run.id)
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.turns_used, 2)
            self.assertEqual(stored.max_turns, 4)
            self.assertIsNotNone(stored.report_markdown)

    async def test_verifier_failure_preserves_report_but_blocks_signing(self) -> None:
        project, artifact_id = self.project_with_artifact()
        provider = _Provider([
            file_tool(artifact_id),
            VALID_REPORT,
            IOC_RESULT,
            "This is not the required verifier JSON.",
        ])
        manager = ReverseAnalysisManager()
        active = SimpleNamespace(image_digest="image@sha256:test")
        with (
            patch("app.reverse.analysis.load_config", return_value=self.cfg),
            patch("app.reverse.analysis.get_provider", return_value=provider),
            patch("app.reverse.analysis.sign_bytes") as sign,
            patch("app.reverse.analysis.sandbox_manager.ensure", return_value=active),
            patch("app.reverse.analysis.sandbox_manager.tool_versions", return_value={}),
            patch("app.reverse.analysis.sandbox_manager.execute", return_value={
                "success": True, "stdout": "data", "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        sign.assert_not_called()
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.report_verification_status, "failed")
            self.assertEqual(stored.report_signature_status, "blocked_by_verification")
            self.assertIn("Forensic Malware Analysis Report", stored.report_markdown)


if __name__ == "__main__":
    unittest.main()
