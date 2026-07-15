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
                "success": True, "stdout": "PE32 executable", "stderr": "", "returncode": 0,
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
            self.assertIn("PE32 executable", tool_messages[0].content)
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
                "success": True, "stdout": "PE32 executable", "stderr": "", "returncode": 0,
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
                "success": True, "stdout": "PE32 executable", "stderr": "", "returncode": 0,
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
                "success": True, "stdout": "PE32 executable", "stderr": "", "returncode": 0,
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
                "success": True, "stdout": "PE32 executable", "stderr": "", "returncode": 0,
            }),
        ):
            run = await manager.start(project.id)
            await manager._tasks[project.id]
        with get_reverse_session() as db:
            stored = db.get(ReverseRun, run.id)
            self.assertEqual(stored.turns_used, 2)
            self.assertEqual(stored.report_verification_status, "verified")
            self.assertNotIn("Confidence: low", stored.report_markdown)

    async def test_three_duplicate_tool_requests_stop_churn_and_finalize(self) -> None:
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
            self.assertEqual(stored.status, "completed")
            self.assertEqual(stored.turns_used, 4)
            self.assertIsNone(stored.awaiting_reason)

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
                "success": True, "stdout": "PE32 executable", "stderr": "", "returncode": 0,
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
