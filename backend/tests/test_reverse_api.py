from __future__ import annotations

import tempfile
import json
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import app.config as config
from fastapi.testclient import TestClient


class ReverseApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_config_dir = config.DEFAULT_CONFIG_DIR
        self.old_cases_dir = config.DEFAULT_CASES_DIR
        self.old_config_file = config.CONFIG_FILE
        self.old_cases_default = config.AppConfig.model_fields["cases_dir"].default
        config.DEFAULT_CONFIG_DIR = self.root
        config.DEFAULT_CASES_DIR = self.root / "cases"
        config.CONFIG_FILE = self.root / "config.json"
        config.AppConfig.model_fields["cases_dir"].default = str(config.DEFAULT_CASES_DIR)
        self.cfg = config.AppConfig(cases_dir=str(config.DEFAULT_CASES_DIR))
        self.config_patch = patch.object(config, "load_config", side_effect=lambda: self.cfg)
        self.config_patch.start()

        from app.main import app
        from app.reverse import router as reverse_router
        from app.reverse.sandbox import sandbox_manager

        self.router_config_patch = patch.object(reverse_router, "load_config", side_effect=lambda: self.cfg)
        self.router_config_patch.start()
        self.health_patch = patch.object(sandbox_manager, "health", return_value={
            "docker_available": False,
            "image_available": False,
            "image": self.cfg.reverse.sandbox_image,
            "image_digest": None,
            "message": "Docker unavailable in test",
        })
        self.health_patch.start()
        self.client = TestClient(app, base_url="http://localhost")
        self.client.__enter__()

    def tearDown(self) -> None:
        from app.reverse.database import dispose_reverse_db
        from app.store.database import dispose_all_db_engines

        self.client.__exit__(None, None, None)
        self.health_patch.stop()
        self.router_config_patch.stop()
        self.config_patch.stop()
        dispose_reverse_db()
        dispose_all_db_engines()
        config.DEFAULT_CONFIG_DIR = self.old_config_dir
        config.DEFAULT_CASES_DIR = self.old_cases_dir
        config.CONFIG_FILE = self.old_config_file
        config.AppConfig.model_fields["cases_dir"].default = self.old_cases_default
        self.temp.cleanup()

    def create_project(self, **extra) -> dict:
        response = self.client.post(
            "/api/reverse/projects",
            json={"name": "sample", "description": "test", **extra},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_project_upload_trace_and_download(self) -> None:
        project = self.create_project()
        response = self.client.post(
            f"/api/reverse/projects/{project['id']}/artifacts",
            files={"file": ("..\\sample.exe", b"MZ-static", "application/octet-stream")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        artifact = response.json()
        self.assertEqual(artifact["name"], "sample.exe")
        self.assertEqual(artifact["file_size"], 9)

        download = self.client.get(
            f"/api/reverse/projects/{project['id']}/artifacts/{artifact['id']}/download"
        )
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.content, b"MZ-static")
        trace = self.client.get(f"/api/reverse/projects/{project['id']}/trace")
        self.assertEqual(trace.status_code, 200)
        self.assertEqual(trace.json()[0]["event_type"], "artifact.uploaded")
        verified = self.client.get(f"/api/reverse/projects/{project['id']}/trace/verify")
        self.assertEqual(verified.json()["valid"], True)

    def test_upload_limit_is_streamed_and_partial_file_is_removed(self) -> None:
        project = self.create_project()
        self.cfg.reverse.max_upload_bytes = 4
        response = self.client.post(
            f"/api/reverse/projects/{project['id']}/artifacts",
            files={"file": ("large.exe", b"12345", "application/octet-stream")},
        )
        self.assertEqual(response.status_code, 413)
        project_root = self.root / "reverse" / "projects" / project["id"]
        self.assertEqual(list((project_root / "uploads").iterdir()), [])
        self.assertEqual(list((project_root / "staging").iterdir()), [])

    def test_case_deletion_preserves_and_unlinks_reverse_project(self) -> None:
        case = self.client.post("/api/cases", json={"name": "case", "description": ""}).json()
        project = self.create_project(linked_case_id=case["id"])
        response = self.client.delete(f"/api/cases/{case['id']}")
        self.assertEqual(response.status_code, 200, response.text)
        retained = self.client.get(f"/api/reverse/projects/{project['id']}").json()
        self.assertIsNone(retained["linked_case_id"])

    def test_hostile_origin_cannot_create_reverse_state(self) -> None:
        response = self.client.post(
            "/api/reverse/projects",
            headers={"origin": "https://evil.example"},
            json={"name": "blocked"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get("/api/reverse/projects").json(), [])

    def test_project_tool_approvals_are_limited_to_configured_registry(self) -> None:
        project = self.create_project()
        path = f"/api/reverse/projects/{project['id']}/tools"
        policy = self.client.get(path)
        self.assertEqual(policy.status_code, 200, policy.text)
        self.assertIn("run_cmd", policy.json()["enabled_tools"])
        changed = self.client.put(path, json={"enabled_tools": ["run_cmd", "read_file"]})
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(changed.json()["enabled_tools"], ["run_cmd", "read_file"])
        rejected = self.client.put(path, json={"enabled_tools": ["shell"]})
        self.assertEqual(rejected.status_code, 400, rejected.text)
        self.assertEqual(self.client.get(path).json()["enabled_tools"], ["run_cmd", "read_file"])

    def test_process_reverse_handoff_endpoint_returns_ready_workspace(self) -> None:
        case = self.client.post("/api/cases", json={"name": "memory", "description": ""}).json()
        response_payload = {
            "project_id": "11111111-1111-4111-8111-111111111111",
            "status": "ready",
            "artifact_ids": ["a", "b", "c", "d"],
        }
        with patch(
            "app.api.cases_router.handoff_process_to_reverse", return_value=response_payload
        ) as handoff:
            response = self.client.post(
                f"/api/cases/{case['id']}/memory/mem-dump/processes/2244/reverse"
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), response_payload)
        handoff.assert_called_once_with(case["id"], "mem-dump", 2244)

    def test_analysis_status_uses_terminal_run_as_authoritative_state(self) -> None:
        from app.reverse.database import ReverseProject, ReverseRun, get_reverse_session

        project = self.create_project()
        run_id = str(uuid.uuid4())
        with get_reverse_session() as db:
            row = db.get(ReverseProject, project["id"])
            row.status = "awaiting_turn_approval"
            row.active_run_id = run_id
            db.add(ReverseRun(
                id=run_id,
                project_id=project["id"],
                status="completed",
                provider="test",
                model="test",
                report_markdown="# Complete",
            ))
            db.commit()
        response = self.client.get(
            f"/api/reverse/projects/{project['id']}/analysis/status"
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "completed")
        self.assertEqual(response.json()["run"]["status"], "completed")

    def test_trace_evidence_is_project_scoped_and_returns_retained_output(self) -> None:
        from app.reverse.database import (
            ReverseMessage,
            ReverseRun,
            get_reverse_session,
        )

        project = self.create_project()
        other = self.create_project(name="other")
        run_id = str(uuid.uuid4())
        with get_reverse_session() as db:
            db.add(ReverseRun(
                id=run_id,
                project_id=project["id"],
                status="running",
                provider="test",
                model="test",
            ))
            message = ReverseMessage(
                project_id=project["id"],
                run_id=run_id,
                phase="analysis",
                role="tool",
                content=json.dumps([{
                    "success": True,
                    "stdout": "PE32 executable",
                    "stderr": "",
                    "returncode": 0,
                    "output_truncated": True,
                }]),
                metadata_json={"tool": "run_cmd", "target": ["file", "/workspace/input"]},
            )
            db.add(message)
            failed = ReverseMessage(
                project_id=project["id"],
                run_id=run_id,
                phase="analysis",
                role="tool",
                content=json.dumps([{
                    "success": False,
                    "stdout": "",
                    "stderr": "unsupported format",
                    "returncode": 2,
                }]),
                metadata_json={"tool": "run_cmd", "target": ["parser", "/workspace/input"]},
            )
            db.add(failed)
            db.commit()
            db.refresh(message)
            db.refresh(failed)
            message_id = message.id
            failed_id = failed.id

        response = self.client.get(
            f"/api/reverse/projects/{project['id']}/evidence/{message_id}"
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["stdout"], "PE32 executable")
        self.assertTrue(response.json()["output_truncated"])
        self.assertEqual(len(response.json()["output_sha256"]), 64)
        failed_response = self.client.get(
            f"/api/reverse/projects/{project['id']}/evidence/{failed_id}"
        )
        self.assertEqual(failed_response.status_code, 200, failed_response.text)
        self.assertFalse(failed_response.json()["success"])
        self.assertEqual(failed_response.json()["stderr"], "unsupported format")
        missing = self.client.get(
            f"/api/reverse/projects/{project['id']}/evidence/999999"
        )
        self.assertEqual(missing.status_code, 404)
        cross_project = self.client.get(
            f"/api/reverse/projects/{other['id']}/evidence/{message_id}"
        )
        self.assertEqual(cross_project.status_code, 404)

    def test_legacy_review_values_are_normalized_and_history_is_exposed(self) -> None:
        from app.reverse.database import (
            ReverseMessage,
            ReverseProject,
            ReverseRun,
            get_reverse_session,
        )

        project = self.create_project()
        run_id = str(uuid.uuid4())
        with get_reverse_session() as db:
            project_row = db.get(ReverseProject, project["id"])
            project_row.status = "completed"
            project_row.active_run_id = run_id
            db.add(ReverseRun(
                id=run_id,
                project_id=project["id"],
                status="completed",
                provider="test",
                model="test",
                report_markdown="# Historical report",
                report_verification_status="needs_review",
            ))
            db.add(ReverseMessage(
                project_id=project["id"],
                run_id=run_id,
                phase="verification",
                role="assistant",
                content="Legacy warning",
                metadata_json={"status": "revise", "pass_number": 1},
            ))
            db.commit()

        status = self.client.get(
            f"/api/reverse/projects/{project['id']}/analysis/status"
        )
        self.assertEqual(status.status_code, 200, status.text)
        self.assertEqual(
            status.json()["run"]["report_verification_status"],
            "passed_with_warnings",
        )
        self.assertEqual(status.json()["run"]["analysis_outcome"], "legacy")
        self.assertTrue(status.json()["can_continue_investigation"])
        report = self.client.get(f"/api/reverse/projects/{project['id']}/report")
        self.assertEqual(report.status_code, 200, report.text)
        self.assertEqual(report.json()["verification_status"], "passed_with_warnings")
        self.assertEqual(report.json()["review_history"][0]["pass_number"], 1)


if __name__ == "__main__":
    unittest.main()
