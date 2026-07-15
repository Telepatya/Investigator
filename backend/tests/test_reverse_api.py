from __future__ import annotations

import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
