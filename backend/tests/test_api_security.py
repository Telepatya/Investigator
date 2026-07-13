from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import app.config as config
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketDenialResponse


class ApiSecurityTests(unittest.TestCase):
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
        self.config_patch = patch.object(
            config,
            "load_config",
            side_effect=lambda: config.AppConfig(cases_dir=str(config.DEFAULT_CASES_DIR)),
        )
        self.config_patch.start()

        from app.api import cases_router
        from app.main import app

        self.cases_router = cases_router
        self.ingestion = AsyncMock()
        self.ingestion_patch = patch.object(
            cases_router.manager, "run_ingestion", self.ingestion,
        )
        self.ingestion_patch.start()
        self.client = TestClient(app, base_url="http://localhost")
        self.client.__enter__()

    def tearDown(self) -> None:
        from app.store.database import dispose_all_db_engines

        self.client.__exit__(None, None, None)
        self.ingestion_patch.stop()
        self.config_patch.stop()
        self.cases_router._CHUNK_UPLOADS.clear()
        dispose_all_db_engines()
        config.DEFAULT_CONFIG_DIR = self.old_config_dir
        config.DEFAULT_CASES_DIR = self.old_cases_dir
        config.CONFIG_FILE = self.old_config_file
        config.AppConfig.model_fields["cases_dir"].default = self.old_cases_default
        self.temp.cleanup()

    def create_case(self) -> str:
        response = self.client.post(
            "/api/cases", json={"name": "security test", "description": ""},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["id"]

    def uploads(self, case_id: str) -> Path:
        return config.DEFAULT_CASES_DIR / case_id / "uploads"

    def post_chunk(
        self,
        case_id: str,
        index: int,
        total: int,
        data: bytes,
        **extra_params,
    ):
        params = {
            "filename": "memory.raw",
            "chunk_index": index,
            "total_chunks": total,
            **extra_params,
        }
        return self.client.post(
            f"/api/cases/{case_id}/upload-chunk",
            params=params,
            files={"file": ("chunk", data, "application/octet-stream")},
        )

    def test_unknown_case_returns_404_without_creating_state(self) -> None:
        missing = config.DEFAULT_CASES_DIR / "deadbeef"
        response = self.client.get("/api/cases/deadbeef/events")
        self.assertEqual(response.status_code, 404)
        self.assertFalse(missing.exists())

    def test_untrusted_host_and_websocket_origins_are_rejected(self) -> None:
        response = self.client.get("/api/health", headers={"host": "evil.example"})
        self.assertEqual(response.status_code, 400)

        case_id = self.create_case()
        with self.assertRaises(WebSocketDenialResponse):
            with self.client.websocket_connect(
                f"/api/cases/{case_id}/ingestion-ws",
                headers={"origin": "https://evil.example"},
            ):
                pass
        with self.assertRaises(WebSocketDenialResponse):
            with self.client.websocket_connect(
                "/api/cases/deadbeef/ingestion-ws",
                headers={"origin": "http://localhost:8400"},
            ):
                pass

    def test_hostile_origin_cannot_mutate_or_upload(self) -> None:
        response = self.client.post(
            "/api/cases",
            headers={"origin": "https://evil.example"},
            json={"name": "blocked", "description": ""},
        )
        self.assertEqual(response.status_code, 403)

        case_id = self.create_case()
        response = self.client.post(
            f"/api/cases/{case_id}/upload",
            headers={"origin": "https://evil.example"},
            files={"file": ("cross-site.txt", b"attacker controlled", "text/plain")},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse((self.uploads(case_id) / "cross-site.txt").exists())

    def test_allowed_origin_and_non_browser_client_can_mutate(self) -> None:
        allowed = self.client.post(
            "/api/cases",
            headers={"origin": "http://localhost:8400"},
            json={"name": "browser", "description": ""},
        )
        self.assertEqual(allowed.status_code, 200)
        no_origin = self.client.post(
            "/api/cases", json={"name": "cli", "description": ""},
        )
        self.assertEqual(no_origin.status_code, 200)

    def test_case_limit_uses_projected_size_and_preserves_existing_files(self) -> None:
        case_id = self.create_case()
        uploads = self.uploads(case_id)
        (uploads / "existing.bin").write_bytes(b"12345678")
        with (
            patch.object(self.cases_router, "MAX_UPLOAD_BYTES", 100),
            patch.object(self.cases_router, "MAX_CASE_BYTES", 10),
        ):
            response = self.client.post(
                f"/api/cases/{case_id}/upload",
                files={"file": ("new.bin", b"abcde", "application/octet-stream")},
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual((uploads / "existing.bin").read_bytes(), b"12345678")
        self.assertFalse((uploads / "new.bin").exists())
        self.assertFalse(any(p.name.startswith(".investigator-upload-") for p in uploads.iterdir()))

    def test_replacement_is_atomic_and_counts_only_final_evidence(self) -> None:
        case_id = self.create_case()
        destination = self.uploads(case_id) / "same.bin"
        destination.write_bytes(b"old-data")
        with (
            patch.object(self.cases_router, "MAX_UPLOAD_BYTES", 4),
            patch.object(self.cases_router, "MAX_CASE_BYTES", 100),
        ):
            response = self.client.post(
                f"/api/cases/{case_id}/upload",
                files={"file": ("same.bin", b"12345", "application/octet-stream")},
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(destination.read_bytes(), b"old-data")

        with (
            patch.object(self.cases_router, "MAX_UPLOAD_BYTES", 100),
            patch.object(self.cases_router, "MAX_CASE_BYTES", 5),
        ):
            response = self.client.post(
                f"/api/cases/{case_id}/upload",
                files={"file": ("same.bin", b"new", "application/octet-stream")},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(destination.read_bytes(), b"new")

    def test_chunk_sequence_and_metadata_are_enforced_before_append(self) -> None:
        case_id = self.create_case()
        self.assertEqual(self.post_chunk(case_id, 0, 3, b"A").status_code, 200)

        skipped = self.post_chunk(case_id, 2, 3, b"C")
        self.assertEqual(skipped.status_code, 409)
        changed = self.post_chunk(case_id, 1, 4, b"B")
        self.assertEqual(changed.status_code, 409)

        listing = self.client.get(f"/api/cases/{case_id}/evidence").json()["files"]
        self.assertEqual(listing, [])
        self.assertEqual(self.post_chunk(case_id, 1, 3, b"B").status_code, 200)
        completed = self.post_chunk(case_id, 2, 3, b"C")
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertTrue(completed.json()["complete"])
        self.assertEqual((self.uploads(case_id) / "memory.raw").read_bytes(), b"ABC")

    def test_chunk_quota_failure_does_not_corrupt_accepted_prefix(self) -> None:
        case_id = self.create_case()
        uploads = self.uploads(case_id)
        (uploads / "other.bin").write_bytes(b"12345678")
        with (
            patch.object(self.cases_router, "MAX_UPLOAD_BYTES", 100),
            patch.object(self.cases_router, "MAX_CASE_BYTES", 10),
        ):
            self.assertEqual(self.post_chunk(case_id, 0, 2, b"AB").status_code, 200)
            rejected = self.post_chunk(case_id, 1, 2, b"C")
            self.assertEqual(rejected.status_code, 413)
            (uploads / "other.bin").unlink()
            accepted = self.post_chunk(case_id, 1, 2, b"C")
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual((uploads / "memory.raw").read_bytes(), b"ABC")


if __name__ == "__main__":
    unittest.main()
