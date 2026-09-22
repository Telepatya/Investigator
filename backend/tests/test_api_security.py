from __future__ import annotations

import asyncio
import io
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import app.config as config
from fastapi import HTTPException
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
        self.cases_router.manager._detections_pending.clear()
        self.cases_router.manager._full_rebuild_pending.clear()
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

    def wait_for(self, predicate, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("Timed out waiting for background replacement")
            time.sleep(0.01)

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

    def test_actual_app_headers_cover_spa_and_host_origin_denials(self) -> None:
        responses = [
            self.client.get("/"),
            self.client.get("/api/cases"),
            self.client.get("/", headers={"Host": "untrusted.example.invalid"}),
            self.client.post("/api/cases", json={"name": "blocked"}, headers={"Origin": "https://untrusted.example.invalid"}),
        ]
        for response in responses:
            self.assertEqual(response.headers["x-frame-options"], "DENY")
            self.assertEqual(response.headers["content-security-policy"], "frame-ancestors 'none'")
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertEqual(responses[2].status_code, 400)
        self.assertEqual(responses[3].status_code, 403)

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
        self.wait_for(lambda: destination.read_bytes() == b"new")
        self.assertEqual(destination.read_bytes(), b"new")

    def test_replacement_purges_prior_generation_rows(self) -> None:
        from app.store.database import Event, Finding, Process

        case_id = self.create_case()
        destination = self.uploads(case_id) / "same.json"
        destination.write_text('{"old": true}', encoding="utf-8")
        session = self.cases_router.case_store.get_session(case_id)
        try:
            session.info["upload_name"] = "same.json"
            self.cases_router.case_store.add_event(session,
                source="same.json", upload_name="same.json", category="test",
                summary="stale event", raw={}, severity="info",
            )
            session.add(Process(
                pid=10, name="stale.exe", session_id="old", upload_name="same.json",
            ))
            session.add(Finding(
                title="stale finding", description="old", severity="low",
                mitre_techniques=[], evidence={}, source="test",
            ))
            session.commit()
        finally:
            session.close()

        response = self.client.post(
            f"/api/cases/{case_id}/upload",
            files={"file": ("same.json", b'{"new": true}', "application/json")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.wait_for(lambda: destination.read_bytes() == b'{"new": true}')
        session = self.cases_router.case_store.get_session(case_id)
        try:
            self.assertEqual(session.query(Event).count(), 0)
            self.assertEqual(session.query(Process).count(), 0)
            # Prior findings remain available until the scheduled atomic full
            # rebuild succeeds, so a parser failure cannot erase unrelated
            # detection results.
            self.assertEqual(session.query(Finding).count(), 1)
        finally:
            session.close()
        self.ingestion.assert_awaited()
        self.assertIn(case_id, self.cases_router.manager._full_rebuild_pending)

    def test_replacement_setup_failure_preserves_original_file_and_rows(self) -> None:
        from app.store.database import Event

        case_id = self.create_case()
        destination = self.uploads(case_id) / "same.json"
        destination.write_bytes(b"old")
        session = self.cases_router.case_store.get_session(case_id)
        try:
            session.info["upload_name"] = "same.json"
            self.cases_router.case_store.add_event(session,
                source="same.json", upload_name="same.json", category="test",
                summary="preserved", raw={}, severity="info",
            )
            session.commit()
        finally:
            session.close()

        def fail_schedule(coroutine):
            coroutine.close()
            raise RuntimeError("closed loop")

        with patch.object(self.cases_router, "_schedule_background", side_effect=fail_schedule):
            response = self.client.post(
                f"/api/cases/{case_id}/upload",
                files={"file": ("same.json", b"new", "application/json")},
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(destination.read_bytes(), b"old")
        self.assertFalse(any(
            path.name.startswith(".investigator-upload-")
            for path in destination.parent.iterdir()
        ))
        session = self.cases_router.case_store.get_session(case_id)
        try:
            self.assertEqual(session.query(Event).count(), 1)
        finally:
            session.close()

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

    def test_completed_chunk_replacement_purges_prior_memory_rows(self) -> None:
        from app.store.database import Event, MemoryResult, Process

        case_id = self.create_case()
        destination = self.uploads(case_id) / "memory.raw"
        destination.write_bytes(b"OLD")
        session = self.cases_router.case_store.get_session(case_id)
        try:
            session.info["upload_name"] = "memory.raw"
            self.cases_router.case_store.add_event(session,
                source="memory:test", upload_name="memory.raw", category="memory",
                summary="stale event", raw={}, severity="info",
            )
            session.add(Process(
                pid=4, name="System", session_id="mem-old", upload_name="memory.raw",
            ))
            session.add(MemoryResult(
                upload_name="memory.raw", plugin="test", summary="stale result",
            ))
            session.commit()
        finally:
            session.close()

        response = self.post_chunk(case_id, 0, 1, b"NEW")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["complete"])
        self.wait_for(lambda: destination.read_bytes() == b"NEW")
        session = self.cases_router.case_store.get_session(case_id)
        try:
            for model in (Event, Process, MemoryResult):
                self.assertEqual(session.query(model).count(), 0)
        finally:
            session.close()


class ReplacementCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
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

        self.router = cases_router
        self.case_id = cases_router.case_store.create_case("cancellation test")["id"]
        self.uploads = config.DEFAULT_CASES_DIR / self.case_id / "uploads"

    async def asyncTearDown(self) -> None:
        from app.store.database import dispose_all_db_engines

        self.router._CHUNK_UPLOADS.clear()
        self.router.manager._detections_pending.discard(self.case_id)
        self.router.manager._full_rebuild_pending.discard(self.case_id)
        dispose_all_db_engines()
        self.config_patch.stop()
        config.DEFAULT_CONFIG_DIR = self.old_config_dir
        config.DEFAULT_CASES_DIR = self.old_cases_dir
        config.CONFIG_FILE = self.old_config_file
        config.AppConfig.model_fields["cases_dir"].default = self.old_cases_default
        self.temp.cleanup()

    def _seed_event(self, upload_name: str) -> None:
        session = self.router.case_store.get_session(self.case_id)
        try:
            session.info["upload_name"] = upload_name
            self.router.case_store.add_event(
                session,
                source=upload_name,
                category="test",
                summary="old generation",
                raw={},
                severity="info",
            )
            session.commit()
        finally:
            session.close()

    async def _cancel_mid_replacement(self, route_coroutine, destination: Path) -> None:
        from app.store.database import Event

        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        ingestion_entered = asyncio.Event()
        original = self.router.evidence_store.replace_file_data

        def blocking_replacement(*args):
            entered.set()
            if not release.wait(timeout=2):
                raise TimeoutError("test did not release replacement worker")
            result = original(*args)
            finished.set()
            return result

        async def observe_ingestion(*_args, **_kwargs):
            self.assertTrue(finished.is_set())
            ingestion_entered.set()

        with (
            patch.object(
                self.router.evidence_store,
                "replace_file_data",
                side_effect=blocking_replacement,
            ),
            patch.object(
                self.router.manager,
                "_run_ingestion_locked",
                side_effect=observe_ingestion,
            ),
        ):
            request_task = asyncio.create_task(route_coroutine)
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            request_task.cancel()
            await asyncio.sleep(0.05)
            self.assertFalse(request_task.done())
            self.assertFalse(ingestion_entered.is_set())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await request_task
            await asyncio.wait_for(ingestion_entered.wait(), 1)
            await asyncio.sleep(0)

        self.assertTrue(finished.is_set())
        session = self.router.case_store.get_session(self.case_id)
        try:
            self.assertEqual(session.query(Event).count(), 0)
        finally:
            session.close()
        self.assertFalse(any(
            path.name.startswith(".investigator-upload-")
            for path in self.uploads.iterdir()
        ))

    async def _assert_failed_replacement_preserves_prior_detection(
        self,
        route_coroutine,
        destination: Path,
    ) -> None:
        self.router.manager._detections_pending.add(self.case_id)
        with (
            patch.object(
                self.router.evidence_store,
                "replace_file_data",
                side_effect=RuntimeError("swap failed"),
            ),
            self.assertRaises(HTTPException) as caught,
        ):
            await route_coroutine

        self.assertEqual(caught.exception.status_code, 500)
        self.assertEqual(destination.read_bytes(), b"old")
        self.assertIn(self.case_id, self.router.manager._detections_pending)
        self.assertNotIn(self.case_id, self.router.manager._full_rebuild_pending)

    async def test_regular_replacement_failure_preserves_prior_detection(self) -> None:
        from starlette.datastructures import UploadFile

        destination = self.uploads / "failed.json"
        destination.write_bytes(b"old")
        self._seed_event(destination.name)
        upload = UploadFile(filename=destination.name, file=io.BytesIO(b"new"))
        await self._assert_failed_replacement_preserves_prior_detection(
            self.router.upload_file(self.case_id, upload),
            destination,
        )

    async def test_chunk_replacement_failure_preserves_prior_detection(self) -> None:
        from starlette.datastructures import UploadFile

        destination = self.uploads / "failed.raw"
        destination.write_bytes(b"old")
        self._seed_event(destination.name)
        upload = UploadFile(filename="chunk", file=io.BytesIO(b"new"))
        await self._assert_failed_replacement_preserves_prior_detection(
            self.router.upload_chunk(
                self.case_id,
                upload,
                destination.name,
                0,
                1,
            ),
            destination,
        )
        self.assertNotIn((self.case_id, destination.name), self.router._CHUNK_UPLOADS)

    async def test_regular_replacement_cancellation_waits_for_worker(self) -> None:
        from starlette.datastructures import UploadFile

        destination = self.uploads / "same.json"
        destination.write_bytes(b"old")
        self._seed_event(destination.name)
        upload = UploadFile(filename=destination.name, file=io.BytesIO(b"new"))
        await self._cancel_mid_replacement(
            self.router.upload_file(self.case_id, upload),
            destination,
        )
        self.assertEqual(destination.read_bytes(), b"new")

    async def test_final_chunk_replacement_cancellation_waits_for_worker(self) -> None:
        from starlette.datastructures import UploadFile

        destination = self.uploads / "memory.raw"
        destination.write_bytes(b"OLD")
        self._seed_event(destination.name)
        upload = UploadFile(filename="chunk", file=io.BytesIO(b"NEW"))
        await self._cancel_mid_replacement(
            self.router.upload_chunk(
                self.case_id,
                upload,
                destination.name,
                0,
                1,
            ),
            destination,
        )
        self.assertEqual(destination.read_bytes(), b"NEW")
        self.assertNotIn((self.case_id, destination.name), self.router._CHUNK_UPLOADS)


if __name__ == "__main__":
    unittest.main()
