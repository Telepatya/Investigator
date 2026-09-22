from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api import analysis_router, cases_router, settings_router
from app.api.http_limits import HTTPBoundaryMiddleware, MAX_JSON_BYTES
from app.api import http_limits
from app.config import AppConfig


class RequestBoundaryTests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        app.include_router(cases_router.router)
        app.include_router(analysis_router.router)
        app.include_router(settings_router.router)
        app.add_middleware(HTTPBoundaryMiddleware)

        @app.get("/")
        def index():
            return HTMLResponse('<div id="root"></div><script src="/assets/app.js"></script>')

        self.client = TestClient(app)

    def test_json_total_bound_including_unlabelled_and_chunked_input(self):
        with patch.object(cases_router.case_store, "create_case") as create:
            for headers in ({"content-type": "application/json"}, {}, {"content-type": "text/plain"}, {"content-type": "multipart/form-data"}):
                response = self.client.post("/api/cases", content=(b'{"name":"' + b"x" * MAX_JSON_BYTES + b'"}'), headers=headers)
                self.assertEqual(response.status_code, 413)
            response = self.client.post("/api/cases", content=iter([b" " * (MAX_JSON_BYTES // 2)] * 3), headers={"content-type": "application/json"})
            self.assertEqual(response.status_code, 413)
            create.assert_not_called()

    def test_negative_or_excessive_pagination_rejected_before_database(self):
        with patch.object(cases_router.case_store, "get_session") as session, patch.object(cases_router.case_store, "get_case") as get_case:
            for path, params in (("entities", {"max_nodes": -1}), ("entities", {"max_nodes": 5001}), ("events", {"limit": -1}), ("events", {"limit": 5001}), ("events", {"offset": -1}), ("timeline", {"limit": -1}), ("timeline", {"limit": 10001}), ("events", {"q": "a" * 1025}), ("memory/mem-test/processes/1/handles", {"limit": -1})):
                response = self.client.get(f"/api/cases/deadbeef/{path}", params=params)
                self.assertEqual(response.status_code, 422, response.text)
            session.assert_not_called()
            get_case.assert_not_called()

    def test_field_types_and_lengths_are_rejected_before_side_effects(self):
        with patch.object(settings_router, "load_config") as load, patch.object(settings_router, "save_api_key") as key, patch.object(cases_router.case_store, "get_session") as session:
            for path, data in (("/api/settings/llm", {"max_tokens": -1}), ("/api/settings/llm", {"max_tokens": 131073}), ("/api/settings/llm", {"temperature": 9}), ("/api/settings/llm/key/openrouter", {"api_key": {"nested": "value"}}), ("/api/cases/deadbeef/rules/disable", {"rule_id": "test", "disabled": "false"}), ("/api/cases/deadbeef/findings/1/benign", {"benign": []})):
                method = self.client.put if path == "/api/settings/llm" else self.client.post
                response = method(path, json=data)
                self.assertEqual(response.status_code, 422, response.text)
            load.assert_not_called()
            key.assert_not_called()
            session.assert_not_called()

    def test_valid_timeline_zero_limit_reaches_query_for_facets(self):
        # Existing UI deliberately asks for zero events while loading facets.
        with patch.object(cases_router.case_store, "get_session", side_effect=RuntimeError("query reached")):
            with self.assertRaisesRegex(RuntimeError, "query reached"):
                self.client.get("/api/cases/deadbeef/timeline?limit=0")

    def test_frame_headers_cover_html_and_denied_responses_without_blocking_assets(self):
        for response in (self.client.get("/"), self.client.get("/missing"), self.client.put("/api/settings/llm", json={"max_tokens": -1})):
            self.assertEqual(response.headers["x-frame-options"], "DENY")
            self.assertEqual(response.headers["content-security-policy"], "frame-ancestors 'none'")
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertIn('src="/assets/app.js"', self.client.get("/").text)

    def test_websocket_invalid_messages_do_not_invoke_model_and_connection_recovers(self):
        async def stream(*_args):
            yield "synthetic response"

        with patch.object(analysis_router, "authorize_ws", AsyncMock(return_value=True)), patch.object(analysis_router, "chat_stream", side_effect=stream) as chat:
            with self.client.websocket_connect("/api/cases/deadbeef/chat-ws") as ws:
                for data in ([], {"message": ["invalid"], "chat_id": "test"}, {"message": "x" * 32001, "chat_id": "test"}):
                    ws.send_json(data)
                    self.assertEqual(ws.receive_json()["type"], "error")
                chat.assert_not_called()
                ws.send_json({"message": "hello", "chat_id": "test"})
                self.assertEqual(ws.receive_json()["type"], "start")
                self.assertEqual(ws.receive_json()["content"], "synthetic response")
                self.assertEqual(ws.receive_json()["type"], "done")
                chat.assert_called_once_with("deadbeef", "test", "hello")

    def test_websocket_oversize_message_closes_without_model_call(self):
        with patch.object(analysis_router, "authorize_ws", AsyncMock(return_value=True)), patch.object(analysis_router, "chat_stream") as chat:
            with self.client.websocket_connect("/api/cases/deadbeef/chat-ws") as ws:
                ws.send_text(" " * 131073)
                with self.assertRaises(WebSocketDisconnect) as closed:
                    ws.receive_json()
                self.assertEqual(closed.exception.code, 1009)
            chat.assert_not_called()


class UploadStreamBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def _request(self, path, chunks, headers=()):
        app = FastAPI()
        handled = []

        @app.post(path)
        async def upload(file: UploadFile):
            handled.append(await file.read())
            return {"ok": True}

        messages = iter([
            {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
            for index, chunk in enumerate(chunks)
        ])
        sent = []
        received = []

        async def receive():
            message = next(messages)
            received.append(message)
            return message

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": "POST", "scheme": "http", "path": path, "raw_path": path.encode(),
                 "query_string": b"", "root_path": "", "server": ("test", 80),
                 "client": ("test", 1234), "headers": [
                     (b"content-type", b"multipart/form-data; boundary=test-boundary"), *headers]}
        await HTTPBoundaryMiddleware(app)(scope, receive, send)
        return sent[0]["status"], handled, received

    async def test_streamed_multipart_is_counted_before_spooling_and_closes_partial_files(self):
        from starlette import formparsers
        original_spool = formparsers.SpooledTemporaryFile
        spools = []

        def track_spool(*args, **kwargs):
            spool = original_spool(*args, **kwargs)
            spools.append(spool)
            return spool

        prefix = b'--test-boundary\r\nContent-Disposition: form-data; name="file"; filename="memory.raw"\r\n\r\n'
        chunks = [prefix + b"x" * 600, b"x" * 600 + b"\r\n--test-boundary--\r\n"]
        for path in ("/api/cases/deadbeef/upload", "/api/cases/deadbeef/upload-chunk", "/api/reverse/projects/example/artifacts"):
            for headers in ((), ((b"content-length", b"1"),)):
                with self.subTest(path=path, headers=headers), patch.object(http_limits, "_upload_limit", return_value=1024), patch.object(formparsers, "SpooledTemporaryFile", side_effect=track_spool):
                    status, handled, received = await self._request(path, chunks, headers)
                    self.assertEqual(status, 413)
                    self.assertEqual(handled, [])
                    self.assertEqual(len(received), 2)
                    self.assertTrue(spools[-1].closed)

    async def test_declared_oversize_never_reads_or_spools(self):
        with patch.object(http_limits, "_upload_limit", return_value=1024), patch("starlette.formparsers.SpooledTemporaryFile") as spool:
            status, handled, received = await self._request("/api/cases/deadbeef/upload", [b"unused"], ((b"content-length", b"1025"),))
            self.assertEqual(status, 413)
            self.assertEqual(handled, [])
            self.assertEqual(received, [])
            spool.assert_not_called()

    async def test_legitimate_multipart_reaches_handler_without_buffering_entire_request(self):
        chunks = [b'--test-boundary\r\nContent-Disposition: form-data; name="file"; filename="memory.raw"\r\n\r\n', b"synthetic", b"\r\n--test-boundary--\r\n"]
        with patch.object(http_limits, "_upload_limit", return_value=1024):
            status, handled, received = await self._request("/api/cases/deadbeef/upload", chunks)
        self.assertEqual(status, 200)
        self.assertEqual(handled, [b"synthetic"])
        self.assertEqual([message["body"] for message in received], chunks)

    def test_route_limits_preserve_large_uploads_and_bound_chunks_and_configuration(self):
        cfg = AppConfig()
        cfg.reverse.max_upload_bytes = 8 * 1024 ** 3
        overhead = http_limits.MULTIPART_OVERHEAD_BYTES
        with patch.object(http_limits, "load_config", return_value=cfg), patch.object(cases_router, "MAX_UPLOAD_BYTES", 128 * 1024 ** 3), patch.object(cases_router, "MAX_CASE_BYTES", 256 * 1024 ** 3):
            self.assertEqual(http_limits._upload_limit("/api/cases/deadbeef/upload"), 128 * 1024 ** 3 + overhead)
            self.assertEqual(http_limits._upload_limit("/api/cases/deadbeef/upload-chunk"), http_limits.MAX_CHUNK_BYTES + overhead)
            self.assertEqual(http_limits._upload_limit("/api/reverse/projects/example/artifacts"), 8 * 1024 ** 3 + overhead)
        with patch.object(cases_router, "MAX_UPLOAD_BYTES", 4 * 1024 ** 4), patch.object(cases_router, "MAX_CASE_BYTES", 4 * 1024 ** 4):
            self.assertEqual(http_limits._upload_limit("/api/cases/deadbeef/upload"), http_limits.MAX_UPLOAD_REQUEST_BYTES)
