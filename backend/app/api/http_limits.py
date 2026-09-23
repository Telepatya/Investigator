"""Browser response protection and request limits before parsing or spooling."""

import re

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.formparsers import MultiPartException

from app.config import load_config

MAX_JSON_BYTES = 1024 * 1024
MULTIPART_OVERHEAD_BYTES = 1024 * 1024
MAX_UPLOAD_REQUEST_BYTES = 1024 ** 4  # 1 TiB, including framing.
MAX_CHUNK_BYTES = 64 * 1024 * 1024
_EVIDENCE_UPLOAD = re.compile(
    r"^/api/(?:cases/[^/]+/(?:upload|upload-chunk)|reverse/projects/[^/]+/artifacts)/?$"
)


class _UploadTooLarge(MultiPartException):
    # Starlette closes every partially spooled file for this exception family.
    pass


def _upload_limit(path: str) -> int:
    if path.startswith("/api/reverse/"):
        cfg = load_config().reverse
        payload_limit = min(cfg.max_upload_bytes, cfg.max_project_bytes)
    else:
        from app.api.cases_router import MAX_CASE_BYTES, MAX_UPLOAD_BYTES

        payload_limit = min(MAX_UPLOAD_BYTES, MAX_CASE_BYTES)
        if path.rstrip("/").endswith("/upload-chunk"):
            payload_limit = min(payload_limit, MAX_CHUNK_BYTES)
    return min(max(payload_limit, 0) + MULTIPART_OVERHEAD_BYTES, MAX_UPLOAD_REQUEST_BYTES)


class HTTPBoundaryMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        upload_too_large = False

        async def protected_send(message):
            if upload_too_large:
                return  # Replace the parser's generic 400 with the precise 413.
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Frame-Options"] = "DENY"
                headers["Content-Security-Policy"] = "frame-ancestors 'none'"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
            await send(message)

        headers = Headers(scope=scope)
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        # Restrict exceptions to actual evidence routes, so changing Content-Type
        # cannot bypass the cap before FastAPI rejects an invalid JSON body.
        evidence_upload = (
            scope["method"] == "POST"
            and _EVIDENCE_UPLOAD.fullmatch(scope["path"])
            and content_type in {"multipart/form-data", "application/octet-stream"}
        )
        if not evidence_upload:
            try:
                declared_length = int(headers.get("content-length", "0"))
            except ValueError:
                declared_length = 0  # Actual bytes below remain authoritative.
            if declared_length > MAX_JSON_BYTES:
                await JSONResponse({"detail": "JSON request is too large"}, status_code=413)(scope, receive, protected_send)
                return
            data = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                if len(data) + len(chunk) > MAX_JSON_BYTES:
                    await JSONResponse({"detail": "JSON request is too large"}, status_code=413)(scope, receive, protected_send)
                    return
                data.extend(chunk)
                if not message.get("more_body", False):
                    break
            consumed = False

            async def bounded_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(data), "more_body": False}
                return await receive()

            await self.app(scope, bounded_receive, protected_send)
        else:
            limit = _upload_limit(scope["path"])
            try:
                declared_length = int(headers.get("content-length", "0"))
            except ValueError:
                declared_length = 0
            response = JSONResponse({"detail": "Upload request is too large"}, status_code=413)
            if declared_length > limit:
                await response(scope, receive, protected_send)
                return
            received_bytes = 0

            async def limited_upload_receive():
                nonlocal received_bytes, upload_too_large
                message = await receive()
                if message["type"] == "http.request":
                    received_bytes += len(message.get("body", b""))
                    if received_bytes > limit:
                        upload_too_large = True
                        raise _UploadTooLarge("Upload request is too large")
                return message

            try:
                await self.app(scope, limited_upload_receive, protected_send)
            except _UploadTooLarge:
                upload_too_large = False
                await response(scope, receive, protected_send)
                return
            if upload_too_large:
                upload_too_large = False
                await response(scope, receive, protected_send)
