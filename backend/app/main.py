"""Investigator DFIR backend entrypoint."""

from __future__ import annotations

import os
from pathlib import Path
import logging
import asyncio

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import analysis_router, cases_router, settings_router
from app.api.http_limits import HTTPBoundaryMiddleware
from app.api.security import allowed_hosts, allowed_origins, authorize_http
from app.auth.config import get_auth_config
from app.auth.middleware import AuthMiddleware
from app.auth.router import router as auth_router
from app.auth.session import sync_auth_policy, sync_auth_policy_if_store_exists
from app.config import ensure_dirs
from app.store.cases import (
    CaseNotFoundError,
    cleanup_orphan_case_dirs,
    cleanup_stale_case_artifacts,
    recover_interrupted_case_operations,
)
from app.store.database import dispose_all_db_engines
from app.reverse.analysis import analysis_manager
from app.reverse.database import dispose_reverse_db, init_reverse_db
from app.reverse.router import router as reverse_router
from app.reverse.sandbox import sandbox_manager
from app.rules.database import dispose_rules_db
from app.rules.router import router as rules_router
from app.reverse.store import (
    cleanup_staging_files,
    recover_interrupted_chats,
    recover_interrupted_runs,
    repair_case_links,
)

logger = logging.getLogger(__name__)

APP_TITLE = "Investigator DFIR"
APP_VERSION = "0.1.0"
APP_RELEASE_CHANNEL = "public-beta"
APP_RELEASE_LABEL = "Public Beta"
APP_CREDIT = "Made by Roei.f"


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_dirs()
    auth_config = get_auth_config()
    if auth_config.enabled:
        sync_auth_policy(auth_config.policy_fingerprint)
    else:
        sync_auth_policy_if_store_exists(auth_config.policy_fingerprint)
    init_reverse_db()
    for run_id in recover_interrupted_runs():
        logger.warning("Recovered interrupted Reverse run %s", run_id)
    for project_id in recover_interrupted_chats():
        logger.warning("Recovered interrupted Reverse chat state for project %s", project_id)
    for project_id in repair_case_links():
        logger.warning("Cleared stale case link for Reverse project %s", project_id)
    cleanup_staging_files()
    for case_id in recover_interrupted_case_operations():
        logger.warning("Recovered interrupted operation state for case %s", case_id)
    for result in cleanup_orphan_case_dirs():
        if result.get("status") == "failed":
            logger.warning(
                "Failed to remove orphan case directory %s: %s",
                result.get("case_id"),
                result.get("error"),
            )
        else:
            logger.info("Removed orphan case directory %s", result.get("case_id"))
    for result in cleanup_stale_case_artifacts():
        if result.get("status") == "failed":
            logger.warning(
                "Failed to remove stale case artifact %s for case %s: %s",
                result.get("path"),
                result.get("case_id"),
                result.get("error"),
            )
        else:
            logger.info(
                "Removed stale case artifact %s for case %s",
                result.get("path"),
                result.get("case_id"),
            )
    async def _reverse_cleanup_loop() -> None:
        while True:
            await asyncio.sleep(60)
            for project_id in await asyncio.to_thread(sandbox_manager.cleanup_idle):
                logger.info("Destroyed idle Reverse sandbox for %s", project_id)

    cleanup_task = asyncio.create_task(_reverse_cleanup_loop(), name="reverse-sandbox-cleanup")
    try:
        yield
    finally:
        cleanup_task.cancel()
        await asyncio.gather(cleanup_task, return_exceptions=True)
        await analysis_manager.shutdown()
        await asyncio.to_thread(sandbox_manager.shutdown)
        dispose_reverse_db()
        dispose_rules_db()
        dispose_all_db_engines()


app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=f"{APP_CREDIT} — {APP_RELEASE_LABEL}",
    lifespan=lifespan,
)

# Reject requests whose Host header is not a loopback name we serve. This blocks
# DNS-rebinding, where a hostile page resolves its own domain to 127.0.0.1 and
# reaches this backend from the victim's browser: the rebound request still
# carries the attacker's hostname in Host and is refused here.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts())

# Local-only tool: restrict cross-origin reads to our own frontend origins
# (built app served by this backend, plus the Vite dev server).
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication is enforced for both HTTP and WebSocket scopes before any
# product route runs. Static SPA assets remain public for the login shell.
app.add_middleware(AuthMiddleware)


@app.middleware("http")
async def _enforce_http_origin(request: Request, call_next):
    # CORS controls whether a hostile page can read a response; it does not stop
    # a browser from sending a "simple" multipart/form-data request. Reject
    # present-but-untrusted Origins before any state-changing route can run.
    if not authorize_http(request):
        return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})
    return await call_next(request)


# Outermost application middleware also protects rejected requests and SPA assets.
app.add_middleware(HTTPBoundaryMiddleware)


@app.exception_handler(CaseNotFoundError)
async def _case_not_found_handler(_request: Request, _exc: CaseNotFoundError) -> JSONResponse:
    # A session was requested for an id absent from the registry; surface it as a
    # clean 404 instead of a 500 and, crucially, without creating case state.
    return JSONResponse(status_code=404, content={"detail": "Case not found"})

app.include_router(settings_router.router)
app.include_router(cases_router.router)
app.include_router(analysis_router.router)
app.include_router(reverse_router)
app.include_router(rules_router)
app.include_router(auth_router)


@app.get("/api/health")
async def health() -> dict:
    from app.memory.memprocfs_runner import is_memprocfs_available
    from app.memory.yara_scanner import get_scanner
    from app.rules.sigma_compile import sigma_available
    reverse = await asyncio.to_thread(sandbox_manager.health)
    return {
        "status": "ok",
        "brand": APP_TITLE,
        "version": APP_VERSION,
        "release_channel": APP_RELEASE_CHANNEL,
        "credit": APP_CREDIT,
        "memprocfs": is_memprocfs_available(),
        "yara": get_scanner().available(),
        # Custom Sigma rule authoring; built-in rule management works without it.
        "sigma": sigma_available(),
        "reverse": {
            **reverse,
            "store_ready": True,
        },
    }


# Serve built frontend if present
FRONTEND_DIST = (Path(__file__).parent.parent.parent / "frontend" / "dist").resolve()
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/")
    async def serve_index() -> FileResponse:
        return FileResponse(FRONTEND_DIST / "index.html")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str) -> FileResponse:
        # SPA fallback for client-side routes; never serve files outside dist
        candidate = os.path.realpath(os.path.join(FRONTEND_DIST, full_path))
        if candidate.startswith(str(FRONTEND_DIST) + os.sep) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")


def main() -> None:
    import uvicorn
    port = int(os.environ.get("INVESTIGATOR_PORT", "8400"))
    uvicorn.run("app.main:app", host="127.0.0.1", port=port, reload=False, ws_max_size=131_072)


if __name__ == "__main__":
    main()
