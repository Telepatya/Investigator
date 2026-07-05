"""Investigator DFIR backend entrypoint."""

from __future__ import annotations

import os
from pathlib import Path
import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import analysis_router, cases_router, settings_router
from app.config import ensure_dirs
from app.store.cases import cleanup_orphan_case_dirs, cleanup_stale_case_artifacts
from app.store.database import dispose_all_db_engines

logger = logging.getLogger(__name__)

APP_TITLE = "Investigator DFIR"
APP_VERSION = "1.0.0"
APP_CREDIT = "Made by Roei.f"


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_dirs()
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
    try:
        yield
    finally:
        dispose_all_db_engines()


app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=APP_CREDIT,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(settings_router.router)
app.include_router(cases_router.router)
app.include_router(analysis_router.router)


@app.get("/api/health")
async def health() -> dict:
    from app.memory.memprocfs_runner import is_memprocfs_available
    from app.memory.yara_scanner import get_scanner
    return {
        "status": "ok",
        "brand": APP_TITLE,
        "credit": APP_CREDIT,
        "memprocfs": is_memprocfs_available(),
        "yara": get_scanner().available(),
    }


# Serve built frontend if present
FRONTEND_DIST = Path(__file__).parent.parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/")
    async def serve_index() -> FileResponse:
        return FileResponse(FRONTEND_DIST / "index.html")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str) -> FileResponse:
        # SPA fallback for client-side routes
        candidate = FRONTEND_DIST / full_path
        if candidate.exists() and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")


def main() -> None:
    import uvicorn
    port = int(os.environ.get("INVESTIGATOR_PORT", "8400"))
    uvicorn.run("app.main:app", host="127.0.0.1", port=port, reload=False)


if __name__ == "__main__":
    main()
