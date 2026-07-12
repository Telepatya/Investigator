#!/usr/bin/env python3
"""Investigator - one-command launcher.

Sets up the Python backend virtual environment, installs dependencies, builds
the frontend (unless running in dev mode), and starts the app, opening it in
your browser.

Usage:
    python run.py                 # build frontend, serve everything on :8400
    python run.py --port 9000     # use a different port
    python run.py --dev           # backend + Vite dev server (hot reload on :5173)
    python run.py --skip-build     # don't rebuild the frontend
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
VENV = BACKEND / ".venv"
IS_WINDOWS = os.name == "nt"
BACKEND_LOCK = BACKEND / "requirements-memory.lock"
BACKEND_CORE_LOCK = BACKEND / "requirements.lock"
BACKEND_UNLOCKED_REQUIREMENTS = BACKEND / "requirements-memory.in"
BACKEND_LOCK_STATE = VENV / ".investigator-requirements-lock.sha256"
FRONTEND_LOCK = FRONTEND / "package-lock.json"
FRONTEND_LOCK_STATE = FRONTEND / "node_modules" / ".investigator-package-lock.sha256"
FRONTEND_DIST = FRONTEND / "dist"
FRONTEND_BUILD_STATE = FRONTEND_DIST / ".investigator-src.sha256"
logger = logging.getLogger(__name__)
# Files whose contents determine the built frontend; a change to any triggers a
# rebuild. node_modules and dist are excluded (deps handled separately, dist is
# the output).
FRONTEND_BUILD_CONFIG_FILES = (
    "index.html", "package.json", "package-lock.json",
    "vite.config.ts", "tsconfig.json", "tsconfig.app.json", "tsconfig.node.json",
)


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def log(msg: str) -> None:
    print(f"\033[36m==\033[0m {msg}", flush=True)


def run(
    cmd: list[str],
    cwd: Path | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=check, env=env)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def state_matches(state_file: Path, digest: str) -> bool:
    try:
        return state_file.read_text(encoding="utf-8").strip() == digest
    except OSError:
        return False


def write_state(state_file: Path, digest: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(digest + "\n", encoding="utf-8")


def npm_cmd() -> str:
    """Resolve the npm executable (npm.cmd on Windows)."""
    for candidate in (("npm.cmd", "npm") if IS_WINDOWS else ("npm",)):
        if shutil.which(candidate):
            return candidate
    return "npm.cmd" if IS_WINDOWS else "npm"


def ensure_venv(allow_unlocked_deps: bool = False) -> Path:
    py = venv_python()
    if not py.exists():
        log("Creating Python virtual environment...")
        run([sys.executable, "-m", "venv", str(VENV)])

    lock_file = BACKEND_LOCK if BACKEND_LOCK.exists() else BACKEND_CORE_LOCK
    if lock_file.exists():
        digest = file_sha256(lock_file)
        if not state_matches(BACKEND_LOCK_STATE, digest):
            log(f"Installing locked backend dependencies from {lock_file.name}...")
            run([
                str(py), "-m", "pip", "install",
                "--require-hashes",
                "-r", str(lock_file),
            ])
            write_state(BACKEND_LOCK_STATE, digest)
        return py

    allow_unlocked = allow_unlocked_deps or os.environ.get("INVESTIGATOR_ALLOW_UNLOCKED_DEPS") == "1"
    if not allow_unlocked:
        raise SystemExit(
            "Missing backend dependency lock file.\n"
            "Generate and commit backend/requirements.lock, backend/requirements-memory.lock, "
            "and backend/requirements-dev.lock with:\n"
            "  cd backend\n"
            "  python -m pip install uv\n"
            "  .\\scripts\\update-locks.ps1\n\n"
            "For temporary local development only, rerun with --allow-unlocked-deps."
        )

    log("Installing UNLOCKED backend dependencies for local development...")
    run([str(py), "-m", "pip", "install", "-r", str(BACKEND_UNLOCKED_REQUIREMENTS)])
    return py


def frontend_source_digest() -> str:
    """Hash of everything that determines the built frontend, so we only rebuild
    when the source actually changed."""
    h = hashlib.sha256()
    inputs: list[Path] = []
    src = FRONTEND / "src"
    if src.exists():
        inputs.extend(p for p in src.rglob("*") if p.is_file())
    for name in FRONTEND_BUILD_CONFIG_FILES:
        p = FRONTEND / name
        if p.is_file():
            inputs.append(p)
    for p in sorted(inputs):
        h.update(p.relative_to(FRONTEND).as_posix().encode("utf-8"))
        h.update(file_sha256(p).encode("utf-8"))
    return h.hexdigest()


def ensure_frontend(build: bool) -> None:
    npm = npm_cmd()
    if not FRONTEND_LOCK.exists():
        raise SystemExit("Missing frontend/package-lock.json; run npm install deliberately and commit the lockfile.")
    digest = file_sha256(FRONTEND_LOCK)
    if not (FRONTEND / "node_modules").exists() or not state_matches(FRONTEND_LOCK_STATE, digest):
        log("Installing locked frontend dependencies...")
        run([npm, "ci"], cwd=FRONTEND)
        write_state(FRONTEND_LOCK_STATE, digest)
    if build:
        # Rebuild only when the frontend source changed (or dist is missing), so
        # a change to any src/config file is picked up automatically without
        # rebuilding on every launch.
        src_digest = frontend_source_digest()
        if (FRONTEND_DIST / "index.html").exists() and state_matches(FRONTEND_BUILD_STATE, src_digest):
            log("Frontend already up to date; skipping build.")
        else:
            log("Building frontend (source changed)...")
            run([npm, "run", "build"], cwd=FRONTEND)
            write_state(FRONTEND_BUILD_STATE, src_digest)


def open_browser_later(url: str, delay: float = 2.0) -> None:
    def _open() -> None:
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            logger.debug("Could not open the browser automatically", exc_info=True)

    threading.Thread(target=_open, daemon=True).start()


def main() -> int:
    parser = argparse.ArgumentParser(description="Investigator DFIR launcher")
    parser.add_argument("--port", type=int, default=8400, help="Backend port (default 8400)")
    parser.add_argument("--dev", action="store_true", help="Run Vite dev server with hot reload")
    parser.add_argument("--skip-build", action="store_true", help="Skip the frontend production build")
    parser.add_argument(
        "--allow-unlocked-deps",
        action="store_true",
        help="Temporary local fallback: install backend deps from requirements-memory.in when no lock is present",
    )
    args = parser.parse_args()

    log("Investigator DFIR")

    py = ensure_venv(allow_unlocked_deps=args.allow_unlocked_deps)

    env = os.environ.copy()
    env["INVESTIGATOR_PORT"] = str(args.port)

    if args.dev:
        ensure_frontend(build=False)
        log(f"Starting backend on :{args.port} and Vite dev server on :5173 ...")
        backend_proc = subprocess.Popen([str(py), "-m", "app.main"], cwd=str(BACKEND), env=env)
        open_browser_later("http://localhost:5173", delay=3.0)
        try:
            run([npm_cmd(), "run", "dev"], cwd=FRONTEND, check=False)
        finally:
            backend_proc.terminate()
        return 0

    ensure_frontend(build=not args.skip_build)
    log(f"Starting Investigator on http://localhost:{args.port} ...")
    open_browser_later(f"http://localhost:{args.port}")
    try:
        run([str(py), "-m", "app.main"], cwd=BACKEND, env=env, check=False)
    except KeyboardInterrupt:
        log("Stopping Investigator...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
