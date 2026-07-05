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


def npm_cmd() -> str:
    """Resolve the npm executable (npm.cmd on Windows)."""
    for candidate in (("npm.cmd", "npm") if IS_WINDOWS else ("npm",)):
        if shutil.which(candidate):
            return candidate
    return "npm.cmd" if IS_WINDOWS else "npm"


def ensure_venv() -> Path:
    py = venv_python()
    if not py.exists():
        log("Creating Python virtual environment...")
        run([sys.executable, "-m", "venv", str(VENV)])
    log("Installing backend dependencies (first run can take a few minutes)...")
    run([str(py), "-m", "pip", "install", "--upgrade", "pip"], check=False)
    run([str(py), "-m", "pip", "install", "-r", str(BACKEND / "requirements.txt")])
    return py


def ensure_frontend(build: bool) -> None:
    npm = npm_cmd()
    if not (FRONTEND / "node_modules").exists():
        log("Installing frontend dependencies...")
        run([npm, "install"], cwd=FRONTEND)
    if build:
        log("Building frontend...")
        run([npm, "run", "build"], cwd=FRONTEND)


def open_browser_later(url: str, delay: float = 2.0) -> None:
    def _open() -> None:
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_open, daemon=True).start()


def main() -> int:
    parser = argparse.ArgumentParser(description="Investigator DFIR launcher")
    parser.add_argument("--port", type=int, default=8400, help="Backend port (default 8400)")
    parser.add_argument("--dev", action="store_true", help="Run Vite dev server with hot reload")
    parser.add_argument("--skip-build", action="store_true", help="Skip the frontend production build")
    args = parser.parse_args()

    log("Investigator DFIR")

    py = ensure_venv()

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
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
