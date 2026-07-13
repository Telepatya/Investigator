"""Run detection timing against a copied case database.

This helper never runs detections on the live case DB. It copies case.db (and
SQLite sidecars when present) under .codex_tmp/detection_benchmark/<case_id>/,
optionally resets rebuild-managed detection state, then runs the normal engine.
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import time
from pathlib import Path

from sqlalchemy import delete as sqldelete, update as sqlupdate

from app.config import case_db_path
from app.detect.engine import run_detections_sync
from app.store import cases as case_store
from app.store.database import Event, Finding, dispose_all_db_engines


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _copy_case_db(case_id: str, source_db: Path | None = None) -> Path:
    src = source_db or case_db_path(case_id)
    if not src.exists():
        raise SystemExit(f"case DB not found: {src}")
    dst_dir = _repo_root() / ".codex_tmp" / "detection_benchmark" / case_id
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / "case.db"
    shutil.copy2(src, dst)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(src) + suffix)
        if sidecar.exists():
            shutil.copy2(sidecar, Path(str(dst) + suffix))
    return dst


def _reset_detection_state(case_id: str) -> None:
    session = case_store.get_session(case_id)
    try:
        session.execute(sqldelete(Finding))
        session.execute(
            sqlupdate(Event)
            .where(
                (Event.severity_reason.like("Detection:%"))
                | (Event.severity_reason.like("Context:%"))
                | (Event.severity_reason.like("Flagged-entity match:%"))
            )
            .values(severity="info", severity_reason=None)
        )
        session.commit()
    finally:
        session.close()


def _counts(db_path: Path) -> dict[str, int]:
    con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        return {
            table: con.execute(f"select count(*) from {table}").fetchone()[0]
            for table in ("events", "processes", "findings", "memory_results")
        }
    finally:
        con.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id")
    parser.add_argument("--source-db", type=Path, default=None)
    parser.add_argument("--no-reset", action="store_true", help="Skip rebuild-style reset on the copied DB.")
    args = parser.parse_args()

    copied_db = _copy_case_db(args.case_id, args.source_db)
    bench_root = copied_db.parent.parent
    case_store.case_db_path = lambda cid: bench_root / cid / "case.db"

    if not args.no_reset:
        _reset_detection_state(args.case_id)

    before = _counts(copied_db)
    started = time.perf_counter()
    added = run_detections_sync(args.case_id)
    elapsed = time.perf_counter() - started
    after = _counts(copied_db)
    dispose_all_db_engines()

    print(f"case_id={args.case_id}")
    print(f"copied_db={copied_db}")
    print(f"seconds={elapsed:.3f}")
    print(f"findings_added={added}")
    print(f"before={before}")
    print(f"after={after}")


if __name__ == "__main__":
    main()
