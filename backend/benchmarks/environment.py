"""Isolated case environment for benchmark runs.

Redirects the case store to a throwaway directory (the same seam the test
suite uses), so benchmarks never read or write ``~/.investigator``. All app
imports happen lazily inside the class so ``benchmarks.corpus`` stays
importable without the backend dependencies installed.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

ProgressCallback = Callable[[str, float, str, bool, str | None], Any]


def noop_progress(_phase: str, _percent: float, _message: str, _done: bool,
                  _error: str | None) -> None:
    return None


class BenchmarkEnvironment:
    """Context manager that sandboxes case storage under ``root``."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.cases_dir = self.root / "cases"
        self._patches: list[Any] = []

    def __enter__(self) -> "BenchmarkEnvironment":
        from app.store import cases as case_store

        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self._patches = [
            patch.object(case_store, "get_cases_dir", return_value=self.cases_dir),
            patch.object(
                case_store, "case_db_path",
                side_effect=lambda cid: self.cases_dir / cid / "case.db",
            ),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        from app.store import database

        database.dispose_all_db_engines()
        for p in reversed(self._patches):
            p.stop()
        self._patches = []

    # --- case helpers -------------------------------------------------------

    def new_case(self, name: str) -> str:
        from app.store import cases as case_store

        return case_store.create_case(name)["id"]

    def drop_case(self, case_id: str | None) -> None:
        if not case_id:
            return
        from app.store import cases as case_store

        case_store.delete_case(case_id)

    def session(self, case_id: str):
        from app.store import cases as case_store

        return case_store.get_session(case_id)

    def stage_upload(self, case_id: str, source: Path) -> Path:
        """Copy a corpus file into the case's uploads dir, like a real upload."""
        uploads = self.cases_dir / case_id / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        dest = uploads / source.name
        shutil.copy2(source, dest)
        return dest

    def ingest(self, case_id: str, file_path: Path) -> dict[str, int]:
        from app.ingest.pipeline import ingest_file_sync

        return ingest_file_sync(case_id, file_path, noop_progress)

    def run_detections(self, case_id: str) -> int:
        from app.detect.engine import run_detections_sync

        return run_detections_sync(case_id)

    def reset_detection_state(self, case_id: str) -> None:
        """Restore the pre-detection baseline, exactly like a rebuild does."""
        from sqlalchemy import delete as sqldelete, update as sqlupdate

        from app.detect import manual
        from app.store.database import Event, Finding

        session = self.session(case_id)
        try:
            manual.restore_manual_event_severities(session)
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

    def clear_graph_cache(self) -> None:
        from app.detect import entity_graph

        with entity_graph._GRAPH_CACHE_LOCK:
            entity_graph._GRAPH_CACHE.clear()
