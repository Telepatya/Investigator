from __future__ import annotations

# ruff: noqa: E402

import asyncio
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class _BaseModel:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


sys.modules.setdefault("keyring", types.SimpleNamespace(
    get_password=lambda *_a, **_k: None,
    set_password=lambda *_a, **_k: None,
    delete_password=lambda *_a, **_k: None,
    errors=types.SimpleNamespace(PasswordDeleteError=Exception),
))
sys.modules.setdefault("pydantic", types.SimpleNamespace(
    BaseModel=_BaseModel,
    Field=lambda default=None, default_factory=None, **_k: (
        default_factory() if default_factory else default
    ),
))

from app.detect import engine
from app.ingest import pipeline


class EmptyIngestionTests(unittest.IsolatedAsyncioTestCase):
    async def test_progress_listener_is_bounded_and_keeps_latest_status(self) -> None:
        manager = pipeline.IngestionManager()
        queue = manager.subscribe("case-1")
        self.assertEqual(queue.maxsize, pipeline.LISTENER_QUEUE_SIZE)

        for sequence in range(pipeline.LISTENER_QUEUE_SIZE + 7):
            manager._broadcast("case-1", {
                "phase": "parsing", "sequence": sequence, "done": False,
            })
        terminal = {"phase": "done", "sequence": 999, "done": True}
        manager._broadcast("case-1", terminal)

        self.assertEqual(queue.qsize(), pipeline.LISTENER_QUEUE_SIZE)
        queued = [queue.get_nowait() for _ in range(queue.qsize())]
        self.assertEqual(queued[-1], terminal)
        self.assertEqual(manager.get_status("case-1"), terminal)

    async def test_zero_event_upload_skips_detections_and_completes(self) -> None:
        manager = pipeline.IngestionManager()
        progress_updates: list[dict] = []

        def capture(_case_id: str, payload: dict) -> None:
            progress_updates.append(payload)

        with (
            patch.object(manager, "_broadcast", side_effect=capture),
            patch.object(pipeline.case_store, "update_case_meta"),
            patch.object(pipeline, "ingest_file_sync", return_value={
                "events": 0,
                "processes": 0,
                "files": 1,
            }),
            patch.object(engine, "run_detections_sync") as run_detections,
        ):
            await manager._run_ingestion_locked(
                "case-1", Path("empty.json"), "artifact"
            )
            await asyncio.sleep(0)

        run_detections.assert_not_called()
        self.assertTrue(any(
            update["message"] == "No events were parsed; skipping detections"
            for update in progress_updates
        ))
        self.assertEqual(progress_updates[-1]["phase"], "done")
        self.assertTrue(progress_updates[-1]["done"])
        self.assertIsNone(progress_updates[-1]["error"])

    async def test_multi_file_queue_runs_one_detection_after_final_file(self) -> None:
        manager = pipeline.IngestionManager()
        progress_updates: list[dict] = []

        with (
            patch.object(
                manager,
                "_broadcast",
                side_effect=lambda _case_id, payload: progress_updates.append(payload),
            ),
            patch.object(pipeline.case_store, "update_case_meta") as update_meta,
            patch.object(
                pipeline,
                "ingest_file_sync",
                side_effect=[
                    {"events": 5, "processes": 0, "files": 1},
                    {"events": 0, "processes": 0, "files": 1},
                ],
            ),
            patch.object(
                pipeline.coordinator,
                "snapshot",
                side_effect=[{"queued": 1}, {"queued": 0}],
            ),
            patch.object(engine, "run_detections_sync") as run_detections,
        ):
            await manager._run_ingestion_locked(
                "case-1", Path("events.json"), "artifact"
            )
            await manager._run_ingestion_locked(
                "case-1", Path("empty.json"), "artifact"
            )
            await asyncio.sleep(0)

        run_detections.assert_called_once_with("case-1", rebuild=False)
        update_meta.assert_any_call(
            "case-1", include_stats=False, status="ready"
        )
        self.assertEqual(progress_updates[-1]["phase"], "done")


if __name__ == "__main__":
    unittest.main()
