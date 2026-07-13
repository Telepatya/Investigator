"""Per-case coordination for long-running background operations."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator


class CaseOperationCoordinator:
    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self._active: dict[str, str] = {}
        self._queued: dict[str, int] = {}

    def _lock_for(self, case_id: str) -> asyncio.Lock:
        lock = self._locks.get(case_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[case_id] = lock
        return lock

    def snapshot(self, case_id: str) -> dict[str, object]:
        return {
            "active": self._active.get(case_id),
            "queued": self._queued.get(case_id, 0),
        }

    @asynccontextmanager
    async def run(self, case_id: str, operation: str) -> AsyncIterator[None]:
        lock = self._lock_for(case_id)
        if lock.locked():
            self._queued[case_id] = self._queued.get(case_id, 0) + 1
        try:
            await lock.acquire()
        finally:
            if self._queued.get(case_id, 0) > 0:
                self._queued[case_id] -= 1
        self._active[case_id] = operation
        try:
            yield
        finally:
            self._active.pop(case_id, None)
            lock.release()


coordinator = CaseOperationCoordinator()
