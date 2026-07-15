"""Benchmark execution harness and machine-readable result documents.

Timing protocol, per benchmark:

1. ``setup`` runs once (untimed) and returns shared state.
2. One untimed warmup iteration (``prepare`` + ``run``) absorbs one-time
   costs — lazy imports, parser caches — so timed iterations measure the
   steady state and stay comparable across commits.
3. For each iteration: ``prepare`` (untimed) resets state, then ``run`` is
   timed with ``time.perf_counter`` around it and a ``gc.collect()`` before.
4. One extra untimed iteration runs under ``tracemalloc`` to record peak
   Python heap usage — tracemalloc slows execution, so memory is never
   sampled during the timed iterations.
5. ``teardown`` runs once.

``run`` returns counters (operation count plus scenario-specific totals such
as events ingested or findings created). Counters are recorded in the result
document so a comparison can flag behavioral drift — a "faster" run that
produces fewer findings is a bug, not a win.
"""

from __future__ import annotations

import gc
import json
import platform
import sqlite3
import statistics
import subprocess
import sys
import time
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from benchmarks.corpus import CORPUS_VERSION

RESULT_SCHEMA_VERSION = 1
RESULT_KIND = "investigator-benchmark-results"


@dataclass
class BenchmarkSpec:
    """One measurable operation. ``run`` must return a counters dict that
    includes ``operations`` (logical units processed, for throughput)."""

    name: str
    group: str
    corpus_size: str
    run: Callable[[dict[str, Any]], dict[str, int]]
    setup: Callable[[], dict[str, Any]] | None = None
    prepare: Callable[[dict[str, Any]], None] | None = None
    teardown: Callable[[dict[str, Any]], None] | None = None
    tags: list[str] = field(default_factory=list)


class HarnessError(RuntimeError):
    """A benchmark violated the harness contract (not a performance problem)."""


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def collect_environment() -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[2]
    commit = _git(["rev-parse", "HEAD"], repo_root)
    dirty = None
    if commit:
        status = _git(["status", "--porcelain"], repo_root)
        dirty = bool(status) if status is not None else None
    try:
        import sqlalchemy
        sqlalchemy_version = sqlalchemy.__version__
    except ImportError:
        sqlalchemy_version = None
    return {
        "commit": commit,
        "commit_dirty": dirty,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": _cpu_count(),
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "sqlalchemy_version": sqlalchemy_version,
        "sqlite_version": sqlite3.sqlite_version,
    }


def _cpu_count() -> int | None:
    try:
        import os
        return os.cpu_count()
    except OSError:
        return None


def run_benchmark(
    spec: BenchmarkSpec, iterations: int, measure_memory: bool = True,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    state = spec.setup() if spec.setup else {}
    wall_seconds: list[float] = []
    counters: dict[str, int] = {}
    try:
        # Untimed warmup: absorbs lazy imports and cold caches.
        if spec.prepare:
            spec.prepare(state)
        warmup_out = spec.run(state)
        if not isinstance(warmup_out, dict) or "operations" not in warmup_out:
            raise HarnessError(
                f"benchmark {spec.name}: run() must return a dict with 'operations'"
            )
        counters = dict(warmup_out)

        for i in range(iterations):
            if spec.prepare:
                spec.prepare(state)
            gc.collect()
            started = time.perf_counter()
            out = spec.run(state)
            elapsed = time.perf_counter() - started
            wall_seconds.append(elapsed)
            if out != counters:
                raise HarnessError(
                    f"benchmark {spec.name}: counters changed between iterations "
                    f"({counters} != {out}); benchmarks must be deterministic"
                )
            if log:
                log(f"  {spec.name} iteration {i + 1}/{iterations}: {elapsed:.3f}s")

        peak_bytes: int | None = None
        if measure_memory:
            if spec.prepare:
                spec.prepare(state)
            gc.collect()
            tracemalloc.start()
            try:
                spec.run(state)
                _current, peak_bytes = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
    finally:
        if spec.teardown:
            spec.teardown(state)

    operations = int(counters["operations"])
    median = statistics.median(wall_seconds)
    return {
        "name": spec.name,
        "group": spec.group,
        "corpus_size": spec.corpus_size,
        "iterations": iterations,
        "operations": operations,
        "wall_seconds": [round(t, 6) for t in wall_seconds],
        "wall_seconds_min": round(min(wall_seconds), 6),
        "wall_seconds_median": round(median, 6),
        "wall_seconds_mean": round(statistics.fmean(wall_seconds), 6),
        "ops_per_second": round(operations / median, 3) if median > 0 else None,
        "peak_tracemalloc_bytes": peak_bytes,
        "counters": {k: v for k, v in counters.items() if k != "operations"},
    }


def run_suite(
    specs: list[BenchmarkSpec],
    iterations: int,
    profile: str,
    measure_memory: bool = True,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    results = []
    for spec in specs:
        if log:
            log(f"running {spec.name} ({spec.group}, corpus={spec.corpus_size})")
        results.append(
            run_benchmark(spec, iterations, measure_memory=measure_memory, log=log)
        )
    return {
        "kind": RESULT_KIND,
        "schema_version": RESULT_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "corpus_version": CORPUS_VERSION,
        "environment": collect_environment(),
        "benchmarks": results,
    }


def write_results(doc: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def validate_results(doc: dict[str, Any]) -> list[str]:
    """Structural validation of a result document. Returns problem strings."""
    problems: list[str] = []
    if doc.get("kind") != RESULT_KIND:
        problems.append(f"kind must be {RESULT_KIND!r}")
    if doc.get("schema_version") != RESULT_SCHEMA_VERSION:
        problems.append(f"unsupported schema_version {doc.get('schema_version')!r}")
    if not isinstance(doc.get("corpus_version"), str):
        problems.append("missing corpus_version")
    if not isinstance(doc.get("environment"), dict):
        problems.append("missing environment")
    benchmarks = doc.get("benchmarks")
    if not isinstance(benchmarks, list) or not benchmarks:
        problems.append("benchmarks must be a non-empty list")
        return problems
    for bench in benchmarks:
        name = bench.get("name", "<unnamed>")
        for key in ("group", "corpus_size", "operations", "wall_seconds",
                    "wall_seconds_median", "counters"):
            if key not in bench:
                problems.append(f"benchmark {name}: missing {key}")
        if not bench.get("wall_seconds"):
            problems.append(f"benchmark {name}: no timings recorded")
        if isinstance(bench.get("operations"), int) and bench["operations"] <= 0:
            problems.append(f"benchmark {name}: operations must be positive")
    return problems
