"""Investigator benchmark suite.

Deterministic, synthetic-corpus performance benchmarks for the ingestion,
detection, query, and memory-artifact normalization paths. Never uses real
case material and never talks to a remote AI provider.

Run from ``backend/``:

    python -m benchmarks run                # full local suite
    python -m benchmarks run --profile smoke
    python -m benchmarks compare BASE NEW   # regression report

See docs/BENCHMARKS.md for the result schema and regression policy.
"""

from benchmarks.corpus import CORPUS_VERSION

__all__ = ["CORPUS_VERSION"]
