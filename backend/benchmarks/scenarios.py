"""Benchmark scenario definitions.

Each factory returns ``BenchmarkSpec`` instances wired to the shared
``BenchmarkEnvironment`` and generated corpus. Scenarios only exercise code
paths that already exist in the app — they never fork parser or detector
behavior, so a timing change here is a real product change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.corpus import MIX_PROFILES, SIZES
from benchmarks.environment import BenchmarkEnvironment, noop_progress
from benchmarks.runner import BenchmarkSpec

# Profile → which corpus sizes each scenario family runs at.
PROFILES: dict[str, dict[str, Any]] = {
    "smoke": {
        "ingest_sizes": ["xs"],
        "bulk_sizes": ["xs"],
        "detection_sizes": ["xs"],
        "detection_mixes": ["mixed"],
        "query_size": "xs",
        "memory_sizes": ["xs"],
        "default_iterations": 1,
    },
    "quick": {
        "ingest_sizes": ["small"],
        "bulk_sizes": ["small", "medium"],
        "detection_sizes": ["small"],
        "detection_mixes": list(MIX_PROFILES),
        "query_size": "small",
        "memory_sizes": ["small"],
        "default_iterations": 2,
    },
    "full": {
        "ingest_sizes": ["small", "medium", "large"],
        "bulk_sizes": ["small", "medium", "large"],
        "detection_sizes": ["medium"],
        "detection_mixes": list(MIX_PROFILES),
        "query_size": "medium",
        "memory_sizes": ["small", "medium", "large"],
        "default_iterations": 3,
    },
}

_INGEST_FILES = {
    "defender_jsonl": "ingest/defender_{size}.jsonl",
    "evtx_jsonl": "ingest/evtx_{size}.jsonl",
    "artifact_csv": "ingest/artifact_{size}.csv",
    "linux_log": "ingest/linux_auth_{size}.log",
    "mixed_zip": "ingest/mixed_{size}.zip",
}


def _corpus_rows(manifest: dict[str, Any], rel: str) -> int:
    return int(manifest["files"][rel]["rows"])


# --- Ingestion ----------------------------------------------------------------


def _ingestion_spec(
    env: BenchmarkEnvironment, corpus_dir: Path, manifest: dict[str, Any],
    label: str, rel: str, size: str,
) -> BenchmarkSpec:
    rows = _corpus_rows(manifest, rel)

    def prepare(state: dict[str, Any]) -> None:
        env.drop_case(state.get("case_id"))
        state["case_id"] = env.new_case(f"bench-{label}-{size}")
        state["upload"] = env.stage_upload(state["case_id"], corpus_dir / rel)

    def run(state: dict[str, Any]) -> dict[str, int]:
        stats = env.ingest(state["case_id"], state["upload"])
        return {"operations": rows, "events": stats["events"],
                "processes": stats["processes"], "files": stats["files"]}

    def teardown(state: dict[str, Any]) -> None:
        env.drop_case(state.get("case_id"))

    return BenchmarkSpec(
        name=f"ingest_{label}_{size}", group="ingestion", corpus_size=size,
        run=run, prepare=prepare, teardown=teardown,
    )


def ingestion_specs(
    env: BenchmarkEnvironment, corpus_dir: Path, manifest: dict[str, Any],
    sizes: list[str],
) -> list[BenchmarkSpec]:
    return [
        _ingestion_spec(env, corpus_dir, manifest, label, template.format(size=size), size)
        for size in sizes
        for label, template in _INGEST_FILES.items()
    ]


# --- Normalization and bulk insertion ------------------------------------------


def normalization_specs(
    env: BenchmarkEnvironment, corpus_dir: Path, manifest: dict[str, Any],
    sizes: list[str],
) -> list[BenchmarkSpec]:
    specs: list[BenchmarkSpec] = []
    for size in sizes:
        rel = f"ingest/defender_{size}.jsonl"
        rows = _corpus_rows(manifest, rel)

        def make_normalize(rel: str = rel, rows: int = rows):
            def run(_state: dict[str, Any]) -> dict[str, int]:
                from app.ingest.parsers import parse_file

                produced = sum(1 for _ in parse_file(corpus_dir / rel, Path(rel).name))
                return {"operations": rows, "events": produced}
            return run

        specs.append(BenchmarkSpec(
            name=f"normalize_defender_jsonl_{size}", group="normalization",
            corpus_size=size, run=make_normalize(),
        ))

        def make_bulk(rel: str = rel, rows: int = rows, size: str = size):
            def setup() -> dict[str, Any]:
                from app.ingest.parsers import parse_file

                return {
                    "rows": list(parse_file(corpus_dir / rel, Path(rel).name)),
                    "case_id": None,
                }

            def prepare(state: dict[str, Any]) -> None:
                env.drop_case(state.get("case_id"))
                state["case_id"] = env.new_case(f"bench-bulk-{size}")

            def run(state: dict[str, Any]) -> dict[str, int]:
                from app.store import cases as case_store

                session = env.session(state["case_id"])
                try:
                    case_store.add_events_bulk(session, state["rows"])
                    session.commit()
                finally:
                    session.close()
                return {"operations": len(state["rows"]), "events": len(state["rows"])}

            def teardown(state: dict[str, Any]) -> None:
                env.drop_case(state.get("case_id"))

            return setup, prepare, run, teardown

        setup, prepare, run, teardown = make_bulk()
        specs.append(BenchmarkSpec(
            name=f"bulk_insert_events_{size}", group="normalization", corpus_size=size,
            run=run, setup=setup, prepare=prepare, teardown=teardown,
        ))
    return specs


# --- Detection rebuilds ---------------------------------------------------------


def detection_specs(
    env: BenchmarkEnvironment, corpus_dir: Path, manifest: dict[str, Any],
    sizes: list[str], mixes: list[str],
) -> list[BenchmarkSpec]:
    specs: list[BenchmarkSpec] = []
    for size in sizes:
        for mix in mixes:
            rel = f"detection/detect_{mix}_{size}.jsonl"
            rows = _corpus_rows(manifest, rel)

            def make(rel: str = rel, rows: int = rows, mix: str = mix, size: str = size):
                def setup() -> dict[str, Any]:
                    case_id = env.new_case(f"bench-detect-{mix}-{size}")
                    upload = env.stage_upload(case_id, corpus_dir / rel)
                    stats = env.ingest(case_id, upload)
                    return {"case_id": case_id, "events": stats["events"]}

                def prepare(state: dict[str, Any]) -> None:
                    env.reset_detection_state(state["case_id"])

                def run(state: dict[str, Any]) -> dict[str, int]:
                    added = env.run_detections(state["case_id"])
                    return {"operations": state["events"], "findings": added}

                def teardown(state: dict[str, Any]) -> None:
                    env.drop_case(state.get("case_id"))

                return setup, prepare, run, teardown

            setup, prepare, run, teardown = make()
            specs.append(BenchmarkSpec(
                name=f"detect_rebuild_{mix}_{size}", group="detection", corpus_size=size,
                run=run, setup=setup, prepare=prepare, teardown=teardown,
            ))
    return specs


# --- Query paths -----------------------------------------------------------------


def query_specs(
    env: BenchmarkEnvironment, corpus_dir: Path, manifest: dict[str, Any],
    size: str,
) -> list[BenchmarkSpec]:
    rel = f"detection/detect_mixed_{size}.jsonl"
    shared: dict[str, Any] = {}

    def shared_case() -> str:
        # One ingested + detected case serves every query benchmark; queries
        # are read-only so sharing keeps setup cost paid once.
        if "case_id" not in shared:
            case_id = env.new_case(f"bench-query-{size}")
            upload = env.stage_upload(case_id, corpus_dir / rel)
            env.ingest(case_id, upload)
            env.run_detections(case_id)
            shared["case_id"] = case_id
        return shared["case_id"]

    def setup() -> dict[str, Any]:
        # Materialize the shared case here so its cost never lands inside a
        # timed run (setup is untimed).
        return {"case_id": shared_case()}

    def timeline_run(_state: dict[str, Any]) -> dict[str, int]:
        from app.api.cases_router import get_timeline

        payload = get_timeline(shared_case(), limit=2000, include_facets=True)
        return {"operations": len(payload["events"]),
                "total_matching": payload["total_matching"]}

    def fts_run(_state: dict[str, Any]) -> dict[str, int]:
        from app.store import cases as case_store

        session = env.session(shared_case())
        try:
            hits = 0
            for term in ("payload", "synthetic", "chrome", "logon"):
                hits += len(case_store.search_events(session, term, limit=200))
                case_store.count_search_events(session, term)
            return {"operations": 4, "hits": hits}
        finally:
            session.close()

    def stats_run(_state: dict[str, Any]) -> dict[str, int]:
        from app.store import cases as case_store

        loops = 25
        counts: dict[str, int] = {}
        for _ in range(loops):
            counts = case_store.get_case_stats(shared_case())
        return {"operations": loops, "events": counts.get("event_count", 0),
                "findings": counts.get("finding_count", 0)}

    def graph_prepare(_state: dict[str, Any]) -> None:
        env.clear_graph_cache()

    def graph_run(_state: dict[str, Any]) -> dict[str, int]:
        from app.detect.entity_graph import build_entity_graph

        graph = build_entity_graph(shared_case())
        return {"operations": graph["total_nodes"], "edges": graph["total_edges"]}

    def findings_run(_state: dict[str, Any]) -> dict[str, int]:
        from app.api.cases_router import get_findings

        payload = get_findings(shared_case())
        count = len(payload["findings"])
        return {"operations": max(count, 1), "findings": count}

    def teardown(_state: dict[str, Any]) -> None:
        # Attached to the last query spec so the shared case is dropped once
        # every query benchmark has run.
        env.drop_case(shared.pop("case_id", None))

    return [
        BenchmarkSpec(name=f"query_timeline_{size}", group="queries", corpus_size=size,
                      run=timeline_run, setup=setup),
        BenchmarkSpec(name=f"query_fts_search_{size}", group="queries", corpus_size=size,
                      run=fts_run, setup=setup),
        BenchmarkSpec(name=f"query_case_stats_{size}", group="queries", corpus_size=size,
                      run=stats_run, setup=setup),
        BenchmarkSpec(name=f"query_entity_graph_{size}", group="queries", corpus_size=size,
                      run=graph_run, setup=setup, prepare=graph_prepare),
        BenchmarkSpec(name=f"query_findings_serialization_{size}", group="queries",
                      corpus_size=size, run=findings_run, setup=setup, teardown=teardown),
    ]


# --- MemProcFS artifact normalization ---------------------------------------------


def memory_specs(
    env: BenchmarkEnvironment, corpus_dir: Path, manifest: dict[str, Any],
    sizes: list[str],
) -> list[BenchmarkSpec]:
    specs: list[BenchmarkSpec] = []
    for size in sizes:
        artifact_dir = corpus_dir / f"memory/memprocfs_{size}"
        rows = sum(
            meta["rows"] for rel, meta in manifest["files"].items()
            if rel.startswith(f"memory/memprocfs_{size}/")
        )

        def make(artifact_dir: Path = artifact_dir, rows: int = rows, size: str = size):
            def prepare(state: dict[str, Any]) -> None:
                env.drop_case(state.get("case_id"))
                state["case_id"] = env.new_case(f"bench-memory-{size}")

            def run(state: dict[str, Any]) -> dict[str, int]:
                from app.memory.forensics import ingest_memprocfs_artifacts_sync

                session = env.session(state["case_id"])
                try:
                    stats = ingest_memprocfs_artifacts_sync(
                        session, "benchdump", artifact_dir, None, noop_progress,
                    )
                    session.commit()
                finally:
                    session.close()
                return {"operations": rows, "events": stats["events"],
                        "processes": stats["processes"],
                        "memory_results": stats["memory_results"]}

            def teardown(state: dict[str, Any]) -> None:
                env.drop_case(state.get("case_id"))

            return prepare, run, teardown

        prepare, run, teardown = make()
        specs.append(BenchmarkSpec(
            name=f"memory_artifact_normalize_{size}", group="memory", corpus_size=size,
            run=run, prepare=prepare, teardown=teardown,
        ))
    return specs


# --- Assembly ---------------------------------------------------------------------


def build_specs(
    env: BenchmarkEnvironment, corpus_dir: Path, manifest: dict[str, Any],
    profile: str, name_filter: str | None = None,
) -> list[BenchmarkSpec]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; expected one of {sorted(PROFILES)}")
    cfg = PROFILES[profile]
    specs = [
        *ingestion_specs(env, corpus_dir, manifest, cfg["ingest_sizes"]),
        *normalization_specs(env, corpus_dir, manifest, cfg["bulk_sizes"]),
        *detection_specs(env, corpus_dir, manifest, cfg["detection_sizes"],
                         cfg["detection_mixes"]),
        *query_specs(env, corpus_dir, manifest, cfg["query_size"]),
        *memory_specs(env, corpus_dir, manifest, cfg["memory_sizes"]),
    ]
    if name_filter:
        specs = [s for s in specs if name_filter in s.name]
    return specs


def corpus_sizes_for_profile(profile: str) -> list[str]:
    cfg = PROFILES[profile]
    labels = {
        *cfg["ingest_sizes"], *cfg["bulk_sizes"], *cfg["detection_sizes"],
        cfg["query_size"], *cfg["memory_sizes"],
    }
    return [label for label in SIZES if label in labels]
