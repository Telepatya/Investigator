"""Command-line entry point: ``python -m benchmarks`` (run from ``backend/``)."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from benchmarks import compare as compare_mod
from benchmarks.corpus import CORPUS_VERSION, SIZES, generate_corpus
from benchmarks.runner import run_suite, validate_results, write_results
from benchmarks.scenarios import PROFILES, build_specs, corpus_sizes_for_profile

_BACKEND_DIR = Path(__file__).resolve().parents[1]


def _default_output(profile: str, commit: str | None) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = f"-{commit[:10]}" if commit else ""
    return _BACKEND_DIR / "benchmarks" / "results" / f"{stamp}-{profile}{suffix}.json"


def _cmd_run(args: argparse.Namespace) -> int:
    from benchmarks.environment import BenchmarkEnvironment

    sizes = corpus_sizes_for_profile(args.profile)
    log = (lambda msg: print(msg, flush=True)) if not args.quiet else None

    with tempfile.TemporaryDirectory(prefix="investigator-bench-") as scratch:
        scratch_dir = Path(scratch)
        if args.corpus_dir:
            corpus_dir = Path(args.corpus_dir)
        else:
            corpus_dir = scratch_dir / "corpus"
        if log:
            log(f"generating corpus v{CORPUS_VERSION} (sizes: {', '.join(sizes)}) "
                f"in {corpus_dir}")
        manifest = generate_corpus(corpus_dir, sizes)

        with BenchmarkEnvironment(scratch_dir / "env") as env:
            specs = build_specs(env, corpus_dir, manifest, args.profile, args.filter)
            if not specs:
                print(f"no benchmarks match filter {args.filter!r}", file=sys.stderr)
                return 2
            iterations = args.iterations or PROFILES[args.profile]["default_iterations"]
            if log:
                log(f"running {len(specs)} benchmark(s), {iterations} iteration(s) each")
            doc = run_suite(
                specs, iterations, profile=args.profile,
                measure_memory=not args.no_memory, log=log,
            )

    problems = validate_results(doc)
    if problems:
        print(f"internal error: invalid result document: {problems}", file=sys.stderr)
        return 2

    output = Path(args.output) if args.output else _default_output(
        args.profile, doc["environment"].get("commit"))
    write_results(doc, output)
    print(f"wrote {len(doc['benchmarks'])} benchmark result(s) to {output}")
    if not args.quiet:
        for bench in doc["benchmarks"]:
            ops = bench["ops_per_second"]
            print(
                f"  {bench['name']:<44} median {bench['wall_seconds_median']:>9.4f}s"
                + (f"  {ops:>12.1f} ops/s" if ops else "")
            )
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    base = compare_mod.load_results(Path(args.base))
    new = compare_mod.load_results(Path(args.new))
    comparison = compare_mod.compare_results(base, new, threshold=args.threshold)
    report = (
        json.dumps(comparison, indent=2)
        if args.format == "json"
        else compare_mod.render_markdown(comparison)
    )
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(f"wrote comparison report to {args.output}")
    else:
        print(report)
    failed = bool(comparison["regressions"] or comparison["counter_drift"])
    return 1 if failed and not args.no_fail else 0


def _cmd_corpus(args: argparse.Namespace) -> int:
    sizes = args.sizes.split(",") if args.sizes else list(SIZES)
    unknown = [s for s in sizes if s not in SIZES]
    if unknown:
        print(f"unknown corpus size(s): {unknown}; expected {list(SIZES)}", file=sys.stderr)
        return 2
    manifest = generate_corpus(Path(args.output), sizes)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    # Names only: a stub manifest and an un-entered environment mean nothing
    # is generated, stored, or run.
    from benchmarks.corpus import manifest_stub
    from benchmarks.environment import BenchmarkEnvironment

    manifest = manifest_stub(corpus_sizes_for_profile("full"))
    env = BenchmarkEnvironment(Path("."))
    for spec in build_specs(env, Path("."), manifest, "full"):
        print(f"{spec.group:<14} {spec.name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks",
        description="Investigator benchmark suite (see docs/BENCHMARKS.md)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="generate the corpus and run benchmarks")
    p_run.add_argument("--profile", choices=sorted(PROFILES), default="full")
    p_run.add_argument("--filter", help="only run benchmarks whose name contains this")
    p_run.add_argument("--iterations", type=int,
                       help="timed iterations per benchmark (default: profile-defined)")
    p_run.add_argument("--output", help="result JSON path "
                       "(default: benchmarks/results/<timestamp>-<profile>-<commit>.json)")
    p_run.add_argument("--corpus-dir", help="generate/reuse the corpus here instead of "
                       "a temporary directory")
    p_run.add_argument("--no-memory", action="store_true",
                       help="skip the tracemalloc peak-memory pass")
    p_run.add_argument("--quiet", action="store_true")
    p_run.set_defaults(func=_cmd_run)

    p_cmp = sub.add_parser("compare", help="compare two result files")
    p_cmp.add_argument("base", help="baseline results JSON")
    p_cmp.add_argument("new", help="candidate results JSON")
    p_cmp.add_argument("--threshold", type=float, default=compare_mod.DEFAULT_THRESHOLD,
                       help="regression threshold as a fraction (default 0.10)")
    p_cmp.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_cmp.add_argument("--output", help="write the report here instead of stdout")
    p_cmp.add_argument("--no-fail", action="store_true",
                       help="exit 0 even when regressions or counter drift are found")
    p_cmp.set_defaults(func=_cmd_compare)

    p_corpus = sub.add_parser("corpus", help="generate the synthetic corpus only")
    p_corpus.add_argument("--output", required=True, help="directory to generate into")
    p_corpus.add_argument("--sizes", help=f"comma-separated subset of {list(SIZES)}")
    p_corpus.set_defaults(func=_cmd_corpus)

    p_list = sub.add_parser("list", help="list benchmarks in the full profile")
    p_list.set_defaults(func=_cmd_list)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
