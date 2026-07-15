"""Compare two benchmark result documents and report regressions.

Policy (ROADMAP.md, workstream 1): a change slower than the regression
threshold (default 10%) on the reference environment requires an explanation
in the PR or an explicit baseline update. The compare command exits non-zero
when regressions are present so CI and scripts can enforce that conversation.

Counter drift (e.g. a different findings count for the same corpus) is
reported separately and always fails: it means behavior changed, which is
never acceptable in a performance-only change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.runner import RESULT_KIND, validate_results

DEFAULT_THRESHOLD = 0.10
# Timings this small are dominated by scheduler and allocator noise; a ratio
# over them is meaningless, so they are compared but never flagged.
NOISE_FLOOR_SECONDS = 0.010


def load_results(path: Path) -> dict[str, Any]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    problems = validate_results(doc)
    if problems:
        raise ValueError(f"{path} is not a valid {RESULT_KIND} document: {problems}")
    return doc


def compare_results(
    base: dict[str, Any], new: dict[str, Any], threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    if base.get("corpus_version") != new.get("corpus_version"):
        raise ValueError(
            "corpus versions differ "
            f"({base.get('corpus_version')} vs {new.get('corpus_version')}); "
            "results are not comparable"
        )
    base_by_name = {b["name"]: b for b in base["benchmarks"]}
    new_by_name = {b["name"]: b for b in new["benchmarks"]}

    rows: list[dict[str, Any]] = []
    counter_drift: list[dict[str, Any]] = []
    for name in [n for n in base_by_name if n in new_by_name]:
        b, n = base_by_name[name], new_by_name[name]
        base_t = float(b["wall_seconds_median"])
        new_t = float(n["wall_seconds_median"])
        ratio = (new_t / base_t) if base_t > 0 else None
        below_floor = base_t < NOISE_FLOOR_SECONDS and new_t < NOISE_FLOOR_SECONDS
        if ratio is None or below_floor:
            status = "not-compared"
        elif ratio > 1 + threshold:
            status = "regressed"
        elif ratio < 1 - threshold:
            status = "improved"
        else:
            status = "unchanged"
        rows.append({
            "name": name,
            "group": b["group"],
            "corpus_size": b["corpus_size"],
            "base_median_seconds": base_t,
            "new_median_seconds": new_t,
            "ratio": round(ratio, 4) if ratio is not None else None,
            "delta_percent": round((ratio - 1) * 100, 2) if ratio is not None else None,
            "status": status,
        })
        drift = {
            key: {"base": b["counters"].get(key), "new": n["counters"].get(key)}
            for key in set(b["counters"]) | set(n["counters"])
            if b["counters"].get(key) != n["counters"].get(key)
        }
        if drift or b["operations"] != n["operations"]:
            if b["operations"] != n["operations"]:
                drift["operations"] = {"base": b["operations"], "new": n["operations"]}
            counter_drift.append({"name": name, "drift": drift})

    return {
        "kind": "investigator-benchmark-comparison",
        "threshold": threshold,
        "corpus_version": new["corpus_version"],
        "base": {"commit": base["environment"].get("commit"),
                 "created_at": base.get("created_at")},
        "new": {"commit": new["environment"].get("commit"),
                "created_at": new.get("created_at")},
        "benchmarks": rows,
        "only_in_base": sorted(set(base_by_name) - set(new_by_name)),
        "only_in_new": sorted(set(new_by_name) - set(base_by_name)),
        "counter_drift": counter_drift,
        "regressions": [r["name"] for r in rows if r["status"] == "regressed"],
        "improvements": [r["name"] for r in rows if r["status"] == "improved"],
    }


def _fmt_seconds(value: float) -> str:
    return f"{value:.4f}" if value < 1 else f"{value:.3f}"


def render_markdown(comparison: dict[str, Any]) -> str:
    lines = [
        "# Benchmark comparison",
        "",
        f"- Base: commit `{comparison['base']['commit'] or 'unknown'}`"
        f" ({comparison['base']['created_at'] or 'unknown time'})",
        f"- New: commit `{comparison['new']['commit'] or 'unknown'}`"
        f" ({comparison['new']['created_at'] or 'unknown time'})",
        f"- Corpus version: `{comparison['corpus_version']}`"
        f" — regression threshold {comparison['threshold'] * 100:.0f}%",
        "",
        "| Benchmark | Group | Base median (s) | New median (s) | Δ | Status |",
        "|---|---|---|---|---|---|",
    ]
    marker = {"regressed": "🔴", "improved": "🟢", "unchanged": "", "not-compared": "·"}
    for row in comparison["benchmarks"]:
        delta = (
            f"{row['delta_percent']:+.1f}%" if row["delta_percent"] is not None else "n/a"
        )
        lines.append(
            f"| {row['name']} | {row['group']} | {_fmt_seconds(row['base_median_seconds'])} "
            f"| {_fmt_seconds(row['new_median_seconds'])} | {delta} "
            f"| {marker[row['status']]} {row['status']} |"
        )
    lines.append("")

    if comparison["counter_drift"]:
        lines.append("## Counter drift (behavior changed — investigate before merging)")
        lines.append("")
        for entry in comparison["counter_drift"]:
            lines.append(f"- **{entry['name']}**: {json.dumps(entry['drift'])}")
        lines.append("")
    if comparison["only_in_base"]:
        lines.append(f"Removed benchmarks: {', '.join(comparison['only_in_base'])}")
        lines.append("")
    if comparison["only_in_new"]:
        lines.append(f"Added benchmarks: {', '.join(comparison['only_in_new'])}")
        lines.append("")

    regressions = comparison["regressions"]
    if regressions:
        lines.append(
            f"**{len(regressions)} regression(s) over threshold.** Each needs an "
            "explanation in the PR or an explicit baseline update (see docs/BENCHMARKS.md)."
        )
    else:
        lines.append("No regressions over threshold.")
    lines.append("")
    return "\n".join(lines)
