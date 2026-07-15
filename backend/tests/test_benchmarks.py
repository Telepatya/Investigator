from __future__ import annotations

# Harness-correctness coverage for the benchmark suite (ROADMAP.md workstream 1):
# corpus determinism, an end-to-end smoke run producing a schema-valid result
# document with plausible counters, and the comparison tool's regression /
# counter-drift verdicts. CI runs this instead of gating merges on shared-runner
# timings.
#
# The smoke run executes ``python -m benchmarks`` in a subprocess: it is the
# documented command, and the benchmark scenarios import FastAPI routers, which
# cannot be imported in this process once other tests have stubbed pydantic.

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from benchmarks import compare as compare_mod
from benchmarks.__main__ import main as benchmarks_main
from benchmarks.corpus import CORPUS_VERSION, SIZES, generate_corpus, manifest_stub
from benchmarks.runner import RESULT_KIND, RESULT_SCHEMA_VERSION, validate_results

_BACKEND_DIR = Path(__file__).resolve().parents[1]


class CorpusTests(unittest.TestCase):
    def test_generation_is_deterministic(self) -> None:
        # Same corpus version + size must produce byte-identical files (and so
        # identical manifests, which embed each file's SHA-256).
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            manifest_a = generate_corpus(Path(tmp_a), ["xs"])
            manifest_b = generate_corpus(Path(tmp_b), ["xs"])
        self.assertEqual(manifest_a, manifest_b)
        self.assertEqual(manifest_a["corpus_version"], CORPUS_VERSION)
        self.assertTrue(manifest_a["files"])
        for meta in manifest_a["files"].values():
            self.assertGreater(meta["rows"], 0)
            self.assertEqual(len(meta["sha256"]), 64)

    def test_manifest_stub_matches_generated_row_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            generated = generate_corpus(Path(tmp), ["xs"])
        stub = manifest_stub(["xs"])
        self.assertEqual(set(stub["files"]), set(generated["files"]))
        for rel, meta in stub["files"].items():
            self.assertEqual(meta["rows"], generated["files"][rel]["rows"], rel)

    def test_detection_mixes_share_size_but_differ_in_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = generate_corpus(Path(tmp), ["xs"])
            benign = manifest["files"]["detection/detect_benign_xs.jsonl"]
            suspicious = manifest["files"]["detection/detect_suspicious_xs.jsonl"]
            self.assertEqual(benign["rows"], suspicious["rows"])
            self.assertNotEqual(benign["sha256"], suspicious["sha256"])
            benign_text = (Path(tmp) / "detection/detect_benign_xs.jsonl").read_text(
                encoding="utf-8")
            self.assertNotIn("payload.exe", benign_text)


class SmokeRunTests(unittest.TestCase):
    def test_smoke_profile_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "smoke.json"
            proc = subprocess.run(
                [sys.executable, "-m", "benchmarks", "run", "--profile", "smoke",
                 "--iterations", "1", "--no-memory", "--quiet",
                 "--output", str(output)],
                cwd=_BACKEND_DIR, capture_output=True, text=True, timeout=600,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            doc = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(validate_results(doc), [])
        self.assertEqual(doc["kind"], RESULT_KIND)
        self.assertEqual(doc["schema_version"], RESULT_SCHEMA_VERSION)
        self.assertEqual(doc["corpus_version"], CORPUS_VERSION)

        by_name = {b["name"]: b for b in doc["benchmarks"]}
        groups = {b["group"] for b in doc["benchmarks"]}
        self.assertEqual(
            groups, {"ingestion", "normalization", "detection", "queries", "memory"})

        rows = SIZES["xs"]
        # Ingestion benchmarks must actually have ingested the corpus rows.
        self.assertEqual(by_name["ingest_defender_jsonl_xs"]["counters"]["events"], rows)
        # Linux syslog lines carry no year: mtime-based inference must have
        # produced events rather than dropping rows.
        self.assertEqual(by_name["ingest_linux_log_xs"]["counters"]["events"], rows)
        # The mixed corpus is designed to fire detections.
        self.assertGreater(by_name["detect_rebuild_mixed_xs"]["counters"]["findings"], 0)
        # The entity graph must contain nodes and edges built from the case.
        self.assertGreater(by_name["query_entity_graph_xs"]["operations"], 0)
        self.assertGreater(by_name["memory_artifact_normalize_xs"]["counters"]["events"], 0)
        for bench in doc["benchmarks"]:
            self.assertEqual(len(bench["wall_seconds"]), 1)
            self.assertGreater(bench["operations"], 0)


class CompareTests(unittest.TestCase):
    def _doc(self) -> dict:
        return {
            "kind": RESULT_KIND,
            "schema_version": RESULT_SCHEMA_VERSION,
            "created_at": "2026-01-05T08:00:00+00:00",
            "profile": "full",
            "corpus_version": CORPUS_VERSION,
            "environment": {"commit": "abc123"},
            "benchmarks": [
                {
                    "name": "detect_rebuild_mixed_medium", "group": "detection",
                    "corpus_size": "medium", "iterations": 3, "operations": 5000,
                    "wall_seconds": [1.0, 1.02, 0.98], "wall_seconds_min": 0.98,
                    "wall_seconds_median": 1.0, "wall_seconds_mean": 1.0,
                    "ops_per_second": 5000.0, "peak_tracemalloc_bytes": 1000,
                    "counters": {"findings": 40},
                },
                {
                    "name": "query_timeline_medium", "group": "queries",
                    "corpus_size": "medium", "iterations": 3, "operations": 2000,
                    "wall_seconds": [0.20, 0.21, 0.19], "wall_seconds_min": 0.19,
                    "wall_seconds_median": 0.20, "wall_seconds_mean": 0.20,
                    "ops_per_second": 10000.0, "peak_tracemalloc_bytes": 1000,
                    "counters": {"total_matching": 2000},
                },
            ],
        }

    def test_identical_results_have_no_regressions(self) -> None:
        doc = self._doc()
        comparison = compare_mod.compare_results(doc, copy.deepcopy(doc))
        self.assertEqual(comparison["regressions"], [])
        self.assertEqual(comparison["counter_drift"], [])
        self.assertTrue(
            all(r["status"] == "unchanged" for r in comparison["benchmarks"]))

    def test_slowdown_over_threshold_is_flagged(self) -> None:
        base = self._doc()
        new = self._doc()
        new["benchmarks"][0]["wall_seconds_median"] = 1.3  # +30%
        comparison = compare_mod.compare_results(base, new, threshold=0.10)
        self.assertEqual(comparison["regressions"], ["detect_rebuild_mixed_medium"])
        row = next(r for r in comparison["benchmarks"]
                   if r["name"] == "detect_rebuild_mixed_medium")
        self.assertEqual(row["status"], "regressed")
        self.assertAlmostEqual(row["delta_percent"], 30.0, places=1)
        report = compare_mod.render_markdown(comparison)
        self.assertIn("detect_rebuild_mixed_medium", report)
        self.assertIn("1 regression(s) over threshold", report)

    def test_speedup_over_threshold_is_improvement(self) -> None:
        base = self._doc()
        new = self._doc()
        new["benchmarks"][1]["wall_seconds_median"] = 0.16  # -20%
        comparison = compare_mod.compare_results(base, new)
        self.assertEqual(comparison["improvements"], ["query_timeline_medium"])
        self.assertEqual(comparison["regressions"], [])

    def test_counter_drift_is_reported(self) -> None:
        base = self._doc()
        new = self._doc()
        new["benchmarks"][0]["counters"]["findings"] = 12
        comparison = compare_mod.compare_results(base, new)
        self.assertEqual(len(comparison["counter_drift"]), 1)
        self.assertEqual(comparison["counter_drift"][0]["name"],
                         "detect_rebuild_mixed_medium")
        self.assertIn("findings", comparison["counter_drift"][0]["drift"])
        self.assertIn("Counter drift", compare_mod.render_markdown(comparison))

    def test_different_corpus_versions_refuse_to_compare(self) -> None:
        base = self._doc()
        new = self._doc()
        new["corpus_version"] = "999.0.0"
        with self.assertRaises(ValueError):
            compare_mod.compare_results(base, new)

    def test_added_and_removed_benchmarks_are_listed(self) -> None:
        base = self._doc()
        new = self._doc()
        renamed = dict(new["benchmarks"].pop(1), name="query_timeline_v2_medium")
        new["benchmarks"].append(renamed)
        comparison = compare_mod.compare_results(base, new)
        self.assertEqual(comparison["only_in_base"], ["query_timeline_medium"])
        self.assertEqual(comparison["only_in_new"], ["query_timeline_v2_medium"])

    def test_validate_results_rejects_malformed_documents(self) -> None:
        self.assertTrue(validate_results({}))
        doc = self._doc()
        del doc["benchmarks"][0]["wall_seconds_median"]
        self.assertTrue(validate_results(doc))
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"kind": "other"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                compare_mod.load_results(bad)

    def test_compare_command_exit_codes(self) -> None:
        # The CLI must fail on regressions (unless --no-fail) so scripts and CI
        # can enforce the >10%-needs-an-explanation policy.
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "base.json"
            slow_path = Path(tmp) / "slow.json"
            base = self._doc()
            slow = self._doc()
            slow["benchmarks"][0]["wall_seconds_median"] = 1.5
            base_path.write_text(json.dumps(base), encoding="utf-8")
            slow_path.write_text(json.dumps(slow), encoding="utf-8")

            report = Path(tmp) / "report.md"
            self.assertEqual(
                benchmarks_main(["compare", str(base_path), str(base_path),
                                 "--output", str(report)]), 0)
            self.assertIn("No regressions over threshold", report.read_text("utf-8"))
            self.assertEqual(
                benchmarks_main(["compare", str(base_path), str(slow_path),
                                 "--output", str(report)]), 1)
            self.assertEqual(
                benchmarks_main(["compare", str(base_path), str(slow_path), "--no-fail",
                                 "--output", str(report)]), 0)


if __name__ == "__main__":
    unittest.main()
