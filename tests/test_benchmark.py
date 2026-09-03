from __future__ import annotations
import dataclasses
import tempfile
import unittest
from pathlib import Path

from outrider.benchmark import (
    CorpusError,
    analyze_misses,
    build_run,
    judge_case,
    load_case,
    load_corpus,
    run_benchmark,
    run_case,
    tally,
)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "outrider" / "benchmark" / "ground_truth"


class CorpusLoadingTests(unittest.TestCase):
    def test_corpus_loads_all_cases(self):
        cases = load_corpus(CORPUS)
        self.assertGreaterEqual(len(cases), 2)
        ids = {c.case_id for c in cases}
        self.assertIn("case-a-subdomain-swagger", ids)
        self.assertIn("case-b-granted-enumeration", ids)

    def test_malformed_case_raises(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text('{"schema_version": 1}', encoding="utf-8")
            with self.assertRaises(CorpusError):
                load_case(bad)

    def test_missing_corpus_dir_raises(self):
        with self.assertRaises(CorpusError):
            load_corpus(Path("/nonexistent/corpus/dir"))


class JudgeTests(unittest.TestCase):
    def test_case_a_scores_and_promotes_nothing(self):
        case = load_case(CORPUS / "case-a-subdomain-swagger.json")
        with tempfile.TemporaryDirectory() as td:
            run_dir, report = run_case(case, td)
            metrics = judge_case(case, run_dir)
            self.assertEqual(metrics.results_valid, metrics.results_total)
            self.assertEqual(metrics.results_valid, 2)      # seed + passive api hop
            self.assertEqual(metrics.discovered_recall, 1.0)
            self.assertEqual(metrics.discovered_precision, 1.0)
            self.assertEqual(metrics.finding_candidate_coverage, 1.0)
            self.assertEqual(metrics.promoted_findings, 0)   # governed loop never promotes
            # Intrusive follow-up was deferred, not dispatched.
            self.assertTrue(any(d["action_type"] == "intrusive_validation" for d in report.deferred))

    def test_case_b_dispatches_granted_active_hop(self):
        case = load_case(CORPUS / "case-b-granted-enumeration.json")
        with tempfile.TemporaryDirectory() as td:
            run_dir, report = run_case(case, td)
            metrics = judge_case(case, run_dir)
            self.assertEqual(metrics.finding_candidate_coverage, 1.0)
            self.assertEqual(metrics.promoted_findings, 0)
            # The ACTIVE enumeration hop ran because a standing approval existed.
            self.assertGreaterEqual(metrics.results_valid, 2)

    def test_judge_detects_a_miss(self):
        case = load_case(CORPUS / "case-a-subdomain-swagger.json")
        with tempfile.TemporaryDirectory() as td:
            run_dir, _ = run_case(case, td)
            harder = dataclasses.replace(
                case, expected_discovered=case.expected_discovered + ["ghost.example.com"]
            )
            metrics = judge_case(harder, run_dir)
            self.assertIn("ghost.example.com", metrics.missing_discovered)
            self.assertLess(metrics.discovered_recall, 1.0)


class BenchmarkRunTests(unittest.TestCase):
    def test_run_benchmark_is_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first = run_benchmark(CORPUS, a)
            second = run_benchmark(CORPUS, b)
            self.assertEqual(first, second)  # identical metrics across independent runs

    def test_totals_are_clean_on_shipped_corpus(self):
        with tempfile.TemporaryDirectory() as td:
            result = run_benchmark(CORPUS, td)
            totals = result["totals"]
            self.assertEqual(totals["promoted_findings_total"], 0)
            self.assertEqual(totals["schema_validity_rate"], 1.0)
            self.assertEqual(totals["mean_finding_candidate_coverage"], 1.0)
            self.assertEqual(totals["mean_discovered_recall"], 1.0)
            self.assertEqual(totals["case_count"], len(load_corpus(CORPUS)))

    def test_analyze_misses_clean_on_shipped_corpus(self):
        with tempfile.TemporaryDirectory() as td:
            misses = analyze_misses(CORPUS, td)
            for entry in misses:
                self.assertEqual(entry["missing_discovered"], [])
                self.assertEqual(entry["missing_finding_subjects"], [])

    def test_build_run_registers_evidence_and_scope(self):
        case = load_case(CORPUS / "case-a-subdomain-swagger.json")
        with tempfile.TemporaryDirectory() as td:
            run_dir, scripts, seeds = build_run(case, td)
            self.assertTrue((run_dir / "manifest.json").is_file())
            self.assertTrue((run_dir / "scope.yaml").is_file())
            self.assertIn("*", scripts)
            self.assertEqual(seeds[0].action_type, "local_analysis")


if __name__ == "__main__":
    unittest.main()
