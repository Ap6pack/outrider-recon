"""Deterministic benchmark harness for the governed orchestrator loop (ADR 0019).

The harness builds synthetic run folders from a ground-truth corpus, drives the
orchestrator with a :class:`~outrider.executors.StubExecutor` (no model, no
network), and scores conformance and coverage with a deterministic judge. It
measures the system under test against fixtures; it is not a live-model accuracy
benchmark. An optional model-assisted judge may be run offline but never in CI.
"""
from outrider.benchmark.corpus import CorpusError, GroundTruthCase, build_run, load_case, load_corpus
from outrider.benchmark.judge import CaseMetrics, judge_case
from outrider.benchmark.run import analyze_misses, run_benchmark, run_case
from outrider.benchmark.tally import Totals, tally

__all__ = [
    "CorpusError", "GroundTruthCase", "build_run", "load_case", "load_corpus",
    "CaseMetrics", "judge_case", "analyze_misses", "run_benchmark", "run_case", "Totals", "tally",
]
