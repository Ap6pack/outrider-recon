"""Drive the orchestrator over a ground-truth corpus and score it.

Everything here runs with a :class:`~outrider.executors.StubExecutor`, so a
corpus run is fully reproducible: no model, no network. This is the CI path.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from outrider.benchmark.corpus import GroundTruthCase, build_run, load_corpus
from outrider.benchmark.judge import CaseMetrics, judge_case
from outrider.benchmark.tally import tally
from outrider.executors import StubExecutor
from outrider.orchestrator import OrchestrationBounds, OrchestrationReport, run_orchestration


def run_case(case: GroundTruthCase, base_dir: str | Path, *, bounds: OrchestrationBounds | None = None) -> tuple[Path, OrchestrationReport]:
    run_dir, scripts, seeds = build_run(case, base_dir)
    report = run_orchestration(
        run_dir,
        executor=StubExecutor(scripts),
        actor="benchmark-operator",
        seeds=seeds,
        bounds=bounds or OrchestrationBounds(),
    )
    return run_dir, report


def run_benchmark(
    corpus_dir: str | Path,
    work_dir: str | Path,
    *,
    bounds: OrchestrationBounds | None = None,
    rebuild: bool = True,
) -> dict[str, Any]:
    """Build, run, judge and tally every case in ``corpus_dir``.

    When ``rebuild`` is false, existing run folders under ``work_dir`` are judged
    in place (used to regenerate metrics without re-running).
    """
    cases = load_corpus(corpus_dir)
    metrics: list[CaseMetrics] = []
    for case in cases:
        run_dir = Path(work_dir) / case.case_id
        if rebuild:
            if run_dir.exists():
                shutil.rmtree(run_dir)
            run_case(case, work_dir, bounds=bounds)
        metrics.append(judge_case(case, run_dir))
    return {
        "cases": [m.to_dict() for m in metrics],
        "totals": tally(metrics).to_dict(),
    }


def analyze_misses(corpus_dir: str | Path, work_dir: str | Path, *, bounds: OrchestrationBounds | None = None) -> list[dict[str, Any]]:
    """Return per-case expected-but-missing candidates and finding subjects."""
    cases = load_corpus(corpus_dir)
    out: list[dict[str, Any]] = []
    for case in cases:
        run_dir = Path(work_dir) / case.case_id
        if run_dir.exists():
            shutil.rmtree(run_dir)
        run_case(case, work_dir, bounds=bounds)
        m = judge_case(case, run_dir)
        out.append({
            "case_id": case.case_id,
            "missing_discovered": m.missing_discovered,
            "missing_finding_subjects": m.missing_finding_subjects,
            "unexpected_discovered": m.unexpected_discovered,
        })
    return out
