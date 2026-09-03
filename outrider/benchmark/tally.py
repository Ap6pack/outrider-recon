"""Aggregate per-case metrics into corpus totals (deterministic)."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable

from outrider.benchmark.judge import CaseMetrics


@dataclass
class Totals:
    case_count: int
    results_total: int
    results_valid: int
    schema_validity_rate: float
    mean_discovered_precision: float
    mean_discovered_recall: float
    mean_discovered_f1: float
    mean_finding_candidate_coverage: float
    promoted_findings_total: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 6) if values else 1.0


def tally(metrics: Iterable[CaseMetrics]) -> Totals:
    items = list(metrics)
    results_total = sum(m.results_total for m in items)
    results_valid = sum(m.results_valid for m in items)
    return Totals(
        case_count=len(items),
        results_total=results_total,
        results_valid=results_valid,
        schema_validity_rate=round(results_valid / results_total, 6) if results_total else 1.0,
        mean_discovered_precision=_mean([m.discovered_precision for m in items]),
        mean_discovered_recall=_mean([m.discovered_recall for m in items]),
        mean_discovered_f1=_mean([m.discovered_f1 for m in items]),
        mean_finding_candidate_coverage=_mean([m.finding_candidate_coverage for m in items]),
        promoted_findings_total=sum(m.promoted_findings for m in items),
    )
