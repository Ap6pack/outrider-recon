"""Deterministic judge for benchmark cases (ADR 0019).

Scores a materialized run folder against a ground-truth case using only
persisted artifacts, so it can re-judge without re-running. It measures
conformance (skill_result schema-validity rate), coverage (did the loop surface
the expected discovered candidates and finding candidates), and — as a
guardrail — that the governed loop promoted nothing. Given the same run folder,
scoring is identical on every invocation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from outrider.benchmark.corpus import GroundTruthCase
from outrider.finding import list_findings
from outrider.scope import ScopeValidationError, _normalize_candidate
from outrider.skill_contract import list_contract_inventory, load_skill_result, validate_skill_result


def _norm(value: str) -> str:
    try:
        normalized, _type, _original = _normalize_candidate(value)
        return normalized
    except (ScopeValidationError, ValueError):
        return value.strip().lower()


def _prf(produced: set[str], expected: set[str]) -> tuple[float, float, float]:
    if not expected and not produced:
        return 1.0, 1.0, 1.0
    hits = len(produced & expected)
    precision = hits / len(produced) if produced else (1.0 if not expected else 0.0)
    recall = hits / len(expected) if expected else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


@dataclass
class CaseMetrics:
    case_id: str
    results_total: int
    results_valid: int
    schema_validity_rate: float
    discovered_precision: float
    discovered_recall: float
    discovered_f1: float
    finding_candidate_coverage: float
    promoted_findings: int
    missing_discovered: list[str] = field(default_factory=list)
    unexpected_discovered: list[str] = field(default_factory=list)
    missing_finding_subjects: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def judge_case(case: GroundTruthCase, run_dir: str | Path) -> CaseMetrics:
    run = Path(run_dir)
    inv = list_contract_inventory(run)
    results_total = 0
    results_valid = 0
    discovered: set[str] = set()
    finding_subjects: set[str] = set()
    for item in inv.get("results", []):
        rel = item.get("relative_path")
        if not rel:
            continue
        results_total += 1
        if validate_skill_result(run, rel).overall_status != "valid":
            continue
        results_valid += 1
        result = load_skill_result(run, rel)
        for cand in result.discovered_candidates:
            discovered.add(_norm(cand["candidate"]))
        for claim in result.claims:
            if claim.get("classification") == "finding_candidate":
                finding_subjects.add(_norm(claim["subject"]))

    expected_discovered = {_norm(x) for x in case.expected_discovered}
    expected_findings = {_norm(x) for x in case.expected_finding_subjects}
    precision, recall, f1 = _prf(discovered, expected_discovered)
    _, finding_coverage, _ = _prf(finding_subjects, expected_findings)

    return CaseMetrics(
        case_id=case.case_id,
        results_total=results_total,
        results_valid=results_valid,
        schema_validity_rate=(results_valid / results_total) if results_total else 1.0,
        discovered_precision=precision,
        discovered_recall=recall,
        discovered_f1=f1,
        finding_candidate_coverage=finding_coverage,
        promoted_findings=list_findings(run).finding_count,
        missing_discovered=sorted(expected_discovered - discovered),
        unexpected_discovered=sorted(discovered - expected_discovered),
        missing_finding_subjects=sorted(expected_findings - finding_subjects),
    )
