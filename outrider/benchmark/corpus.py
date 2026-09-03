"""Load a ground-truth corpus and build synthetic run folders from it.

A corpus case is a ``ground_truth`` v1 document (see
``contracts/ground-truth-v1.schema.json``). Building a case produces a real
Outrider run folder (manifest, scope, evidence registry, contract dirs) plus the
resolved :class:`~outrider.executors.StubExecutor` scripts and seed requests the
harness replays. Fixtures are synthetic and must not contain real secrets; any
secret-shaped value should be assembled from fragments by the case author.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from outrider.evidence import register_evidence
from outrider.executors import ResultScript
from outrider.orchestrator import SeedRequest
from outrider.run_setup import render_scope_yaml
from outrider.state import initialize_state, transition_state
from outrider.approval import grant_approval

CORPUS_ACTOR = "benchmark-operator"


class CorpusError(ValueError):
    """Raised when a ground-truth case is malformed."""


@dataclass(frozen=True)
class GroundTruthCase:
    case_id: str
    target: str
    in_scope: list[str]
    out_of_scope: list[str]
    evidence: list[dict[str, Any]]
    seeds: list[dict[str, Any]]
    grants: list[dict[str, Any]]
    scripts: dict[str, dict[str, Any]]
    expected_discovered: list[str]
    expected_finding_subjects: list[str]
    description: str = ""


def _require(data: dict[str, Any], key: str) -> Any:
    if key not in data:
        raise CorpusError(f"ground_truth case missing required field: {key}")
    return data[key]


def load_case(path: str | Path) -> GroundTruthCase:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"cannot read ground_truth case {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CorpusError("ground_truth case must be a JSON object")
    if data.get("schema_version") != 1 or data.get("contract_type") != "ground_truth":
        raise CorpusError("ground_truth case must declare schema_version 1 and contract_type ground_truth")
    expected = _require(data, "expected")
    if not isinstance(expected, dict):
        raise CorpusError("expected must be an object")
    return GroundTruthCase(
        case_id=_require(data, "case_id"),
        target=_require(data, "target"),
        in_scope=list(_require(data, "in_scope")),
        out_of_scope=list(data.get("out_of_scope", [])),
        evidence=list(_require(data, "evidence")),
        seeds=list(_require(data, "seeds")),
        grants=list(data.get("grants", [])),
        scripts=dict(_require(data, "scripts")),
        expected_discovered=list(_require(expected, "discovered_candidates")),
        expected_finding_subjects=list(_require(expected, "finding_candidate_subjects")),
        description=str(data.get("description", "")),
    )


def load_corpus(corpus_dir: str | Path) -> list[GroundTruthCase]:
    root = Path(corpus_dir)
    if not root.is_dir():
        raise CorpusError(f"corpus directory not found: {root}")
    cases = [load_case(p) for p in sorted(root.glob("*.json"))]
    if not cases:
        raise CorpusError(f"no ground_truth cases found under {root}")
    return cases


def _resolve_evidence(refs: Any, mapping: dict[str, str], field_name: str) -> list[str]:
    if not isinstance(refs, list):
        raise CorpusError(f"{field_name} must be an array of evidence refs")
    out = []
    for ref in refs:
        if ref not in mapping:
            raise CorpusError(f"unknown evidence ref {ref!r} in {field_name}")
        out.append(mapping[ref])
    return out


def _resolve_script(spec: dict[str, Any], mapping: dict[str, str]) -> ResultScript:
    claims = []
    for claim in spec.get("claims", []):
        entry = {k: v for k, v in claim.items() if k not in {"evidence", "evidence_ids"}}
        entry["evidence_ids"] = _resolve_evidence(claim.get("evidence", claim.get("evidence_ids", [])), mapping, "claim evidence")
        claims.append(entry)
    discovered = []
    for cand in spec.get("discovered_candidates", []):
        entry = {k: v for k, v in cand.items() if k not in {"source_evidence", "source_evidence_ids"}}
        entry["source_evidence_ids"] = _resolve_evidence(cand.get("source_evidence", cand.get("source_evidence_ids", [])), mapping, "discovered source_evidence")
        discovered.append(entry)
    return ResultScript(
        status=spec.get("status", "completed"),
        summary=spec.get("summary", "benchmark result"),
        claims=claims,
        discovered_candidates=discovered,
        recommended_actions=list(spec.get("recommended_actions", [])),
        errors=list(spec.get("errors", [])),
    )


def build_run(case: GroundTruthCase, base_dir: str | Path) -> tuple[Path, dict[str, ResultScript], list[SeedRequest]]:
    """Materialize a run folder for ``case`` under ``base_dir`` and resolve scripts.

    Returns ``(run_dir, scripts, seeds)`` ready to hand to the orchestrator with
    a :class:`StubExecutor`.
    """
    run = Path(base_dir) / case.case_id
    run.mkdir(parents=True, exist_ok=False)
    (run / "scope.yaml").write_text(render_scope_yaml(case.target, case.in_scope, case.out_of_scope), encoding="utf-8")
    initialize_state(run, case.target, CORPUS_ACTOR, f"BENCH-{case.case_id}")
    for name in ("evidence.jsonl", "approvals.jsonl", "findings.jsonl"):
        (run / name).write_text("", encoding="utf-8")
    (run / "artifacts").mkdir()
    for rel in ("contracts", "contracts/requests", "contracts/results"):
        (run / rel).mkdir(parents=True, exist_ok=True)

    mapping: dict[str, str] = {}
    for item in case.evidence:
        rel_path = _require(item, "path")
        artifact = run / rel_path
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(item.get("content", ""), encoding="utf-8")
        record = register_evidence(run, rel_path, CORPUS_ACTOR, _require(item, "artifact_type"))
        mapping[_require(item, "ref")] = record.evidence_id

    transition_state(run, "scoped", CORPUS_ACTOR)
    for grant in case.grants:
        grant_approval(run, grant["action_type"], grant["candidate"], CORPUS_ACTOR, "benchmark grant", duration_minutes=60)

    scripts = {key: _resolve_script(spec, mapping) for key, spec in case.scripts.items()}
    seeds = [
        SeedRequest(
            skill=_require(s, "skill"), action_type=_require(s, "action_type"),
            objective=_require(s, "objective"), candidate=s.get("candidate"),
        )
        for s in case.seeds
    ]
    return run, scripts, seeds
