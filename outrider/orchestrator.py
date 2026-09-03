"""Governed agent-to-agent orchestrator loop (ADR 0017).

The orchestrator advances a run by repeatedly creating a ``skill_request``,
delegating execution to an injected :class:`~outrider.executors.Executor`, and
deriving the next hops from *validated* results. It introduces no new authority:
every hop is created through :func:`outrider.skill_contract.create_skill_request`
(which refuses when current scope, approval, evidence, or workflow state
disallow it), and it never promotes findings, transitions state, registers
evidence, or edits any append-only log directly.

Auto-dispatch is capped by action class:

* ``local_analysis`` and ``public_source_lookup`` may be auto-dispatched.
* ``target_read_only_request`` / ``target_enumeration`` (ACTIVE) are dispatched
  only when a current approval + allowed state already permit them.
* ``intrusive_validation`` and prohibited actions are handoff-only and are
  never auto-dispatched.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import time
from pathlib import Path
from typing import Any

from outrider.approval import ACTIVE, INTRUSIVE, LOCAL, PASSIVE, PROHIBITED, evaluate_action
from outrider.executors import Executor, ExecutorError
from outrider.skill_contract import (
    SkillContractValidationError,
    contract_revision,
    create_skill_request,
    ensure_contract_dirs,
    list_contract_inventory,
    load_skill_request,
    load_skill_result,
    validate_skill_result,
)
from outrider.state import StateValidationError, load_manifest, load_state, state_revision

AUTO_DISPATCH = frozenset(LOCAL | PASSIVE)
HANDOFF_ONLY = frozenset(INTRUSIVE | PROHIBITED)
DEFAULT_ROUTE_SKILL = "offensive-osint"


@dataclass(frozen=True)
class OrchestrationBounds:
    max_hops: int = 25
    max_requests: int = 50
    max_wall_clock_seconds: float = 300.0
    per_action_caps: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SeedRequest:
    skill: str
    action_type: str
    objective: str
    candidate: str | None = None
    evidence_ids: list[str] | None = None
    max_items: int = 100
    notes: str | None = None


@dataclass
class OrchestrationReport:
    run_id: str | None
    stop_reason: str
    hops: int = 0
    requests_created: int = 0
    results_valid: int = 0
    results_invalid: int = 0
    candidates_discovered: int = 0
    deferred: list[dict[str, Any]] = field(default_factory=list)
    log: list[dict[str, Any]] = field(default_factory=list)
    start_state_revision: str | None = None
    end_state_revision: str | None = None
    start_contract_revision: str | None = None
    end_contract_revision: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _request_key(skill: str, action_type: str, candidate: str | None) -> tuple[str, str, str | None]:
    return (skill, action_type, candidate)


def _pending_requests(run: Path) -> tuple[list[str], set[tuple[str, str, str | None]]]:
    """Return (relative paths of requests without a result, existing request keys).

    Used both for resume (re-enqueue unanswered requests) and dedup (never
    re-issue an identical skill/action/candidate hop).
    """
    inv = list_contract_inventory(run)
    answered: set[str] = set()
    for item in inv.get("results", []):
        rel = item.get("relative_path")
        if not rel:
            continue
        try:
            answered.add(load_skill_result(run, rel).request_id)
        except SkillContractValidationError:
            continue
    pending: list[str] = []
    keys: set[tuple[str, str, str | None]] = set()
    for item in inv.get("requests", []):
        rel = item.get("relative_path")
        if not rel:
            continue
        try:
            req = load_skill_request(run, rel)
        except SkillContractValidationError:
            continue
        keys.add(_request_key(req.skill, req.requested_action["action_type"], req.requested_action.get("candidate")))
        if req.request_id not in answered:
            pending.append(rel)
    return pending, keys


def orchestration_status(run_dir: str | Path) -> dict[str, Any]:
    """Summarize contract inventory and validity for ``orchestrate status``."""
    run = Path(run_dir)
    inv = list_contract_inventory(run)
    valid = invalid = 0
    for item in inv.get("results", []):
        rel = item.get("relative_path")
        if not rel:
            continue
        if validate_skill_result(run, rel).overall_status == "valid":
            valid += 1
        else:
            invalid += 1
    pending, _ = _pending_requests(run)
    try:
        current_state = load_state(run).current_state
    except StateValidationError as exc:
        current_state = f"unavailable ({exc})"
    return {
        "run_id": load_manifest(run).run_id,
        "current_state": current_state,
        "request_count": inv.get("request_count", 0),
        "result_count": inv.get("result_count", 0),
        "valid_result_count": valid,
        "invalid_result_count": invalid,
        "pending_request_count": len(pending),
    }


def run_orchestration(
    run_dir: str | Path,
    *,
    executor: Executor,
    actor: str,
    seeds: list[SeedRequest] | None = None,
    route_skill: str = DEFAULT_ROUTE_SKILL,
    bounds: OrchestrationBounds | None = None,
    default_objective: str = "orchestrated hop",
) -> OrchestrationReport:
    run = Path(run_dir)
    bounds = bounds or OrchestrationBounds()
    ensure_contract_dirs(run)
    manifest = load_manifest(run)
    start_state_rev = _safe_state_revision(run)
    report = OrchestrationReport(
        run_id=manifest.run_id,
        stop_reason="quiescent",
        start_state_revision=start_state_rev,
        start_contract_revision=_safe_contract_revision(run),
    )

    pending, requested_keys = _pending_requests(run)
    queue: list[str] = list(pending)
    created_by_action: dict[str, int] = {}

    # Seed new requests (deduped against existing ones).
    for seed in seeds or []:
        rel = _create_hop(
            run, report, requested_keys, created_by_action, bounds,
            skill=seed.skill, actor=actor, objective=seed.objective,
            action_type=seed.action_type, candidate=seed.candidate,
            evidence_ids=seed.evidence_ids, max_items=seed.max_items, notes=seed.notes,
            precheck=False,
        )
        if rel:
            queue.append(rel)

    start = time.monotonic()
    while queue:
        if report.hops >= bounds.max_hops:
            report.stop_reason = "max_hops"
            break
        if time.monotonic() - start >= bounds.max_wall_clock_seconds:
            report.stop_reason = "timeout"
            break
        if _safe_state_revision(run) != start_state_rev:
            report.stop_reason = "external_state_change"
            break

        request_rel = queue.pop(0)
        try:
            request = load_skill_request(run, request_rel)
        except SkillContractValidationError as exc:
            report.log.append({"event": "load_request_failed", "path": request_rel, "reason": str(exc)})
            continue

        try:
            result_path = executor.run(run, request)
        except ExecutorError as exc:
            report.log.append({"event": "executor_failed", "request_id": request.request_id, "reason": str(exc)})
            report.hops += 1
            continue

        report.hops += 1
        rel_result = Path(result_path).resolve().relative_to(run.resolve()).as_posix()
        validation = validate_skill_result(run, rel_result)
        if validation.overall_status != "valid":
            report.results_invalid += 1
            report.log.append({
                "event": "result_invalid", "request_id": request.request_id,
                "result_path": rel_result, "status": validation.overall_status,
                "reason": "; ".join(validation.errors),
            })
            continue

        report.results_valid += 1
        result = load_skill_result(run, rel_result)
        report.candidates_discovered += len(result.discovered_candidates)
        report.log.append({
            "event": "result_valid", "request_id": request.request_id,
            "result_id": result.result_id, "skill": result.skill,
            "discovered": len(result.discovered_candidates),
            "recommended": len(result.recommended_actions),
        })

        for rec in result.recommended_actions:
            if report.requests_created >= bounds.max_requests:
                report.stop_reason = "max_requests"
                queue.clear()
                break
            new_rel = _create_hop(
                run, report, requested_keys, created_by_action, bounds,
                skill=route_skill, actor=actor,
                objective=rec.get("reason") or default_objective,
                action_type=rec["action_type"], candidate=rec.get("candidate"),
                evidence_ids=None, max_items=100, notes=None, precheck=True,
            )
            if new_rel:
                queue.append(new_rel)

    report.end_state_revision = _safe_state_revision(run)
    report.end_contract_revision = _safe_contract_revision(run)
    return report


def _create_hop(
    run: Path,
    report: OrchestrationReport,
    requested_keys: set[tuple[str, str, str | None]],
    created_by_action: dict[str, int],
    bounds: OrchestrationBounds,
    *,
    skill: str,
    actor: str,
    objective: str,
    action_type: str,
    candidate: str | None,
    evidence_ids: list[str] | None,
    max_items: int,
    notes: str | None,
    precheck: bool,
) -> str | None:
    """Create one governed hop, or record why it was deferred/skipped.

    Returns the new request's relative path, or ``None`` when nothing was
    created. Dedup (never re-issue an identical skill/action/candidate hop)
    applies to both seeds and derived hops, so a re-run resumes rather than
    duplicates. ``precheck`` additionally gates *derived* hops through the
    action-class ceiling and current action policy; seeds skip that gate but
    ``create_skill_request`` still enforces policy and raises if disallowed.
    """
    if precheck and action_type in HANDOFF_ONLY:
        report.deferred.append({"action_type": action_type, "candidate": candidate, "reason": "handoff_only: requires separate human-reviewed authorization"})
        return None

    decision = evaluate_action(run, action_type, candidate)
    normalized = decision.normalized_candidate if decision.normalized_candidate is not None else candidate
    key = _request_key(skill, action_type, normalized)
    if key in requested_keys:
        return None

    if precheck:
        if decision.decision != "allow":
            report.deferred.append({"action_type": action_type, "candidate": normalized, "reason": decision.reason})
            return None
        if action_type not in AUTO_DISPATCH and action_type not in ACTIVE:
            report.deferred.append({"action_type": action_type, "candidate": normalized, "reason": "action class is not auto-dispatchable"})
            return None
        cap = bounds.per_action_caps.get(action_type)
        if cap is not None and created_by_action.get(action_type, 0) >= cap:
            report.deferred.append({"action_type": action_type, "candidate": normalized, "reason": f"per-action cap ({cap}) reached"})
            return None

    try:
        req, path, _ = create_skill_request(
            run, skill, actor, objective, action_type, candidate,
            evidence_ids or [], max_items, notes,
        )
    except SkillContractValidationError as exc:
        report.deferred.append({"action_type": action_type, "candidate": candidate, "reason": str(exc)})
        return None

    requested_keys.add(_request_key(req.skill, req.requested_action["action_type"], req.requested_action.get("candidate")))
    created_by_action[action_type] = created_by_action.get(action_type, 0) + 1
    report.requests_created += 1
    return path.resolve().relative_to(run.resolve()).as_posix()


def _safe_state_revision(run: Path) -> str | None:
    try:
        return state_revision(run)
    except StateValidationError:
        return None


def _safe_contract_revision(run: Path) -> str | None:
    try:
        return contract_revision(run)
    except SkillContractValidationError:
        return None
