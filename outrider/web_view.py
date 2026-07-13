from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from outrider.approval import ApprovalValidationError, action_class, approval_policy_catalog, approval_revision, list_approvals, MAX_LIFETIME
from outrider.evidence import EvidenceValidationError, load_evidence_registry, verify_all_evidence
from outrider.finding import FindingValidationError, list_findings, verify_all_findings
from outrider.scope import ScopeValidationError, load_scope, scope_revision, load_scope_document
from outrider.skill_contract import (
    SkillContractValidationError,
    load_skill_request,
    load_skill_result,
    validate_skill_request,
    validate_skill_result,
)
from outrider.state import ALLOWED_TRANSITIONS, REASON_REQUIRED, StateValidationError, load_manifest, load_state

CONTROL_FILES = ("manifest.json", "scope.yaml", "run.jsonl", "evidence.jsonl", "approvals.jsonl", "findings.jsonl")

@dataclass(frozen=True)
class ViewError:
    section: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _clean(value: BaseException | str) -> str:
    text = str(value).replace("\\", "/")
    for marker in ("manifest.json", "scope.yaml", "run.jsonl", "evidence.jsonl", "approvals.jsonl", "findings.jsonl", "contracts/requests", "contracts/results", "artifacts/"):
        if marker in text:
            text = text[text.find(marker):]
    return text.split("\n", 1)[0][:240]


def _ok(section: str, fn: Callable[[], Any]) -> tuple[Any | None, list[ViewError]]:
    try:
        return fn(), []
    except Exception as exc:  # isolate malformed subsection data
        return None, [ViewError(section, _clean(exc))]


def _rule(rule: Any) -> dict[str, str]:
    return {"original": rule.original, "kind": rule.kind, "value": str(rule.value)}


def _run_root(root: str | Path) -> Path:
    path = Path(root)
    if path.is_symlink():
        raise ValueError("runs root must not be a symlink")
    if not path.exists():
        raise ValueError("runs root does not exist")
    if not path.is_dir():
        raise ValueError("runs root must be a directory")
    return path


def _manifest_path(child: Path) -> Path:
    return child / "manifest.json"


def discover_run_dirs(runs_root: str | Path) -> dict[str, Path]:
    root = _run_root(runs_root)
    found: dict[str, Path] = {}
    duplicates: set[str] = set()
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not child.is_dir() or child.is_symlink():
            continue
        if not _manifest_path(child).is_file():
            continue
        try:
            manifest = load_manifest(child)
        except StateValidationError:
            continue
        if manifest.run_id in found:
            duplicates.add(manifest.run_id)
        else:
            found[manifest.run_id] = child
    for run_id in duplicates:
        found.pop(run_id, None)
    return found


def _run_dir_for_id(runs_root: str | Path, run_id: str) -> Path | None:
    UUID(run_id)
    return discover_run_dirs(runs_root).get(run_id)


def _health(errors: list[ViewError], warning_count: int = 0) -> str:
    if errors:
        return "error"
    if warning_count:
        return "warning"
    return "healthy"


def list_runs(runs_root: str | Path) -> dict[str, Any]:
    root = _run_root(runs_root)
    items: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    dupes: set[str] = set()
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not child.is_dir() or child.is_symlink():
            continue
        if not _manifest_path(child).is_file():
            continue
        manifest, errors = _ok("manifest", lambda c=child: load_manifest(c))
        if manifest is None:
            items.append({"run_id": None, "directory_name": child.name, "target": child.name, "created_at": None, "current_state": None, "evidence_count": 0, "active_approval_count": 0, "request_count": 0, "result_count": 0, "finding_count": 0, "health": "error", "summary": errors[0].message})
            continue
        if manifest.run_id in seen:
            dupes.add(manifest.run_id)
            continue
        seen[manifest.run_id] = child.name
        overview = run_overview(child)
        items.append({"run_id": manifest.run_id, "target": manifest.target, "created_at": manifest.created_at, "current_state": overview.get("current_state"), "evidence_count": overview["evidence_summary"]["count"], "active_approval_count": overview["approval_summary"]["active_count"], "request_count": overview["contract_summary"]["request_count"], "result_count": overview["contract_summary"]["result_count"], "finding_count": overview["finding_summary"]["count"], "health": overview["health"]["status"], "summary": overview["health"]["summary"]})
    if dupes:
        for run_id in sorted(dupes):
            items = [i for i in items if i.get("run_id") != run_id]
            items.append({"run_id": run_id, "directory_name": None, "target": "duplicate run ID", "created_at": None, "current_state": None, "evidence_count": 0, "active_approval_count": 0, "request_count": 0, "result_count": 0, "finding_count": 0, "health": "error", "summary": "duplicate run_id detected; no run selected"})
    return {"runs": items, "total": len(items)}


def scope_view(run_dir: str | Path) -> dict[str, Any]:
    scope, errors = _ok("scope", lambda: load_scope(run_dir))
    current_state = None
    try:
        current_state = load_state(run_dir).current_state
    except Exception:
        current_state = None
    editable = current_state == "initialized"
    rev = None
    control = None
    try:
        rev = scope_revision(run_dir)
        doc = load_scope_document(run_dir)
        if isinstance(doc.get("scope_control"), dict):
            sc = doc["scope_control"]
            control = {k: sc.get(k) for k in ("schema_version", "revision_number", "last_updated_at", "last_updated_by", "last_change_reason", "history") if k in sc}
    except Exception:
        pass
    base = {"scope_revision": rev, "editable": editable, "edit_reason": None if editable else "scope changes are web-enabled only while the run is initialized", "current_state": current_state, "scope_control": control}
    if scope is None:
        return {**base, "valid": False, "in_scope": [], "out_of_scope": [], "counts": {"in_scope": 0, "out_of_scope": 0}, "errors": [e.to_dict() for e in errors]}
    return {**base, "valid": True, "in_scope": [_rule(r) for r in scope.in_scope], "out_of_scope": [_rule(r) for r in scope.out_of_scope], "counts": {"in_scope": len(scope.in_scope), "out_of_scope": len(scope.out_of_scope)}, "errors": []}


def allowed_state_transitions(current_state: str | None) -> list[dict[str, Any]]:
    if current_state not in ALLOWED_TRANSITIONS:
        return []
    return [
        {"new_state": new_state, "reason_required": new_state == "cancelled" or (current_state, new_state) in REASON_REQUIRED}
        for new_state in sorted(ALLOWED_TRANSITIONS[current_state])
    ]


def state_view(run_dir: str | Path) -> dict[str, Any]:
    summary, errors = _ok("state", lambda: load_state(run_dir))
    events: list[dict[str, Any]] = []
    if summary:
        event_log = Path(run_dir) / load_manifest(run_dir).event_log
        for line in event_log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                data = json.loads(line)
                events.append({k: data.get(k) for k in ("sequence", "event_type", "occurred_at", "actor", "previous_state", "new_state", "reason")})
    current_state = getattr(summary, "current_state", None)
    return {"valid": summary is not None, "current_state": current_state, "allowed_transitions": allowed_state_transitions(current_state), "event_count": getattr(summary, "event_count", 0), "last_transition_at": getattr(summary, "last_transition_at", None), "events": events, "errors": [e.to_dict() for e in errors]}


def evidence_view(run_dir: str | Path) -> dict[str, Any]:
    registry, errors = _ok("evidence", lambda: load_evidence_registry(run_dir))
    verifications, verr = _ok("evidence", lambda: verify_all_evidence(run_dir))
    errors += verr
    by_id = {v.evidence_id: v for v in (verifications or [])}
    records = []
    for rec in getattr(registry, "records", ()):
        v = by_id.get(rec.evidence_id)
        records.append({"evidence_id": rec.evidence_id, "sequence": rec.sequence, "relative_artifact_path": rec.path, "artifact_type": rec.artifact_type, "media_type": rec.media_type, "source": rec.source, "actor": rec.actor, "registered_at": rec.registered_at, "expected_sha256": rec.sha256, "expected_size": rec.size_bytes, "verification_status": getattr(v, "status", "unknown"), "verification_reason": getattr(v, "reason", "not verified")})
    return {"valid": registry is not None, "evidence_count": len(records), "records": records, "errors": [e.to_dict() for e in errors]}


def approval_view(run_dir: str | Path) -> dict[str, Any]:
    summary, errors = _ok("approvals", lambda: list_approvals(run_dir))
    current_state = None
    try:
        current_state = load_state(run_dir).current_state
    except Exception:
        pass
    approvals = []
    for a in getattr(summary, "approvals", ()):
        revocable = a.status == "active"
        approvals.append({"approval_id": a.approval_id, "action_type": a.action_type, "action_class": action_class(a.action_type), "normalized_candidate": a.candidate, "candidate_type": a.candidate_type, "actor": a.actor, "granted_at": a.occurred_at, "expires_at": a.expires_at, "current_status": a.status, "revocable": revocable, "revocation_disabled_reason": None if revocable else f"approval is {a.status}", "revoked_at": a.revoked_at, "revoked_by": a.revoked_by, "revocation_reason": a.revocation_reason, "reason": a.reason, "conditions": a.conditions})
    grant_enabled = current_state in {"scoped", "collecting", "analyzing"}
    return {"valid": summary is not None, "current_state": current_state, "approval_revision": approval_revision(run_dir), "grant_enabled": grant_enabled, "grant_disabled_reason": None if grant_enabled else f"approval grants are not permitted in state {current_state}", "max_lifetime_minutes": int(MAX_LIFETIME.total_seconds() // 60), "action_types": approval_policy_catalog(), "approval_count": len(approvals), "active_count": getattr(summary, "active_count", 0), "expired_count": getattr(summary, "expired_count", 0), "revoked_count": getattr(summary, "revoked_count", 0), "approvals": approvals, "errors": [e.to_dict() for e in errors], "notice": "Actor values are attribution only; approvals are not proof of written authorization. An active approval alone does not guarantee an action is currently allowed; evaluate_action remains a point-in-time policy check."}


def _json_files(base: Path) -> list[Path]:
    if not base.exists() or base.is_symlink() or not base.is_dir():
        return []
    return [p for p in sorted(base.iterdir(), key=lambda x: x.name) if p.is_file() and not p.is_symlink() and p.suffix == ".json"]


def contract_view(run_dir: str | Path) -> dict[str, Any]:
    run = Path(run_dir)
    requests = []
    results = []
    errors: list[ViewError] = []
    for path in _json_files(run / "contracts" / "requests"):
        rel = path.relative_to(run).as_posix()
        req, err = _ok("contracts", lambda rel=rel: load_skill_request(run, rel))
        rep = validate_skill_request(run, rel)
        if err: errors += err
        if req:
            requests.append({"request_id": req.request_id, "skill": req.skill, "objective": req.objective, "requested_action": req.requested_action, "candidate": req.candidate, "created_at": req.created_at, "validation_result": rep.overall_status, "policy_decision": rep.current_request_policy_decision, "evidence_status": "valid" if rep.evidence_ids_valid else "error"})
    for path in _json_files(run / "contracts" / "results"):
        rel = path.relative_to(run).as_posix()
        res, err = _ok("contracts", lambda rel=rel: load_skill_result(run, rel))
        rep = validate_skill_result(run, rel)
        if err: errors += err
        if res:
            results.append({"result_id": res.result_id, "request_id": res.request_id, "skill": res.skill, "completion_status": res.status, "summary": res.summary, "claim_count": len(res.claims), "discovered_candidate_count": len(res.discovered_candidates), "recommended_action_count": len(res.recommended_actions), "validation_result": rep.overall_status, "evidence_status": "valid" if rep.evidence_ids_valid else "error"})
    return {"valid": not errors, "requests": requests, "results": results, "request_count": len(requests), "result_count": len(results), "errors": [e.to_dict() for e in errors], "notice": "finding_candidate entries are skill output; validated_finding entries are human-reviewed local promotions."}


def finding_view(run_dir: str | Path) -> dict[str, Any]:
    registry, errors = _ok("findings", lambda: list_findings(run_dir))
    verifications, verr = _ok("findings", lambda: verify_all_findings(run_dir))
    errors += verr
    by_id = {v.finding_id: v for v in (verifications or [])}
    findings = []
    for f in getattr(registry, "records", ()):
        v = by_id.get(f.finding_id)
        findings.append({"finding_id": f.finding_id, "title": f.title, "affected_candidate": f.affected_candidate, "location": f.location, "severity": f.severity, "confidence": f.confidence, "reviewer": f.promoted_by, "promoted_at": f.promoted_at, "source_skill": f.source.skill, "source_result_id": f.source.result_id, "source_claim_id": f.source.claim_id, "evidence_ids": f.evidence_ids, "source_result_integrity_status": getattr(v, "source_status", "unknown"), "evidence_integrity_status": getattr(v, "evidence_status", "unknown"), "current_scope_status": getattr(v, "current_scope_status", "unknown"), "overall_verification_status": getattr(v, "overall_status", "unknown")})
    return {"valid": registry is not None, "finding_count": len(findings), "findings": findings, "errors": [e.to_dict() for e in errors], "notice": "validated_finding represents human-reviewed local promotion; it does not prove exploitation, authenticated reviewer identity, or client acceptance."}


def integrity_view(run_dir: str | Path) -> dict[str, Any]:
    sections = {"manifest": _ok("manifest", lambda: load_manifest(run_dir)), "state": _ok("state", lambda: load_state(run_dir)), "scope": _ok("scope", lambda: load_scope(run_dir)), "evidence": _ok("evidence", lambda: load_evidence_registry(run_dir)), "approvals": _ok("approvals", lambda: list_approvals(run_dir)), "findings": _ok("findings", lambda: list_findings(run_dir))}
    errors = [e for _, es in sections.values() for e in es]
    ev = evidence_view(run_dir); fv = finding_view(run_dir); cv = contract_view(run_dir)
    errors += [ViewError(e["section"], e["message"]) for e in ev["errors"] + fv["errors"] + cv["errors"]]
    ev_counts = {"verified": 0, "mismatch": 0, "missing": 0, "other": 0}
    for r in ev["records"]:
        s = r["verification_status"]
        ev_counts["verified" if s == "verified" else "mismatch" if "mismatch" in s else "missing" if "missing" in s else "other"] += 1
    f_counts = {"verified": 0, "invalid": 0, "other": 0}
    for f in fv["findings"]:
        s = f["overall_verification_status"]
        f_counts["verified" if s == "verified" else "invalid" if s == "invalid" else "other"] += 1
    return {"manifest_valid": not sections["manifest"][1], "state_stream_valid": not sections["state"][1], "scope_valid": not sections["scope"][1], "evidence_registry_valid": ev["valid"], "evidence_verification_counts": ev_counts, "approval_registry_valid": not sections["approvals"][1], "contract_validation_counts": {"requests": cv["request_count"], "results": cv["result_count"], "errors": len(cv["errors"])}, "finding_registry_valid": fv["valid"], "finding_verification_counts": f_counts, "warnings": [], "errors": [e.to_dict() for e in errors], "health": _health(errors)}


def run_overview(run_dir: str | Path) -> dict[str, Any]:
    manifest, errors = _ok("manifest", lambda: load_manifest(run_dir))
    sv = state_view(run_dir); sc = scope_view(run_dir); ev = evidence_view(run_dir); av = approval_view(run_dir); cv = contract_view(run_dir); fv = finding_view(run_dir)
    all_errors = errors + [ViewError(e["section"], e["message"]) for block in (sv, sc, ev, av, cv, fv) for e in block.get("errors", [])]
    return {"run_id": getattr(manifest, "run_id", None), "target": getattr(manifest, "target", None), "engagement_type": getattr(manifest, "engagement_type", None), "created_at": getattr(manifest, "created_at", None), "actor": getattr(manifest, "created_by", None), "current_state": sv["current_state"], "last_transition_at": sv["last_transition_at"], "control_files": list(CONTROL_FILES), "scope_summary": {"valid": sc["valid"], **sc["counts"]}, "evidence_summary": {"valid": ev["valid"], "count": ev["evidence_count"]}, "approval_summary": {"valid": av["valid"], "count": av["approval_count"], "active_count": av["active_count"]}, "contract_summary": {"valid": cv["valid"], "request_count": cv["request_count"], "result_count": cv["result_count"]}, "finding_summary": {"valid": fv["valid"], "count": fv["finding_count"]}, "health": {"status": _health(all_errors), "summary": "; ".join(e.message for e in all_errors[:3]) or "healthy", "errors": [e.to_dict() for e in all_errors]}}


def view_for_run_id(runs_root: str | Path, run_id: str, view: str) -> dict[str, Any] | None:
    run_dir = _run_dir_for_id(runs_root, run_id)
    if run_dir is None:
        return None
    return {"overview": run_overview, "scope": scope_view, "state": state_view, "evidence": evidence_view, "approvals": approval_view, "contracts": contract_view, "findings": finding_view, "integrity": integrity_view}[view](run_dir)
