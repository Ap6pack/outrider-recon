from __future__ import annotations

import hashlib, json
from pathlib import Path
from typing import Any

from outrider.evidence import evidence_revision, verify_all_evidence
from outrider.finding import finding_revision, list_finding_candidates, verify_all_findings, list_findings
from outrider.scope import load_scope, load_scope_document, scope_revision
from outrider.skill_contract import contract_revision, list_contract_inventory, validate_skill_result
from outrider.state import load_manifest, load_state, state_revision

PHASE_LABELS = {
    "initialized": ("setup", "Setup"), "scoped": ("scope_confirmed", "Scope confirmed"),
    "collecting": ("discovery", "Discovery"), "analyzing": ("analysis", "Analysis"),
    "reporting": ("findings", "Findings"), "completed": ("completed", "Completed"),
    "cancelled": ("cancelled", "Cancelled"), "archived": ("archived", "Archived"),
}
GUIDE_ACTION_TARGETS = {"confirm_scope":"scoped","begin_discovery":"collecting","begin_analysis":"analyzing","begin_findings":"reporting","complete_engagement":"completed"}
NOTICE = "Guidance is derived from current local run data and performs no action."

def _action(id: str, label: str, desc: str, kind: str, target: str | None, available=True, requires_confirmation=False, blocked_reason=None):
    return {"id":id,"label":label,"description":desc,"kind":kind,"target_view":target,"available":available,"requires_confirmation":requires_confirmation,"blocked_reason":blocked_reason}

def _safe(fn, default):
    try: return fn(), []
    except Exception as exc: return default, [str(exc).split('\n',1)[0][:200]]

def _metadata(run_dir: Path):
    doc,_ = _safe(lambda: load_scope_document(run_dir), {})
    tagging = doc.get("traffic_tagging") if isinstance(doc.get("traffic_tagging"), dict) else {}
    headers = tagging.get("headers") if isinstance(tagging.get("headers"), dict) else {}
    return {"engagement_platform": doc.get("engagement_platform"), "traffic_header_configured": bool(headers)}

def _contract_counts(run_dir: Path):
    inv, errs = _safe(lambda: list_contract_inventory(run_dir), {"requests":[],"results":[]})
    valid_results=invalid_results=0
    for item in inv.get("results", []):
        if item.get("error"):
            invalid_results += 1; continue
        rep = validate_skill_result(run_dir, item["relative_path"])
        if rep.overall_status == "valid": valid_results += 1
        else: invalid_results += 1
    return inv, valid_results, invalid_results, errs

def _milestones(run_dir: Path):
    scope_obj, scope_errors = _safe(lambda: load_scope(run_dir), None)
    evs, ev_errors = _safe(lambda: verify_all_evidence(run_dir), [])
    inv, valid_results, invalid_results, contract_errors = _contract_counts(run_dir)
    cands, cand_errors = _safe(lambda: list_finding_candidates(run_dir), {"candidates":[],"candidate_count":0})
    finds, find_errors = _safe(lambda: list_findings(run_dir), None)
    fver, fver_errors = _safe(lambda: verify_all_findings(run_dir), [])
    promoted = len(getattr(finds, "records", ()) or [])
    unpromoted = sum(1 for c in cands.get("candidates", []) if not c.get("already_promoted"))
    return {
        "scope_valid": scope_obj is not None,
        "evidence_count": len(evs),
        "verified_evidence_count": sum(1 for v in evs if getattr(v,"status",None)=="verified"),
        "request_count": len(inv.get("requests", [])), "result_count": len(inv.get("results", [])),
        "valid_result_count": valid_results, "invalid_result_count": invalid_results,
        "unpromoted_candidate_count": unpromoted, "finding_count": promoted,
        "unverified_finding_count": sum(1 for v in fver if getattr(v,"overall_status",None)!="verified"),
        "errors": scope_errors + ev_errors + contract_errors + cand_errors + find_errors + fver_errors,
    }

def _progress(current: str, m: dict[str, Any], integrity_error: bool):
    order=[("setup","Setup"),("scope","Scope"),("discovery","Discovery"),("evidence","Evidence"),("analysis","Analysis"),("findings","Findings"),("complete","Complete")]
    rank={"initialized":1,"scoped":2,"collecting":2,"analyzing":4,"reporting":5,"completed":6,"archived":6,"cancelled":-1}.get(current,0)
    out=[]
    for i,(id,label) in enumerate(order):
        status="upcoming"
        if integrity_error and id in {"setup","scope"}: status="blocked"
        elif current=="cancelled": status="blocked" if id not in {"setup"} else "complete"
        elif id=="setup": status="complete"
        elif id=="scope": status="current" if current=="initialized" else ("complete" if rank>=2 and m["scope_valid"] else "blocked")
        elif id=="discovery": status="current" if current in {"scoped","collecting"} and not m["verified_evidence_count"] else ("complete" if rank>=4 else "upcoming")
        elif id=="evidence": status="complete" if m["verified_evidence_count"] or rank>=4 else ("current" if current=="collecting" and m["evidence_count"] else "upcoming")
        elif id=="analysis": status="current" if current=="analyzing" else ("complete" if rank>=5 else "upcoming")
        elif id=="findings": status="current" if current=="reporting" else ("complete" if rank>=6 else "upcoming")
        elif id=="complete": status="complete" if current in {"completed","archived"} else "upcoming"
        out.append({"id":id,"label":label,"status":status})
    return out

def _next(current: str, m: dict[str,Any], enrichment_enabled: bool, integrity_error: bool):
    if integrity_error: return _action("review_integrity","Review Engagement Issue","Review the engagement integrity issue before continuing.","navigation","integrity",False,False,"Engagement integrity must be resolved before guided transitions are available.")
    if current=="initialized":
        return _action("review_scope","Review Scope","Confirm that the listed rules match your written authorization.","review","scope",m["scope_valid"],False,None if m["scope_valid"] else "Scope must be valid before it can be confirmed.") if m["scope_valid"] else _action("fix_scope","Fix Scope","Update scope rules before continuing.","navigation","scope",False,False,"Scope must be valid before it can be confirmed.")
    if current=="scoped": return _action("begin_discovery","Begin Discovery","Record the start of the Discovery phase only. No reconnaissance tools run automatically.","transition",None,True,True)
    if current=="collecting":
        if not m["evidence_count"]: return _action("open_discovery","Open Discovery","Open the fixed enrichment workspace. Results are transient and are not saved automatically.","navigation","enrichment") if enrichment_enabled else _action("discovery_setup","Set Up Discovery","Discovery tools are disabled for this server session. Restart Outrider with: outrider --enable-mcp-enrichment. Advanced users may collect externally and register existing artifacts through Advanced Workspace.","instruction",None,False)
        if not m["verified_evidence_count"]: return _action("verify_evidence","Verify Evidence","Verify registered evidence byte integrity before analysis.","navigation","evidence")
        return _action("begin_analysis","Continue to Analysis","Move to Analysis after verified evidence review. No skills execute in the browser.","transition",None,True,True)
    if current=="analyzing":
        if not m["request_count"]: return _action("prepare_analysis","Prepare Analysis","Create or review analysis request contracts. The browser does not execute skills.","navigation","contracts")
        if not m["result_count"]: return _action("review_analysis_requests","Review Analysis Request","Review request contracts. Skill execution remains external.","navigation","contracts")
        if m["invalid_result_count"]: return _action("review_result_issues","Review Result Issue","Review malformed or invalid result contracts.","navigation","contracts")
        if m["unpromoted_candidate_count"]: return _action("review_finding_candidates","Review Finding Candidates","Review candidate findings before moving to Findings.","navigation","findings")
        return _action("begin_findings","Continue to Findings","Move to Findings. No findings are created automatically.","transition",None,True,True)
    if current=="reporting":
        if m["unpromoted_candidate_count"]: return _action("review_finding_candidates","Review Finding Candidates","Review candidate findings before completion.","navigation","findings")
        if m["unverified_finding_count"]: return _action("verify_findings","Verify Findings","Verify promoted finding provenance before completion.","navigation","findings")
        return _action("complete_engagement","Complete Engagement","Mark the engagement complete. This does not publish, export, notify, or submit a report.","transition",None,True,True)
    if current=="completed": return _action("completed","Engagement Completed","This engagement is complete.","none",None,False)
    if current=="cancelled": return _action("cancelled","Engagement Cancelled","This engagement was stopped before completion.","none",None,False)
    if current=="archived": return _action("archived","Engagement Archived","This engagement is archived.","none",None,False)
    return _action("review_integrity","Review Engagement Issue","Current state is not recognized.","navigation","integrity",False)

def build_workflow_guide(run_dir: str | Path, *, enrichment_enabled: bool) -> dict[str, Any]:
    run=Path(run_dir)
    manifest, manifest_errors = _safe(lambda: load_manifest(run), None)
    summary, state_errors = _safe(lambda: load_state(run), None)
    current = getattr(summary, "current_state", "initialized")
    m = _milestones(run)
    integrity_error = bool(manifest_errors or state_errors or not m["scope_valid"] and current!="initialized" or m["errors"] and (manifest_errors or state_errors))
    phase_id, phase_label = PHASE_LABELS.get(current, (current, current))
    next_action = _next(current, m, enrichment_enabled, bool(manifest_errors or state_errors or (current!="initialized" and not m["scope_valid"])))
    rev_inputs={
        "current_state": current, "state_revision": _safe(lambda: state_revision(run), "error")[0],
        "scope_revision": _safe(lambda: scope_revision(run), "error")[0],
        "evidence_revision": _safe(lambda: evidence_revision(run), "error")[0],
        "contract_revision": _safe(lambda: contract_revision(run), "error")[0],
        "finding_revision": _safe(lambda: finding_revision(run), "error")[0],
        "enrichment_enabled": bool(enrichment_enabled), "milestones": {k:v for k,v in m.items() if k!="errors"},
    }
    guide_revision=hashlib.sha256(json.dumps(rev_inputs, sort_keys=True, separators=(",",":")).encode()).hexdigest()
    return {"current_state":current,"phase":{"id":phase_id,"label":phase_label},"progress":_progress(current,m,bool(manifest_errors or state_errors)),"next_action":next_action,"secondary_actions":[],"milestones":{k:v for k,v in m.items() if k!="errors"},"guide_revision":guide_revision,"notice":NOTICE,"target":getattr(manifest,"target",None),"actor":getattr(manifest,"created_by",None),"engagement_platform":_metadata(run)["engagement_platform"],"traffic_header_configured":_metadata(run)["traffic_header_configured"],"health":{"status":"error" if (manifest_errors or state_errors or (current!="initialized" and not m["scope_valid"])) else "healthy","summary":"; ".join((manifest_errors+state_errors+m["errors"])[:2]) or "healthy"}}
