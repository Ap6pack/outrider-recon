from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
from uuid import UUID, uuid4

from outrider.evidence import EvidenceValidationError, load_evidence_registry, verify_all_evidence
from outrider.scope import evaluate_scope_path
from outrider.skill_contract import SkillContractValidationError, find_skill_request_by_id, find_skill_result_by_id, load_skill_request, load_skill_result, validate_skill_result, list_contract_inventory
from outrider.state import StateValidationError, load_manifest, load_state

SCHEMA_VERSION = 1
REGISTRY = "findings.jsonl"
EVENT_TYPE = "finding_promoted"
CLASSIFICATION = "validated_finding"
SOURCE_CLASSIFICATION = "finding_candidate"
SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
PROMOTED_CONFIDENCES = frozenset({"medium", "high"})
VALIDATION_BASES = frozenset({"evidence_review", "response_evidence", "configuration_evidence", "owner_confirmation"})
PROMOTION_STATES = frozenset({"analyzing", "reporting"})
VERIFICATION_STATUSES = frozenset({"verified", "source_missing", "source_changed", "evidence_missing", "evidence_mismatch", "evidence_unsafe", "invalid"})
SCOPE_STATUSES = frozenset({"currently_in_scope", "currently_out_of_scope", "scope_error"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CHUNK = 1024 * 1024

class FindingValidationError(ValueError): pass
class FindingPromotionRefusal(ValueError): pass

@dataclass(frozen=True)
class FindingClaimSnapshot:
    classification: str; subject: str; statement: str; confidence: str; suggested_severity: str | None; evidence_ids: list[str]
    def to_dict(self) -> dict[str, Any]: return asdict(self)

@dataclass(frozen=True)
class FindingSource:
    result_id: str; request_id: str; skill: str; result_path: str; result_sha256: str; claim_id: str; claim: FindingClaimSnapshot
    def to_dict(self) -> dict[str, Any]:
        d=asdict(self); d["claim"]=self.claim.to_dict(); return d

@dataclass(frozen=True)
class FindingRecord:
    schema_version: int; sequence: int; event_type: str; event_id: str; finding_id: str; run_id: str; promoted_at: str; promoted_by: str; classification: str; title: str; affected_candidate: str; candidate_type: str; location: str | None; severity: str; confidence: str; validation_basis: str; validation_reason: str; impact: str; remediation: str; source: FindingSource; evidence_ids: list[str]; notes: str | None
    def to_dict(self) -> dict[str, Any]:
        d=asdict(self); d["source"]=self.source.to_dict(); return d

@dataclass(frozen=True)
class FindingRegistrySummary:
    run_id: str; finding_count: int; records: tuple[FindingRecord, ...]
    def to_dict(self) -> dict[str, Any]: return {"run_id": self.run_id, "finding_count": self.finding_count, "records": [r.to_dict() for r in self.records]}

@dataclass(frozen=True)
class FindingVerification:
    finding_id: str; title: str; source_status: str; expected_source_sha256: str; actual_source_sha256: str | None; evidence_status: str; current_scope_status: str; overall_status: str; reason: str
    def to_dict(self) -> dict[str, Any]: return asdict(self)

def utc_now() -> str: return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def _nonempty(v: Any, field: str) -> str:
    if not isinstance(v, str) or not v.strip(): raise FindingValidationError(f"{field} must be a non-empty string")
    return v

def _optional(v: Any, field: str) -> str | None:
    if v is None: return None
    return _nonempty(v, field)

def _uuid4(v: Any, field: str) -> str:
    if not isinstance(v, str): raise FindingValidationError(f"{field} must be a UUID string")
    try: u=UUID(v)
    except ValueError as exc: raise FindingValidationError(f"{field} must be a valid UUID") from exc
    if u.version != 4: raise FindingValidationError(f"{field} must be a UUID version 4")
    return str(u)

def _timestamp(v: Any) -> str:
    if not isinstance(v, str): raise FindingValidationError("promoted_at must be a string timestamp")
    try: dt=datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as exc: raise FindingValidationError("promoted_at must be a valid ISO-8601 timestamp") from exc
    if dt.tzinfo is None or dt.utcoffset() is None: raise FindingValidationError("promoted_at must be timezone-aware")
    return v

def _unique_uuid_list(v: Any, field: str) -> list[str]:
    if not isinstance(v, list) or not v: raise FindingValidationError(f"{field} must be a non-empty array")
    ids=[_uuid4(x, field) for x in v]
    if len(set(ids)) != len(ids): raise FindingValidationError(f"duplicate {field}")
    return ids

def _parse_claim(data: Any) -> FindingClaimSnapshot:
    if not isinstance(data, dict): raise FindingValidationError("source claim must be an object")
    if set(data) != {"classification","subject","statement","confidence","suggested_severity","evidence_ids"}: raise FindingValidationError("source claim fields are invalid")
    if data["classification"] != SOURCE_CLASSIFICATION: raise FindingValidationError("source claim classification must be finding_candidate")
    conf=_nonempty(data["confidence"], "source claim confidence")
    sev=data["suggested_severity"]
    if sev is not None and sev not in SEVERITIES: raise FindingValidationError("unsupported source suggested_severity")
    return FindingClaimSnapshot(SOURCE_CLASSIFICATION, _nonempty(data["subject"], "subject"), _nonempty(data["statement"], "statement"), conf, sev, _unique_uuid_list(data["evidence_ids"], "evidence_ids"))

def _parse_source(data: Any) -> FindingSource:
    if not isinstance(data, dict): raise FindingValidationError("source must be an object")
    if set(data) != {"result_id","request_id","skill","result_path","result_sha256","claim_id","claim"}: raise FindingValidationError("source fields are invalid")
    path=normalize_result_path(data["result_path"])
    sha=data["result_sha256"]
    if not isinstance(sha, str) or not _SHA256.fullmatch(sha): raise FindingValidationError("result_sha256 must contain 64 lowercase hexadecimal characters")
    return FindingSource(_uuid4(data["result_id"], "result_id"), _uuid4(data["request_id"], "request_id"), _nonempty(data["skill"], "skill"), path, sha, _uuid4(data["claim_id"], "claim_id"), _parse_claim(data["claim"]))

def _parse_record(data: Any, run_id: str, expected_sequence: int, event_ids: set[str], finding_ids: set[str], pairs: set[tuple[str,str]]) -> FindingRecord:
    required={"schema_version","sequence","event_type","event_id","finding_id","run_id","promoted_at","promoted_by","classification","title","affected_candidate","candidate_type","location","severity","confidence","validation_basis","validation_reason","impact","remediation","source","evidence_ids","notes"}
    if not isinstance(data, dict): raise FindingValidationError("finding record must be a JSON object")
    if set(data) != required: raise FindingValidationError("finding record fields must exactly match required fields")
    if data["schema_version"] != SCHEMA_VERSION: raise FindingValidationError("unsupported finding schema_version")
    if data["sequence"] != expected_sequence: raise FindingValidationError("finding sequence must increment by exactly one")
    if data["event_type"] != EVENT_TYPE: raise FindingValidationError("unknown finding event_type")
    event_id=_uuid4(data["event_id"], "event_id"); finding_id=_uuid4(data["finding_id"], "finding_id")
    if event_id in event_ids: raise FindingValidationError("duplicate finding event_id")
    if finding_id in finding_ids: raise FindingValidationError("duplicate finding_id")
    event_ids.add(event_id); finding_ids.add(finding_id)
    if data["run_id"] != run_id: raise FindingValidationError("finding run_id does not match manifest")
    if data["classification"] != CLASSIFICATION: raise FindingValidationError("classification must be validated_finding")
    sev=data["severity"]; conf=data["confidence"]; basis=data["validation_basis"]
    if sev not in SEVERITIES: raise FindingValidationError("unsupported severity")
    if conf not in PROMOTED_CONFIDENCES: raise FindingValidationError("unsupported promoted finding confidence")
    if basis not in VALIDATION_BASES: raise FindingValidationError("unsupported validation_basis")
    source=_parse_source(data["source"]); pair=(source.result_id, source.claim_id)
    if pair in pairs: raise FindingValidationError("duplicate source result_id and claim_id")
    pairs.add(pair)
    evidence_ids=_unique_uuid_list(data["evidence_ids"], "evidence_ids")
    if not set(source.claim.evidence_ids).issubset(set(evidence_ids)): raise FindingValidationError("finding evidence_ids must include all source claim evidence IDs")
    return FindingRecord(SCHEMA_VERSION, data["sequence"], EVENT_TYPE, event_id, finding_id, run_id, _timestamp(data["promoted_at"]), _nonempty(data["promoted_by"], "promoted_by"), CLASSIFICATION, _nonempty(data["title"], "title"), _nonempty(data["affected_candidate"], "affected_candidate"), _nonempty(data["candidate_type"], "candidate_type"), _optional(data["location"], "location"), sev, conf, basis, _nonempty(data["validation_reason"], "validation_reason"), _nonempty(data["impact"], "impact"), _nonempty(data["remediation"], "remediation"), source, evidence_ids, _optional(data["notes"], "notes"))

def load_finding_registry(run_dir: str | Path) -> FindingRegistrySummary:
    manifest=load_manifest(run_dir); path=Path(run_dir)/REGISTRY
    if not path.exists(): return FindingRegistrySummary(manifest.run_id, 0, ())
    records=[]; event_ids=set(); finding_ids=set(); pairs=set(); seen=False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if raw == "":
            if seen: raise FindingValidationError(f"blank line in finding registry at line {lineno}")
            continue
        seen=True
        try: data=json.loads(raw)
        except json.JSONDecodeError as exc: raise FindingValidationError(f"malformed JSON in finding registry at line {lineno}: {exc}") from exc
        records.append(_parse_record(data, manifest.run_id, len(records)+1, event_ids, finding_ids, pairs))
    return FindingRegistrySummary(manifest.run_id, len(records), tuple(records))

def ensure_finding_registry(run_dir: str | Path) -> None:
    load_manifest(run_dir); load_state(run_dir)
    (Path(run_dir)/REGISTRY).touch(exist_ok=True)

def normalize_result_path(path_value: Any) -> str:
    text=_nonempty(path_value, "result_path").replace("\\", "/")
    p=PurePosixPath(text)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts): raise FindingValidationError("result_path must be a canonical relative POSIX path")
    if len(p.parts) != 3 or p.parts[0] != "contracts" or p.parts[1] != "results": raise FindingValidationError("result_path must be beneath contracts/results/")
    return p.as_posix()

def validate_source_result_path(run_dir: str | Path, result_file: str | Path) -> tuple[str, Path]:
    run=Path(run_dir).resolve(); base=run/"contracts"/"results"; raw=Path(result_file)
    if raw.is_absolute():
        p=raw
    else:
        s=raw.as_posix()
        p=(Path.cwd()/raw) if s.startswith(str(Path(run_dir).as_posix())) or s.startswith("/") else (run/raw)
    try: resolved=p.resolve(strict=False); rel=resolved.relative_to(base.resolve(strict=False))
    except ValueError as exc: raise FindingValidationError("source result must be beneath contracts/results/") from exc
    if any(part in {"", ".", ".."} for part in rel.parts): raise FindingValidationError("unsafe result path")
    full=base.joinpath(*rel.parts)
    current=run
    for part in (Path("contracts")/"results"/rel).parts:
        current=current/part
        try: st=os.lstat(current)
        except FileNotFoundError as exc: raise FindingValidationError("source result is missing") from exc
        if stat.S_ISLNK(st.st_mode): raise FindingValidationError("source result path contains a symbolic link")
    if full.is_dir(): raise FindingValidationError("source result must be a file")
    if not full.is_file(): raise FindingValidationError("source result must be a regular file")
    return (PurePosixPath("contracts/results")/PurePosixPath(*rel.parts)).as_posix(), full

def stable_sha256_file(path: Path) -> str:
    try:
        before=os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise FindingValidationError("source result is missing") from exc
    if stat.S_ISLNK(before.st_mode): raise FindingValidationError("source result path contains a symbolic link")
    if not stat.S_ISREG(before.st_mode): raise FindingValidationError("source result must be a regular file")
    h=hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            h.update(chunk)
    after=os.stat(path, follow_symlinks=False)
    attrs=("st_dev","st_ino","st_mode","st_size","st_mtime_ns")
    if tuple(getattr(before,a) for a in attrs) != tuple(getattr(after,a) for a in attrs):
        raise FindingPromotionRefusal("source result changed while hashing")
    return h.hexdigest()

def _hash_file(path: Path) -> str:
    return stable_sha256_file(path)

def finding_revision(run_dir: str | Path) -> str:
    """Return SHA-256 of current findings.jsonl bytes as an optimistic stale-write token, not a signature."""
    path=Path(run_dir)/REGISTRY
    if not path.exists(): return hashlib.sha256(b"").hexdigest()
    rel, full = validate_source_result_path(Path(run_dir), path) if False else (None, path)
    return stable_sha256_file(full)

def _verify_ids(run_dir: Path, ids: list[str]) -> None:
    registry=load_evidence_registry(run_dir); known={r.evidence_id for r in registry.records}
    for eid in ids:
        if eid not in known: raise FindingPromotionRefusal(f"unknown evidence_id: {eid}")
    checks={v.evidence_id: v for v in verify_all_evidence(run_dir)}
    for eid in ids:
        status=checks[eid].status if eid in checks else "missing"
        if status != "verified": raise FindingPromotionRefusal(f"evidence {eid} verification {status}")

def _claim_snapshot(claim: dict[str, Any]) -> FindingClaimSnapshot:
    return FindingClaimSnapshot(claim["classification"], claim["subject"], claim["statement"], claim["confidence"], claim.get("suggested_severity"), list(claim["evidence_ids"]))

def promote_finding(run_dir: str | Path, result_file: str | Path, claim_id: str, *, actor: str, title: str, candidate: str, severity: str, confidence: str, validation_basis: str, validation_reason: str, impact: str, remediation: str, location: str | None=None, notes: str | None=None, supplementary_evidence_ids: list[str] | None=None) -> FindingRecord:
    run=Path(run_dir); manifest=load_manifest(run); state=load_state(run)
    if state.current_state not in PROMOTION_STATES: raise FindingPromotionRefusal(f"finding promotion is not permitted while run is {state.current_state}")
    registry=load_finding_registry(run)
    actor=_nonempty(actor,"actor"); title=_nonempty(title,"title"); validation_reason=_nonempty(validation_reason,"validation_reason"); impact=_nonempty(impact,"impact"); remediation=_nonempty(remediation,"remediation"); location=_optional(location,"location"); notes=_optional(notes,"notes")
    if severity not in SEVERITIES: raise FindingValidationError("unsupported severity")
    if confidence not in PROMOTED_CONFIDENCES: raise FindingPromotionRefusal("low confidence findings cannot be promoted")
    if validation_basis not in VALIDATION_BASES: raise FindingValidationError("unsupported validation_basis")
    cid=_uuid4(claim_id,"claim_id")
    rel, full=validate_source_result_path(run, result_file)
    report=validate_skill_result(run, full)
    if not report.structural_valid: raise FindingValidationError("source result contract is invalid: "+"; ".join(report.errors))
    if report.overall_status != "valid": raise FindingPromotionRefusal("source result evidence does not verify: "+"; ".join(report.errors))
    result=load_skill_result(run, full)
    if result.status not in {"completed", "partial"}: raise FindingPromotionRefusal("blocked or failed results cannot be promoted")
    lookup=find_skill_request_by_id(run,result.request_id)
    if lookup.status == "not_found": raise FindingValidationError("linked request not found")
    if lookup.status == "ambiguous": raise FindingPromotionRefusal("linked request ID is ambiguous")
    req=load_skill_request(run, lookup.relative_path)
    if req.request_id != result.request_id or req.run_id != result.run_id or req.skill != result.skill: raise FindingValidationError("result does not match linked request")
    claim=next((c for c in result.claims if c["claim_id"] == cid), None)
    if claim is None: raise FindingPromotionRefusal("selected claim_id was not found")
    if claim["classification"] != SOURCE_CLASSIFICATION: raise FindingPromotionRefusal("only finding_candidate claims can be promoted")
    if any(r.source.result_id == result.result_id and r.source.claim_id == cid for r in registry.records): raise FindingPromotionRefusal("source claim has already been promoted")
    evidence_ids=list(dict.fromkeys(list(claim["evidence_ids"]) + list(supplementary_evidence_ids or [])))
    evidence_ids=_unique_uuid_list(evidence_ids, "evidence_ids")
    _verify_ids(run, evidence_ids)
    decision=evaluate_scope_path(run, candidate)
    if decision.decision == "error": raise FindingValidationError(decision.reason)
    if decision.decision != "allow": raise FindingPromotionRefusal(decision.reason)
    sha=_hash_file(full)
    record=FindingRecord(SCHEMA_VERSION, registry.finding_count+1, EVENT_TYPE, str(uuid4()), str(uuid4()), manifest.run_id, utc_now(), actor, CLASSIFICATION, title, decision.normalized_candidate or candidate, decision.candidate_type or "domain", location, severity, confidence, validation_basis, validation_reason, impact, remediation, FindingSource(result.result_id, result.request_id, result.skill, rel, sha, cid, _claim_snapshot(claim)), evidence_ids, notes)
    ensure_finding_registry(run)
    with (run/REGISTRY).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.to_dict(), sort_keys=True)+"\n"); handle.flush(); os.fsync(handle.fileno())
    return record


def promote_finding_by_ids(run_dir: str | Path, result_id: str, claim_id: str, *, actor: str, title: str, candidate: str, severity: str, confidence: str, validation_basis: str, validation_reason: str, impact: str, remediation: str, location: str | None=None, notes: str | None=None, supplementary_evidence_ids: list[str] | None=None, expected_source_sha256: str | None=None) -> FindingRecord:
    rid=_uuid4(result_id,"result_id"); cid=_uuid4(claim_id,"claim_id")
    lookup=find_skill_result_by_id(run_dir,rid)
    if lookup.status == "not_found": raise FindingPromotionRefusal("unknown source result")
    if lookup.status == "ambiguous": raise FindingPromotionRefusal("source result ID is ambiguous")
    rel, full=validate_source_result_path(run_dir, lookup.relative_path)
    sha=stable_sha256_file(full)
    if expected_source_sha256 is not None:
        if not isinstance(expected_source_sha256,str) or not _SHA256.fullmatch(expected_source_sha256): raise FindingValidationError("expected_source_sha256 must contain 64 lowercase hexadecimal characters")
        if sha != expected_source_sha256: raise FindingPromotionRefusal("source result SHA-256 is stale")
    return promote_finding(run_dir, rel, cid, actor=actor, title=title, candidate=candidate, severity=severity, confidence=confidence, validation_basis=validation_basis, validation_reason=validation_reason, impact=impact, remediation=remediation, location=location, notes=notes, supplementary_evidence_ids=supplementary_evidence_ids)

def list_finding_candidates(run_dir: str | Path, *, max_results:int=1000, max_claims:int=5000) -> dict[str,Any]:
    run=Path(run_dir); candidates=[]; skipped=[]; truncated=False; claims_seen=0
    promoted={(r.source.result_id,r.source.claim_id):r.finding_id for r in load_finding_registry(run).records}
    inv=list_contract_inventory(run, max_files=max_results)
    for item in inv.get("skipped",[]): skipped.append(item)
    for item in inv.get("results",[])[:max_results]:
        if claims_seen >= max_claims: truncated=True; break
        rel=item.get("relative_path")
        try:
            result=load_skill_result(run, rel); report=validate_skill_result(run, rel); _,full=validate_source_result_path(run, rel); sha=stable_sha256_file(full)
        except Exception as exc:
            skipped.append({"section":"results","message":str(exc)}); continue
        ev_checks={v.evidence_id:v for v in verify_all_evidence(run)}
        for claim in result.claims:
            if claim.get("classification") != SOURCE_CLASSIFICATION: continue
            claims_seen += 1
            if claims_seen > max_claims: truncated=True; break
            eids=list(claim.get("evidence_ids",[])); reasons=[]
            if result.status in {"blocked","failed"}: reasons.append(f"result status is {result.status}")
            if report.overall_status != "valid": reasons.append("source result validation is not valid")
            dec=evaluate_scope_path(run, claim.get("subject",""));
            if dec.decision != "allow": reasons.append("candidate is currently outside scope")
            assessments=[]
            for eid in eids:
                v=ev_checks.get(eid); status=getattr(v,"status","missing")
                assessments.append({"evidence_id":eid,"verification_status":status})
                if status != "verified": reasons.append(f"evidence {eid} verification {status}")
            existing=promoted.get((result.result_id, claim["claim_id"]))
            if existing: reasons.append("already promoted")
            candidates.append({"result_id":result.result_id,"request_id":result.request_id,"skill":result.skill,"result_status":result.status,"completed_at":result.completed_at,"result_summary":result.summary,"source_result_sha256":sha,"source_result_validation":{"overall_status":report.overall_status,"structural_valid":report.structural_valid,"evidence_verified":report.evidence_verified},"claim_id":claim["claim_id"],"classification":claim["classification"],"subject":claim["subject"],"statement":claim["statement"],"source_confidence":claim["confidence"],"suggested_severity":claim.get("suggested_severity"),"evidence_ids":eids,"evidence_assessments":assessments,"subject_scope_decision":{"decision":dec.decision},"already_promoted":existing is not None,"existing_finding_id":existing,"promotion_eligible":not reasons,"promotion_disabled_reasons":sorted(set(reasons))})
    candidates.sort(key=lambda c:(c["result_id"],c["claim_id"]))
    return {"candidates":candidates,"candidate_count":len(candidates),"truncated":truncated or len(inv.get("results",[]))>max_results,"max_results":max_results,"max_claims":max_claims,"skipped":skipped}

def list_findings(run_dir: str | Path) -> FindingRegistrySummary: load_state(run_dir); return load_finding_registry(run_dir)

def get_finding(run_dir: str | Path, finding_id: str) -> FindingRecord | None:
    fid=_uuid4(finding_id,"finding_id")
    for r in list_findings(run_dir).records:
        if r.finding_id == fid: return r
    return None

def _verify_evidence_for_record(run_dir: Path, ids: list[str]) -> tuple[str, str]:
    try:
        reg=load_evidence_registry(run_dir); known={r.evidence_id for r in reg.records}; checks={v.evidence_id: v for v in verify_all_evidence(run_dir)}
        for eid in ids:
            if eid not in known: return "evidence_missing", f"evidence {eid} is not registered"
            status=checks[eid].status
            if status == "missing": return "evidence_missing", f"evidence {eid} is missing"
            if status == "mismatch": return "evidence_mismatch", f"evidence {eid} does not match registry"
            if status != "verified": return "evidence_unsafe", f"evidence {eid} is unsafe: {checks[eid].reason}"
        return "verified", "evidence artifacts verify"
    except (EvidenceValidationError, StateValidationError) as exc:
        return "invalid", str(exc)

def verify_finding(run_dir: str | Path, finding: FindingRecord) -> FindingVerification:
    run=Path(run_dir); actual=None; source_status="verified"; reason=[]
    try:
        rel, full=validate_source_result_path(run, run/finding.source.result_path)
        actual=_hash_file(full)
        if actual != finding.source.result_sha256:
            source_status="source_changed"; reason.append("source result SHA-256 changed")
        else:
            res=load_skill_result(run, full)
            if res.result_id != finding.source.result_id: source_status="source_changed"; reason.append("source result_id changed")
            claim=next((c for c in res.claims if c["claim_id"] == finding.source.claim_id), None)
            if claim is None or _claim_snapshot(claim).to_dict() != finding.source.claim.to_dict(): source_status="source_changed"; reason.append("source claim snapshot changed")
    except FindingValidationError as exc:
        source_status="source_missing" if "missing" in str(exc) else "invalid"; reason.append(str(exc))
    except SkillContractValidationError as exc:
        source_status="source_changed"; reason.append(str(exc))
    evidence_status, ev_reason=_verify_evidence_for_record(run, finding.evidence_ids)
    if evidence_status != "verified": reason.append(ev_reason)
    dec=evaluate_scope_path(run, finding.affected_candidate)
    scope_status="currently_in_scope" if dec.decision == "allow" else "currently_out_of_scope" if dec.decision == "deny" else "scope_error"
    if source_status == "verified" and evidence_status == "verified": overall="verified"
    elif source_status != "verified": overall=source_status
    else: overall=evidence_status
    return FindingVerification(finding.finding_id, finding.title, source_status, finding.source.result_sha256, actual, evidence_status, scope_status, overall, "; ".join(reason) if reason else "finding provenance and evidence verify")

def verify_all_findings(run_dir: str | Path, finding_id: str | None=None) -> list[FindingVerification]:
    summary=list_findings(run_dir)
    records=list(summary.records)
    if finding_id is not None:
        fid=_uuid4(finding_id,"finding_id"); records=[r for r in records if r.finding_id == fid]
        if not records: return [FindingVerification(fid, "", "invalid", "", None, "invalid", "scope_error", "invalid", "finding_id is not registered")]
    return [verify_finding(run_dir, r) for r in records]
