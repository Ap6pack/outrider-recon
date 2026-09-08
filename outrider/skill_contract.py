from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib, json, os, re, stat, tempfile
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from outrider.approval import ACTION_TYPES, ACTIVE, ALLOWED_STATES, INTRUSIVE, PROHIBITED, action_class, evaluate_action
from outrider.evidence import load_evidence_registry, verify_all_evidence
from outrider.scope import ScopeValidationError, _normalize_candidate, evaluate_scope_path
from outrider.state import load_manifest, load_state

SCHEMA_VERSION = 1
REQUEST_CONTRACT_TYPE = "skill_request"
RESULT_CONTRACT_TYPE = "skill_result"
REQUEST_ACTIONS = frozenset({"local_analysis","public_source_lookup","target_read_only_request","target_enumeration"})
RECOMMENDED_ACTIONS = frozenset((set(ACTION_TYPES) - set(PROHIBITED)))
RESULT_STATUSES = frozenset({"completed","partial","blocked","failed"})
CLAIM_CLASSIFICATIONS = frozenset({"observation","exposure","hypothesis","finding_candidate"})
CONFIDENCES = frozenset({"low","medium","high"})
SEVERITIES = frozenset({"informational","low","medium","high","critical"})
PRIORITIES = frozenset({"low","medium","high"})
REQUEST_REQUIRED = ["schema_version","contract_type","request_id","run_id","created_at","created_by","skill","objective","requested_action","input_evidence_ids","limits","notes"]
RESULT_REQUIRED = ["schema_version","contract_type","result_id","request_id","run_id","skill","completed_at","status","summary","claims","discovered_candidates","recommended_actions","errors"]
LOWER_TOKEN = re.compile(r"^[a-z][a-z0-9-]*$")

class SkillContractValidationError(ValueError): pass

@dataclass(frozen=True)
class SkillRequest:
    schema_version:int; contract_type:str; request_id:str; run_id:str; created_at:str; created_by:str; skill:str; objective:str; requested_action:dict[str,Any]; input_evidence_ids:list[str]; limits:dict[str,Any]; notes:str|None
    def to_dict(self): return asdict(self)

@dataclass(frozen=True)
class SkillClaim:
    claim_id:str; classification:str; subject:str; statement:str; confidence:str; suggested_severity:str|None; evidence_ids:list[str]
    def to_dict(self): return asdict(self)

@dataclass(frozen=True)
class DiscoveredCandidate:
    candidate:str; relationship:str; source_evidence_ids:list[str]
    def to_dict(self): return asdict(self)

@dataclass(frozen=True)
class RecommendedAction:
    action_type:str; candidate:str|None; priority:str; reason:str
    def to_dict(self): return asdict(self)

@dataclass(frozen=True)
class SkillResult:
    schema_version:int; contract_type:str; result_id:str; request_id:str; run_id:str; skill:str; completed_at:str; status:str; summary:str; claims:list[dict[str,Any]]; discovered_candidates:list[dict[str,Any]]; recommended_actions:list[dict[str,Any]]; errors:list[dict[str,Any]]
    def to_dict(self): return asdict(self)

@dataclass(frozen=True)
class ContractValidationReport:
    contract_type:str; structural_valid:bool; run_id:str|None; request_id:str|None; result_id:str|None; skill:str|None; current_request_policy_decision:dict[str,Any]|None; evidence_count:int; evidence_verified:bool; discovered_candidate_scope_assessments:list[dict[str,Any]]; recommended_action_policy_assessments:list[dict[str,Any]]; warnings:list[str]; errors:list[str]; overall_status:str
    def to_dict(self): return asdict(self)

def utc_now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def list_known_skills(repo_root: str|Path|None=None) -> tuple[str,...]:
    if repo_root is None:
        from outrider.package_resources import packaged_skill_catalog
        return packaged_skill_catalog()
    root = Path(repo_root)
    return tuple(sorted(p.parent.name for p in (root/"skills").glob("*/SKILL.md")))

def _uuid4(v:Any, field:str)->str:
    if not isinstance(v,str): raise SkillContractValidationError(f"{field} must be a UUID string")
    try: u=UUID(v)
    except ValueError as e: raise SkillContractValidationError(f"{field} must be a valid UUID") from e
    if u.version != 4: raise SkillContractValidationError(f"{field} must be a UUID version 4")
    return str(u)

def _ts(v:Any, field:str)->str:
    if not isinstance(v,str): raise SkillContractValidationError(f"{field} must be a string timestamp")
    try: dt=datetime.fromisoformat(v.replace("Z","+00:00"))
    except ValueError as e: raise SkillContractValidationError(f"{field} must be a valid ISO-8601 timestamp") from e
    if dt.tzinfo is None or dt.utcoffset() is None: raise SkillContractValidationError(f"{field} must be timezone-aware")
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()

def _nonempty(v:Any, field:str)->str:
    if not isinstance(v,str) or not v.strip(): raise SkillContractValidationError(f"{field} must be a non-empty string")
    return v

def _json_obj(path:Path)->dict[str,Any]:
    try: data=json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e: raise SkillContractValidationError(f"malformed JSON: {e}") from e
    if not isinstance(data,dict): raise SkillContractValidationError("contract JSON must be an object")
    return data

def _safe_existing_file(run_dir:Path, file_path:str|Path, subdir:str)->Path:
    run=run_dir.resolve(); base=run/"contracts"/subdir
    p=Path(file_path)
    if not p.is_absolute(): p=(run/p).resolve()
    else: p=p.resolve()
    try: rel=p.relative_to(base.resolve(strict=False))
    except ValueError as e: raise SkillContractValidationError(f"contract file must be under contracts/{subdir}/") from e
    if any(part in {"..",""} for part in rel.parts): raise SkillContractValidationError("unsafe contract path")
    if not p.exists(): raise SkillContractValidationError("contract file is missing")
    if p.is_dir(): raise SkillContractValidationError("contract path must be a file")
    cur=run
    for part in (Path("contracts")/subdir/rel).parts:
        cur=cur/part
        st=os.lstat(cur)
        if stat.S_ISLNK(st.st_mode): raise SkillContractValidationError("contract path contains a symbolic link")
    return p


@dataclass(frozen=True)
class ContractLookup:
    contract_id: str
    relative_path: str
    kind: str
    status: str = "found"
    error: str | None = None
    def to_dict(self): return asdict(self)

EMPTY_CONTRACT_REVISION = hashlib.sha256(b"outrider-contract-set-v1\n").hexdigest()

def _contract_dir(run_dir: Path, kind: str) -> Path:
    return run_dir / "contracts" / kind

def _safe_contract_files(run_dir: Path, kind: str) -> tuple[list[Path], list[str]]:
    base = _contract_dir(run_dir, kind); errors=[]
    if not base.exists(): return [], errors
    st=os.lstat(base)
    if stat.S_ISLNK(st.st_mode): return [], [f"contracts/{kind} is a symbolic link"]
    if not stat.S_ISDIR(st.st_mode): return [], [f"contracts/{kind} is not a directory"]
    files=[]
    for child in base.iterdir():
        try: cst=os.lstat(child)
        except OSError as e: errors.append(f"contracts/{kind}/{child.name}: {e}"); continue
        if stat.S_ISLNK(cst.st_mode): errors.append(f"contracts/{kind}/{child.name}: symbolic links are skipped"); continue
        if not stat.S_ISREG(cst.st_mode): continue
        if child.suffix != ".json": continue
        files.append(child)
    return sorted(files, key=lambda p: p.relative_to(run_dir).as_posix()), errors

def _read_stable_bytes(path: Path) -> bytes:
    before=os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode): raise SkillContractValidationError("contract path is not a regular file")
    data=path.read_bytes()
    after=os.stat(path, follow_symlinks=False)
    if (before.st_mtime_ns,before.st_size,before.st_ino)!=(after.st_mtime_ns,after.st_size,after.st_ino):
        raise SkillContractValidationError("contract file changed while reading")
    return data

def contract_revision(run_dir: str|Path) -> str:
    """Return an optimistic SHA-256 inventory token for safe request/result contracts; not a signature."""
    run=Path(run_dir); h=hashlib.sha256(); h.update(b"outrider-contract-set-v1\n")
    entries=[]; errors=[]
    for kind in ("requests","results"):
        fs, es=_safe_contract_files(run, kind); entries += fs; errors += es
    if errors: raise SkillContractValidationError("; ".join(errors))
    for path in sorted(entries, key=lambda p: p.relative_to(run).as_posix()):
        rel=path.relative_to(run).as_posix().encode(); data=_read_stable_bytes(path)
        h.update(len(rel).to_bytes(8,"big")); h.update(rel); h.update(len(data).to_bytes(8,"big")); h.update(data)
    return h.hexdigest()

def _top_uuid(path: Path, field: str) -> tuple[str|None,str|None]:
    try:
        data=json.loads(_read_stable_bytes(path).decode("utf-8"))
        if not isinstance(data,dict): return None,"contract JSON must be an object"
        v=data.get(field)
        if isinstance(v,str): return str(UUID(v)), None
        return None, f"missing {field}"
    except Exception as e:
        return None, str(e)

def list_contract_inventory(run_dir: str|Path, *, max_files:int=2000) -> dict[str,Any]:
    run=Path(run_dir); out={"requests":[],"results":[],"request_count":0,"result_count":0,"truncated":False,"max_files":max_files,"skipped":[],"duplicates":{"request_ids":[],"result_ids":[]}}
    seen={"requests":{},"results":{}}
    total=0
    for kind, field in (("requests","request_id"),("results","result_id")):
        files, errors=_safe_contract_files(run, kind); out["skipped"] += [{"section":kind,"message":e} for e in errors]
        for path in files:
            if total >= max_files: out["truncated"]=True; break
            total += 1; rel=path.relative_to(run).as_posix(); cid,err=_top_uuid(path, field)
            item={"kind":kind[:-1],"relative_path":rel,"contract_id":cid,"valid_json":err is None,"error":err}
            out[kind].append(item)
            if cid: seen[kind].setdefault(cid,[]).append(rel)
    for kind, key in (("requests","request_ids"),("results","result_ids")):
        out["duplicates"][key]=sorted([cid for cid,paths in seen[kind].items() if len(paths)>1])
    out["request_count"]=len(out["requests"]); out["result_count"]=len(out["results"])
    return out

def _find_by_id(run_dir: str|Path, kind: str, field: str, contract_id: str) -> ContractLookup:
    try: cid=str(UUID(contract_id))
    except Exception as e: raise SkillContractValidationError(f"{field} must be a UUID") from e
    run=Path(run_dir); matches=[]
    files,_=_safe_contract_files(run, kind)
    for path in files:
        found,err=_top_uuid(path, field)
        if found == cid: matches.append(path.relative_to(run).as_posix())
    if not matches: return ContractLookup(cid,"",kind[:-1],"not_found")
    if len(matches)>1: return ContractLookup(cid,"",kind[:-1],"ambiguous","duplicate matching contract IDs")
    return ContractLookup(cid,matches[0],kind[:-1])

def find_skill_request_by_id(run_dir: str|Path, request_id: str) -> ContractLookup:
    return _find_by_id(run_dir,"requests","request_id",request_id)

def find_skill_result_by_id(run_dir: str|Path, result_id: str) -> ContractLookup:
    return _find_by_id(run_dir,"results","result_id",result_id)

def request_action_catalog() -> list[dict[str,Any]]:
    rows=[]
    for at in sorted(REQUEST_ACTIONS):
        rows.append({"action_type":at,"action_class":action_class(at),"candidate_mode":"optional" if at=="local_analysis" else "required","candidate_required":at!="local_analysis","approval_required":at in ACTIVE,"allowed_states":sorted(ALLOWED_STATES.get(at,()))})
    return rows

def ensure_contract_dirs(run_dir: str|Path)->None:
    run=Path(run_dir); load_manifest(run); load_state(run)
    for rel in ["contracts","contracts/requests","contracts/results"]:
        p=run/rel
        if p.exists() and os.path.islink(p): raise SkillContractValidationError("contract directories must not be symbolic links")
        p.mkdir(exist_ok=True)

def _normalize(candidate: str|None)->tuple[str|None,str|None]:
    if candidate is None: return None,None
    try: c = _normalize_candidate(candidate); return c.normalized, c.kind
    except ScopeValidationError as e: raise SkillContractValidationError(str(e)) from e

def _verify_evidence_ids(run_dir:Path, ids:list[str])->tuple[bool,list[str]]:
    registry=load_evidence_registry(run_dir); known={r.evidence_id for r in registry.records}; errors=[]
    for eid in ids:
        _uuid4(eid,"evidence_id")
        if eid not in known: errors.append(f"unknown evidence_id: {eid}")
    ver=verify_all_evidence(run_dir)
    by={v.evidence_id:v for v in ver}
    for eid in ids:
        if eid in by and by[eid].status != "verified": errors.append(f"evidence {eid} verification {by[eid].status}: {by[eid].reason}")
    return not errors, errors

def _parse_request(run_dir:Path, data:dict[str,Any])->SkillRequest:
    if set(data)!=set(REQUEST_REQUIRED): raise SkillContractValidationError("request fields must exactly match required fields")
    if data["schema_version"]!=1: raise SkillContractValidationError("schema_version must be integer 1")
    if data["contract_type"]!=REQUEST_CONTRACT_TYPE: raise SkillContractValidationError("contract_type must be skill_request")
    manifest=load_manifest(run_dir); rid=_uuid4(data["request_id"],"request_id")
    if data["run_id"]!=manifest.run_id: raise SkillContractValidationError("run_id does not match manifest")
    created_at=_ts(data["created_at"],"created_at"); actor=_nonempty(data["created_by"],"created_by")
    skill=_nonempty(data["skill"],"skill")
    if skill not in list_known_skills(): raise SkillContractValidationError("unknown skill")
    objective=_nonempty(data["objective"],"objective")
    ra=data["requested_action"]
    if not isinstance(ra,dict) or set(ra)!={"action_type","candidate"}: raise SkillContractValidationError("requested_action must contain only action_type and candidate")
    at=_nonempty(ra["action_type"],"action_type")
    if at not in REQUEST_ACTIONS: raise SkillContractValidationError("action_type is not permitted for skill requests")
    cand=ra["candidate"]
    if at=="local_analysis":
        if cand is not None: cand=_normalize(cand)[0]
    else:
        if cand is None: raise SkillContractValidationError("candidate is required")
        cand=_normalize(cand)[0]
    ids=data["input_evidence_ids"]
    if not isinstance(ids,list): raise SkillContractValidationError("input_evidence_ids must be an array")
    ids=[_uuid4(x,"input_evidence_ids") for x in ids]
    if len(set(ids))!=len(ids): raise SkillContractValidationError("duplicate input evidence IDs")
    limits=data["limits"]
    if not isinstance(limits,dict) or set(limits)!={"max_items"}: raise SkillContractValidationError("limits must contain only max_items")
    mi=limits["max_items"]
    if isinstance(mi,bool) or not isinstance(mi,int) or mi<1 or mi>1000: raise SkillContractValidationError("max_items must be between 1 and 1000")
    notes=data["notes"]
    if notes is not None: notes=_nonempty(notes,"notes")
    return SkillRequest(1,REQUEST_CONTRACT_TYPE,rid,manifest.run_id,created_at,actor,skill,objective,{"action_type":at,"candidate":cand},ids,{"max_items":mi},notes)

def _report_request(run_dir:Path, req:SkillRequest, structural=True, errors=None)->ContractValidationReport:
    errors=errors or []
    decision=evaluate_action(run_dir, req.requested_action["action_type"], req.requested_action.get("candidate")).to_dict() if structural else None
    ok, ev_errors=_verify_evidence_ids(run_dir, req.input_evidence_ids) if structural else (False,[])
    all_errors=errors+ev_errors
    status="valid" if structural and ok and decision and decision["decision"]=="allow" and not all_errors else ("deny" if structural and decision and decision["decision"]=="deny" and ok and not ev_errors else "error")
    return ContractValidationReport(REQUEST_CONTRACT_TYPE,structural,req.run_id,req.request_id,None,req.skill,decision,len(req.input_evidence_ids),ok,[],[],[],all_errors,status)

def load_skill_request(run_dir: str|Path, request_file: str|Path)->SkillRequest:
    run=Path(run_dir); p=_safe_existing_file(run,request_file,"requests"); return _parse_request(run,_json_obj(p))

def validate_skill_request(run_dir: str|Path, request_file: str|Path)->ContractValidationReport:
    run=Path(run_dir)
    try: req=load_skill_request(run,request_file); return _report_request(run,req)
    except SkillContractValidationError as e: return ContractValidationReport(REQUEST_CONTRACT_TYPE,False,None,None,None,None,None,0,False,[],[],[],[str(e)],"error")

def create_skill_request(run_dir: str|Path, skill:str, actor:str, objective:str, action_type:str, candidate:str|None=None, evidence_ids:list[str]|None=None, max_items:int=100, notes:str|None=None)->tuple[SkillRequest,Path,ContractValidationReport]:
    run=Path(run_dir); ensure_contract_dirs(run)
    if action_type not in REQUEST_ACTIONS: raise SkillContractValidationError("action_type is not permitted for skill requests")
    n,_=_normalize(candidate) if candidate is not None else (None,None)
    data={"schema_version":1,"contract_type":REQUEST_CONTRACT_TYPE,"request_id":str(uuid4()),"run_id":load_manifest(run).run_id,"created_at":utc_now(),"created_by":actor,"skill":skill,"objective":objective,"requested_action":{"action_type":action_type,"candidate":n},"input_evidence_ids":evidence_ids or [],"limits":{"max_items":max_items},"notes":notes}
    req=_parse_request(run,data); rep=_report_request(run,req)
    if rep.overall_status != "valid": raise SkillContractValidationError("current policy or evidence does not allow request: "+(rep.current_request_policy_decision or {}).get("reason","invalid evidence"))
    out=run/"contracts"/"requests"/f"{req.request_id}.json"
    if out.exists(): raise SkillContractValidationError("request file already exists")
    fd,tmp=tempfile.mkstemp(prefix=f".{req.request_id}.", suffix=".tmp", dir=out.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as h:
            json.dump(req.to_dict(),h,indent=2,sort_keys=True); h.write("\n"); h.flush(); os.fsync(h.fileno())
        os.replace(tmp,out)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return req,out,rep

def _parse_result(run_dir:Path, data:dict[str,Any])->SkillResult:
    if set(data)!=set(RESULT_REQUIRED): raise SkillContractValidationError("result fields must exactly match required fields")
    if data["schema_version"]!=1: raise SkillContractValidationError("schema_version must be integer 1")
    if data["contract_type"]!=RESULT_CONTRACT_TYPE: raise SkillContractValidationError("contract_type must be skill_result")
    manifest=load_manifest(run_dir); result_id=_uuid4(data["result_id"],"result_id"); request_id=_uuid4(data["request_id"],"request_id")
    if data["run_id"]!=manifest.run_id: raise SkillContractValidationError("run_id does not match manifest")
    skill=_nonempty(data["skill"],"skill")
    if skill not in list_known_skills(): raise SkillContractValidationError("unknown skill")
    completed_at=_ts(data["completed_at"],"completed_at"); status=_nonempty(data["status"],"status")
    if status not in RESULT_STATUSES: raise SkillContractValidationError("unsupported result status")
    summary=_nonempty(data["summary"],"summary")
    claims=data["claims"]; disc=data["discovered_candidates"]; recs=data["recommended_actions"]; errs=data["errors"]
    if not all(isinstance(x,list) for x in [claims,disc,recs,errs]): raise SkillContractValidationError("claims, discovered_candidates, recommended_actions, and errors must be arrays")
    if status in {"completed","partial"} and not (claims or disc or recs): raise SkillContractValidationError("completed and partial results require structured content")
    if status in {"blocked","failed"} and not errs: raise SkillContractValidationError("blocked and failed results require errors")
    cids=set(); all_eids=[]
    for c in claims:
        if not isinstance(c,dict) or set(c)!={"claim_id","classification","subject","statement","confidence","suggested_severity","evidence_ids"}: raise SkillContractValidationError("claim fields are invalid")
        cid=_uuid4(c["claim_id"],"claim_id")
        if cid in cids: raise SkillContractValidationError("duplicate claim_id")
        cids.add(cid)
        if c["classification"] not in CLAIM_CLASSIFICATIONS: raise SkillContractValidationError("unsupported claim classification; finding_candidate is not a validated finding")
        _nonempty(c["subject"],"subject"); _nonempty(c["statement"],"statement")
        if c["confidence"] not in CONFIDENCES: raise SkillContractValidationError("unsupported confidence")
        if c["suggested_severity"] is not None and c["suggested_severity"] not in SEVERITIES: raise SkillContractValidationError("unsupported severity")
        eids=c["evidence_ids"]
        if not isinstance(eids,list) or not eids: raise SkillContractValidationError("each claim requires evidence IDs")
        if len(set(eids))!=len(eids): raise SkillContractValidationError("duplicate evidence IDs in claim")
        all_eids += [_uuid4(e,"evidence_ids") for e in eids]
    dcands=set()
    for d in disc:
        if not isinstance(d,dict) or set(d)!={"candidate","relationship","source_evidence_ids"}: raise SkillContractValidationError("discovered candidate fields are invalid")
        n,_=_normalize(_nonempty(d["candidate"],"candidate"));
        if n in dcands: raise SkillContractValidationError("duplicate discovered candidate")
        dcands.add(n)
        if not isinstance(d["relationship"],str) or not re.fullmatch(r"[a-z][a-z0-9_-]*", d["relationship"]): raise SkillContractValidationError("relationship must be a lowercase token")
        eids=d["source_evidence_ids"]
        if not isinstance(eids,list) or not eids: raise SkillContractValidationError("discovered candidates require source evidence IDs")
        if len(set(eids))!=len(eids): raise SkillContractValidationError("duplicate evidence IDs in discovered candidate")
        all_eids += [_uuid4(e,"source_evidence_ids") for e in eids]
    for r in recs:
        if not isinstance(r,dict) or set(r)!={"action_type","candidate","priority","reason"}: raise SkillContractValidationError("recommended action fields are invalid")
        at=_nonempty(r["action_type"],"action_type")
        if at in PROHIBITED: raise SkillContractValidationError("prohibited recommendation")
        if at not in RECOMMENDED_ACTIONS: raise SkillContractValidationError("unknown recommendation action")
        if r["priority"] not in PRIORITIES: raise SkillContractValidationError("unsupported priority")
        _nonempty(r["reason"],"reason")
        if at != "local_analysis" and r["candidate"] is None: raise SkillContractValidationError("candidate is required")
        if r["candidate"] is not None: _normalize(r["candidate"])
    return SkillResult(1,RESULT_CONTRACT_TYPE,result_id,request_id,manifest.run_id,skill,completed_at,status,summary,claims,disc,recs,errs)

def load_skill_result(run_dir: str|Path, result_file: str|Path)->SkillResult:
    run=Path(run_dir); p=_safe_existing_file(run,result_file,"results"); return _parse_result(run,_json_obj(p))

def validate_skill_result(run_dir: str|Path, result_file: str|Path)->ContractValidationReport:
    run=Path(run_dir)
    try:
        res=load_skill_result(run,result_file)
        lookup=find_skill_request_by_id(run,res.request_id)
        if lookup.status == "not_found": raise SkillContractValidationError("linked request not found")
        if lookup.status == "ambiguous": raise SkillContractValidationError("linked request ID is ambiguous")
        req=load_skill_request(run,lookup.relative_path)
        if req.request_id!=res.request_id or req.run_id!=res.run_id or req.skill!=res.skill: raise SkillContractValidationError("result does not match linked request")
        req_rep=_report_request(run,req)
        eids=[]
        for c in res.claims: eids += c["evidence_ids"]
        for d in res.discovered_candidates: eids += d["source_evidence_ids"]
        ok, ev_errors=_verify_evidence_ids(run,eids)
        scopes=[]
        for d in res.discovered_candidates:
            dec=evaluate_scope_path(run,d["candidate"]).to_dict(); scopes.append(dec)
        actions=[]
        for r in res.recommended_actions:
            dec=evaluate_action(run,r["action_type"],r.get("candidate")).to_dict()
            if r["action_type"]=="intrusive_validation": dec["handoff_only"]=True
            actions.append(dec)
        status="valid" if ok else "evidence_failed"
        return ContractValidationReport(RESULT_CONTRACT_TYPE,True,res.run_id,res.request_id,res.result_id,res.skill,req_rep.current_request_policy_decision,len(set(eids)),ok,scopes,actions,[],ev_errors,status)
    except SkillContractValidationError as e:
        return ContractValidationReport(RESULT_CONTRACT_TYPE,False,None,None,None,None,None,0,False,[],[],[],[str(e)],"error")
