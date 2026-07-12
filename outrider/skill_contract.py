from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json, os, re, stat, tempfile
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from outrider.approval import ACTION_TYPES, INTRUSIVE, PROHIBITED, evaluate_action
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
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[1]
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
    if not p.is_absolute(): p=(Path.cwd()/p).resolve()
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

def ensure_contract_dirs(run_dir: str|Path)->None:
    run=Path(run_dir); load_manifest(run); load_state(run)
    for rel in ["contracts","contracts/requests","contracts/results"]:
        p=run/rel
        if p.exists() and os.path.islink(p): raise SkillContractValidationError("contract directories must not be symbolic links")
        p.mkdir(exist_ok=True)

def _normalize(candidate: str|None)->tuple[str|None,str|None]:
    if candidate is None: return None,None
    try: n,t,_ = _normalize_candidate(candidate); return n,t
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
    if not isinstance(mi,int) or mi<1 or mi>1000: raise SkillContractValidationError("max_items must be between 1 and 1000")
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
        req_path=run/"contracts"/"requests"/f"{res.request_id}.json"
        req=load_skill_request(run,req_path)
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
