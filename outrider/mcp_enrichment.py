from __future__ import annotations

import asyncio, json, logging, socket, re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from outrider.approval import ALLOWED_STATES, action_class, approval_revision
from outrider.mcp_guard import MCPGuardDecision, TOOL_POLICIES, authorize_mcp_tool, normalize_domain_candidate
from outrider.scope import scope_revision
from outrider.state import load_manifest, load_state

_SCOPE_NOTE = "Returned observations do not expand authorized scope."
_NOTICE = "Transient point-in-time enrichment. The response was not automatically saved, registered as evidence, or converted into a contract or finding."
_UA = "outrider-recon/1.0 (bounded enrichment)"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
MAX_BODY = 5 * 1024 * 1024
MAX_SERIALIZED = 1024 * 1024
LIMITS = {"crtsh_lookup":500,"hudsonrock_lookup":100,"epss_score":1,"wayback_urls":500,"dns_records":500}
log = logging.getLogger(__name__)

class EnrichmentError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 502):
        super().__init__(message); self.code=code; self.message=message; self.status_code=status_code
class InputError(ValueError): pass

@dataclass
class InvocationResult:
    result: Any
    metadata: dict[str, Any]

def catalog(enabled: bool | None = None) -> list[dict[str, Any]]:
    meta = {
      "crtsh_lookup": ("crt.sh lookup","Fetch bounded certificate transparency observations for an in-scope domain.","crt.sh","http", {"domain":{"type":"string","required":True,"maximum_length":253}}),
      "hudsonrock_lookup": ("HudsonRock lookup","Fetch bounded public HudsonRock Cavalier domain exposure summary.","HudsonRock Cavalier","http", {"domain":{"type":"string","required":True,"maximum_length":253}}),
      "epss_score": ("EPSS score","Fetch a bounded FIRST EPSS score after policy checks the manifest target.","FIRST EPSS","http", {"cve_id":{"type":"string","required":True,"maximum_length":32}}),
      "wayback_urls": ("Wayback URLs","Fetch bounded Wayback CDX index URLs for an in-scope domain without fetching archived pages.","Wayback CDX","http", {"domain":{"type":"string","required":True,"maximum_length":253},"limit":{"type":"integer","required":False,"minimum":1,"maximum":500,"default":100}}),
      "dns_records": ("DNS records","Fetch bounded DNS records for an exact approved domain.","DNS","dns", {"domain":{"type":"string","required":True,"maximum_length":253}}),
    }
    rows=[]
    for name in sorted(TOOL_POLICIES):
        p=TOOL_POLICIES[name]; display, desc, provider, network, schema = meta[name]
        cls=action_class(p.action_type)
        row={"tool_name":name,"display_name":display,"description":desc,"action_type":p.action_type,"action_class":cls,"candidate_source":p.candidate_source,"candidate_required":p.candidate_source=="domain_argument","approval_required":cls in {"active","intrusive"},"allowed_states":sorted(ALLOWED_STATES[p.action_type]),"argument_schema":schema,"provider":provider,"network_kind":network,"result_limit":LIMITS[name]}
        if enabled is not None: row["enabled"] = enabled
        rows.append(row)
    return rows

def validate_arguments(tool: str, arguments: Any, *, web: bool=False) -> dict[str, Any]:
    if tool not in TOOL_POLICIES: raise InputError("unknown tool")
    if not isinstance(arguments, dict): raise InputError("arguments must be a JSON object")
    allowed = set(catalog()[[r["tool_name"] for r in catalog()].index(tool)]["argument_schema"])
    if set(arguments) - allowed: raise InputError("unknown argument field")
    out: dict[str, Any] = {}
    if tool in {"crtsh_lookup","hudsonrock_lookup","wayback_urls","dns_records"}:
        if "domain" not in arguments: raise InputError("domain is required")
        out["domain"] = normalize_domain_candidate(arguments["domain"])
    if tool == "epss_score":
        if set(arguments) != {"cve_id"}: raise InputError("cve_id is required")
        cve = arguments["cve_id"]
        if not isinstance(cve, str) or len(cve)>32: raise InputError("invalid CVE")
        cve = cve.strip().upper()
        if not _CVE.fullmatch(cve): raise InputError("invalid CVE")
        out["cve_id"] = cve
    if tool == "wayback_urls":
        limit = arguments.get("limit", 100)
        max_limit = 500 if web else 10000
        if isinstance(limit, bool) or not isinstance(limit, int): raise InputError("limit must be an integer")
        if limit < 1 or limit > max_limit: raise InputError(f"limit must be between 1 and {max_limit}")
        out["limit"] = limit
    return out

def envelope(tool: str, policy: MCPGuardDecision, result: Any=None, error: dict[str,str]|None=None) -> dict[str, Any]:
    return {"ok": error is None, "tool": tool, "policy": policy.to_dict(), "result": result if error is None else None, "error": error, "scope_note": _SCOPE_NOTE}

def result_metadata(result: Any, limit: int | None = None) -> dict[str, Any]:
    if isinstance(result, list): count=len(result); truncated=limit is not None and count>=limit
    elif isinstance(result, dict) and "records" in result and isinstance(result["records"], dict):
        count=sum(len(v) for v in result["records"].values() if isinstance(v,list)); truncated=bool(result.get("truncated"))
    else: count=1 if result else 0; truncated=False
    size=len(json.dumps(result, sort_keys=True, default=str).encode())
    if size > MAX_SERIALIZED: raise EnrichmentError("oversized_result", "upstream result exceeded response size limit", 502)
    return {"item_count":count,"truncated":truncated,"serialized_size_bytes":size}

class FixedEnrichmentExecutor:
    async def invoke(self, tool: str, args: dict[str, Any]) -> Any:
        if tool == "dns_records": return await asyncio.to_thread(self._dns, args["domain"])
        try: import httpx
        except ImportError as exc: raise EnrichmentError("dependency_unavailable", 'Install enrichment dependencies with: python -m pip install -e ".[enrichment]"', 503) from exc
        timeout=httpx.Timeout(30.0, connect=10.0)
        async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent":_UA}, trust_env=False, follow_redirects=False) as client:
            if tool=="crtsh_lookup": data=await self._json(client,"https://crt.sh/", {"q":args["domain"],"output":"json"}); return self._crt(data)
            if tool=="hudsonrock_lookup": data=await self._json(client,"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain", {"domain":args["domain"]}); return self._hud(data,args["domain"])
            if tool=="epss_score": data=await self._json(client,"https://api.first.org/data/v1/epss", {"cve":args["cve_id"]}); return self._epss(data,args["cve_id"])
            if tool=="wayback_urls": data=await self._json(client,"https://web.archive.org/cdx/search/cdx", {"url":f'{args["domain"]}/*',"output":"json","fl":"timestamp,original","limit":str(args["limit"])}); return self._way(data,args["limit"])
        raise InputError("unknown tool")
    async def _json(self, client, url, params):
        try:
            r=await client.get(url, params=params); r.raise_for_status()
            if len(r.content)>MAX_BODY: raise EnrichmentError("oversized_response","upstream response exceeded size limit",502)
            return r.json()
        except EnrichmentError: raise
        except Exception as exc:
            name=exc.__class__.__name__.lower()
            if "timeout" in name: raise EnrichmentError("upstream_timeout","upstream request timed out",504)
            if "status" in name: raise EnrichmentError("upstream_http_error","upstream returned an HTTP error",502)
            if "json" in name or "decode" in name: raise EnrichmentError("unexpected_response","upstream response was malformed",502)
            raise EnrichmentError("upstream_error","upstream request failed",502)
    def _crt(self, raw):
        if not isinstance(raw,list): raise EnrichmentError("unexpected_response","upstream response was malformed",502)
        out=[]; seen=set()
        for e in raw:
            if not isinstance(e,dict): raise EnrichmentError("unexpected_response","upstream response was malformed",502)
            item={k:e.get(k) for k in ("common_name","name_value","issuer_ca_id","not_before","not_after")}; key=json.dumps(item,sort_keys=True)
            if key not in seen: seen.add(key); out.append(item)
            if len(out)>=500: break
        return out
    def _hud(self, data, domain):
        if not isinstance(data,dict): raise EnrichmentError("unexpected_response","upstream response was malformed",502)
        fam=[]
        for e in data.get("data",[]):
            if isinstance(e,dict):
                f=e.get("stealer_family") or e.get("stealer")
                if f and f not in fam and len(fam)<100: fam.append(f)
        return {"domain":domain,"total":data.get("total", len(data.get("data",[])) if isinstance(data.get("data",[]),list) else None),"stealer_families":fam}
    def _epss(self,data,cve):
        if not isinstance(data,dict): raise EnrichmentError("unexpected_response","upstream response was malformed",502)
        rows=data.get("data") or []
        if not rows: return {"cve":cve,"epss":None,"percentile":None,"note":"No EPSS data found"}
        e=rows[0]
        if not isinstance(e,dict): raise EnrichmentError("unexpected_response","upstream response was malformed",502)
        return {"cve":e.get("cve",cve),"epss":float(e["epss"]) if "epss" in e else None,"percentile":float(e["percentile"]) if "percentile" in e else None}
    def _way(self, raw, limit):
        if not isinstance(raw,list): raise EnrichmentError("unexpected_response","upstream response was malformed",502)
        out=[]
        for row in raw[1:]:
            if not isinstance(row,list): raise EnrichmentError("unexpected_response","upstream response was malformed",502)
            if len(row)>=2: out.append({"timestamp":str(row[0]),"url":str(row[1])})
            if len(out)>=min(limit,500): break
        return out
    def _dns(self, domain):
        types=["A","AAAA","MX","TXT","NS","SOA","CAA","CNAME"]; records={}; total=0
        try:
            import dns.resolver
            resolver=dns.resolver.Resolver(); resolver.timeout=5; resolver.lifetime=10
            for t in types:
                try: vals=[r.to_text() for r in resolver.resolve(domain,t)]
                except dns.resolver.NXDOMAIN as exc: raise EnrichmentError("dns_error","DNS resolver failure",502) from exc
                except Exception: continue
                vals=vals[:min(100,500-total)]; total+=len(vals)
                if vals: records[t]=vals
                if total>=500: break
        except ImportError:
            try: infos=socket.getaddrinfo(domain,None)
            except socket.gaierror as exc: raise EnrichmentError("dns_error","DNS resolver failure",502) from exc
            addrs=[]
            for info in infos:
                a=info[4][0]
                if a not in addrs and len(addrs)<100: addrs.append(a)
            records["A_AAAA"] = addrs
        return {"domain":domain,"records":records,"truncated":total>=500}

async def preflight(run_dir: str, tool: str, arguments: Any) -> dict[str, Any]:
    args=validate_arguments(tool, arguments, web=True)
    pol=authorize_mcp_tool(tool, run_dir, domain=args.get("domain"))
    return {"ok":True,"network_performed":False,"tool":next(r for r in catalog() if r["tool_name"]==tool),"normalized_arguments":args,"policy":pol.to_dict(),"validation_context":{"current_state":load_state(run_dir).current_state,"scope_revision":scope_revision(run_dir),"approval_revision":approval_revision(run_dir)},"notice":"Preflight only. No HTTP or DNS activity occurred."}

async def invoke(run_dir: str, tool: str, arguments: Any, executor: Any | None=None, *, web: bool=False) -> tuple[MCPGuardDecision, InvocationResult]:
    args=validate_arguments(tool, arguments, web=web)
    pol=authorize_mcp_tool(tool, run_dir, domain=args.get("domain"))
    if pol.decision != "allow": return pol, InvocationResult(None,{"item_count":0,"truncated":False,"serialized_size_bytes":0})
    ex=executor or FixedEnrichmentExecutor()
    result=await ex.invoke(tool,args)
    meta=result_metadata(result, LIMITS.get(tool))
    return pol, InvocationResult(result, meta)

async def mcp_call(tool: str, run_dir: str, arguments: dict[str, Any], executor: Any | None=None) -> dict[str, Any]:
    try:
        pol,res=await invoke(run_dir, tool, arguments, executor, web=False)
        if pol.decision != "allow": return envelope(tool, pol, error={"code":"policy_denied" if pol.decision=="deny" else "policy_error","message":pol.reason})
        return envelope(tool, pol, res.result)
    except InputError as exc:
        pol=authorize_mcp_tool(tool, run_dir, domain=arguments.get("domain") if isinstance(arguments,dict) else None)
        code = "policy_error" if pol.decision == "error" else "invalid_input"
        return envelope(tool, pol, error={"code":code,"message":str(exc)})
    except ValueError as exc:
        pol=authorize_mcp_tool(tool, run_dir, domain=arguments.get("domain") if isinstance(arguments,dict) else None)
        code = "policy_error" if pol.decision == "error" else "unexpected_response"
        return envelope(tool, pol, error={"code":code,"message":str(exc)})
    except EnrichmentError as exc:
        pol=authorize_mcp_tool(tool, run_dir, domain=arguments.get("domain") if isinstance(arguments,dict) else None)
        return envelope(tool, pol, error={"code":exc.code,"message":exc.message})
    except Exception as exc:
        pol=authorize_mcp_tool(tool, run_dir, domain=arguments.get("domain") if isinstance(arguments,dict) else None)
        name=exc.__class__.__name__.lower()
        if "timeout" in name: return envelope(tool, pol, error={"code":"upstream_timeout","message":f"{tool} request timed out"})
        return envelope(tool, pol, error={"code":"upstream_error","message":f"{tool} request failed"})

