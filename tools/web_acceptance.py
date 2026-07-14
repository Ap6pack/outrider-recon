#!/usr/bin/env python3
from __future__ import annotations

import argparse, hashlib, json, tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from uuid import uuid4

from outrider.skill_contract import utc_now
from outrider.state import load_manifest

CONTROL_VALUE = "acceptance-token"

@dataclass
class Stage:
    name: str
    status: str
    detail: str

class FakeExecutor:
    def __init__(self): self.http_calls=[]; self.dns_calls=[]
    async def invoke(self, tool, args):
        if tool == 'dns_records':
            self.dns_calls.append((tool, dict(args)))
            return {'domain': args['domain'], 'records': {'A': ['192.0.2.10']}, 'truncated': False}
        self.http_calls.append((tool, dict(args)))
        if tool == 'crtsh_lookup': return [{'common_name': args['domain'], 'name_value': args['domain']}]
        if tool == 'hudsonrock_lookup': return {'domain': args['domain'], 'total': 0, 'stealer_families': []}
        if tool == 'wayback_urls': return [{'timestamp': '20200101000000', 'url': f"https://{args['domain']}/"}]
        if tool == 'epss_score': return {'cve': args['cve_id'], 'epss': 0.01, 'percentile': 0.1}
        raise AssertionError(tool)

def files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}

def sha(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()

def assert_ok(cond, msg):
    if not cond: raise AssertionError(msg)

def run_acceptance() -> dict:
    try:
        from fastapi.testclient import TestClient
        from outrider.web_app import create_app
    except ImportError as exc:
        raise RuntimeError('Install web dependencies with .[web] to run acceptance') from exc
    stages=[]
    def stage(name, fn):
        try:
            detail=fn() or 'passed'
            stages.append(Stage(name,'PASS',detail))
        except Exception as exc:
            stages.append(Stage(name,'FAIL',f'{exc.__class__.__name__}: {exc}'))
            raise
    with tempfile.TemporaryDirectory(prefix='outrider-web-acceptance-') as td:
        root=Path(td)/'runs'; root.mkdir()
        fake=FakeExecutor()
        default=TestClient(create_app(root, enrichment_executor=fake))
        client=TestClient(create_app(root, control_token=CONTROL_VALUE, mcp_enrichment_enabled=True, enrichment_executor=fake))
        h={'X-Outrider-Control-Token': CONTROL_VALUE}
        ctx={}
        def s1():
            health=default.get('/api/health').json(); session=default.get('/api/session').json()
            assert_ok(health['network_scope']=='loopback-only' and health['authentication']=='none','loopback unauthenticated health')
            assert_ok(not health['capabilities']['mcp_enrichment_enabled'] and not session['capabilities']['mcp_invocation'],'enrichment disabled by default')
            assert_ok(default.get('/docs').status_code==404 and default.get('/openapi.json').status_code==404,'docs disabled')
            assert_ok('access-control-allow-origin' not in default.get('/api/health').headers,'no cors')
            for path in ['/api/files/x','/artifacts/x','/api/runs/x/recon','/api/runs/x/skills','/api/runs/x/results','/api/reports']:
                assert_ok(default.get(path).status_code in {404,405,422}, f'unsupported route {path}')
            assert_ok(fake.http_calls==[] and fake.dns_calls==[],'no network calls')
            return 'default safety boundaries verified'
        stage('default safety', s1)
        def s2():
            r=client.post('/api/runs',json={'target':'https://example.com/path','actor':'authorized-operator','authorization_reference':'EXAMPLE-ROE-001','in_scope':['example.com','*.example.com'],'out_of_scope':[]},headers=h)
            assert_ok(r.status_code==201,r.text); body=r.json(); ctx['rid']=body['run']['run_id']; ctx['run_dir']=next(root.iterdir())
            assert_ok(str(ctx['run_dir']).startswith(str(root)) and body['run']['target']=='example.com','safe normalized run')
            assert_ok((ctx['run_dir']/ 'artifacts').is_dir() and (ctx['run_dir']/ 'contracts'/'results').is_dir(),'scaffold')
            sc=client.get(f"/api/runs/{ctx['rid']}/scope").json(); ctx['scope_rev']=sc['scope_revision']
            assert_ok(client.post(f"/api/runs/{ctx['rid']}/scope/check",json={'candidate':'api.example.com'},headers=h).json()['decision']=='allow','scope allow')
            rep=client.put(f"/api/runs/{ctx['rid']}/scope",json={'expected_revision':ctx['scope_rev'],'actor':'authorized-operator','reason':'accepted scope update','in_scope':['example.com','*.example.com','api.example.com'],'out_of_scope':['admin.example.com']},headers=h)
            assert_ok(rep.status_code==200,rep.text); ctx['scope_rev']=rep.json()['scope']['scope_revision']
            stale=client.put(f"/api/runs/{ctx['rid']}/scope",json={'expected_revision':'0'*64,'actor':'authorized-operator','reason':'stale','in_scope':['example.com'],'out_of_scope':[]},headers=h)
            assert_ok(stale.status_code==409,'stale rejected')
            tr=client.post(f"/api/runs/{ctx['rid']}/state/transition",json={'expected_state':'initialized','new_state':'scoped','actor':'authorized-operator','reason':None},headers=h)
            assert_ok(tr.status_code==200,tr.text)
            blocked=client.put(f"/api/runs/{ctx['rid']}/scope",json={'expected_revision':ctx['scope_rev'],'actor':'authorized-operator','reason':'late','in_scope':['example.com'],'out_of_scope':[]},headers=h)
            assert_ok(blocked.status_code==409,'post-initialized scope rejected')
            return 'run creation, scope edit, stale rejection, and transition verified'
        stage('run creation and scope', s2)
        def s3():
            appr=client.get(f"/api/runs/{ctx['rid']}/approvals").json(); ctx['approval_rev']=appr['approval_revision']
            deny=client.post(f"/api/runs/{ctx['rid']}/action/check",json={'action_type':'target_enumeration','candidate':'api.example.com'},headers=h).json(); assert_ok(deny['decision']=='deny','denied without approval')
            gr=client.post(f"/api/runs/{ctx['rid']}/approvals",json={'expected_revision':ctx['approval_rev'],'expected_state':'scoped','action_type':'target_enumeration','candidate':'api.example.com','actor':'authorized-operator','reason':'DNS allowed by ROE','duration_minutes':30,'conditions':None},headers=h)
            assert_ok(gr.status_code==201,gr.text); ctx['approval_id']=gr.json()['approval']['approval_id']; ctx['approval_rev']=gr.json()['approvals']['approval_revision']
            assert_ok(client.post(f"/api/runs/{ctx['rid']}/action/check",json={'action_type':'target_enumeration','candidate':'api.example.com'},headers=h).json()['decision']=='allow','exact allow')
            assert_ok(client.post(f"/api/runs/{ctx['rid']}/action/check",json={'action_type':'target_enumeration','candidate':'other.example.com'},headers=h).json()['decision']=='deny','different candidate deny')
            assert_ok(client.post(f"/api/runs/{ctx['rid']}/action/check",json={'action_type':'intrusive_validation','candidate':'api.example.com'},headers=h).json()['decision']=='deny','prohibited denied')
            return 'approval grant and policy enforcement verified'
        stage('approvals and policy', s3)
        def s4():
            art=ctx['run_dir']/'artifacts'/'obs.txt'; art.write_text('api.example.com evidence',encoding='utf-8'); before=art.read_bytes()
            inv=client.get(f"/api/runs/{ctx['rid']}/evidence/artifacts").json(); assert_ok('api.example.com evidence' not in json.dumps(inv),'metadata only inventory')
            evv=client.get(f"/api/runs/{ctx['rid']}/evidence").json(); ctx['evidence_rev']=evv['evidence_revision']
            reg=client.post(f"/api/runs/{ctx['rid']}/evidence",json={'expected_revision':ctx['evidence_rev'],'expected_state':'scoped','relative_artifact_path':'artifacts/obs.txt','actor':'authorized-operator','artifact_type':'text','media_type':'text/plain','source':'local fixture','note':'reviewed'},headers=h)
            assert_ok(reg.status_code==201,reg.text); ctx['evidence_id']=reg.json()['evidence']['evidence_id']; ctx['evidence_rev']=reg.json()['evidence_view']['evidence_revision']
            assert_ok(reg.json()['evidence']['expected_sha256']==hashlib.sha256(before).hexdigest() and art.read_bytes()==before,'sha and bytes preserved')
            ver=client.post(f"/api/runs/{ctx['rid']}/evidence/verify",json={'evidence_id':ctx['evidence_id']},headers=h).json(); assert_ok(ver['results'][0].get('overall_status', ver['results'][0].get('status'))=='verified','evidence verified')
            assert_ok(client.get(f"/api/runs/{ctx['rid']}/evidence/artifacts/obs.txt").status_code in {404,405},'no content route')
            return 'artifact metadata, evidence registration, and verification verified'
        stage('evidence', s4)
        def s5():
            cv=client.get(f"/api/runs/{ctx['rid']}/contracts").json(); ctx['contract_rev']=cv['contract_revision']
            cr=client.post(f"/api/runs/{ctx['rid']}/contracts/requests",json={'expected_revision':ctx['contract_rev'],'expected_state':'scoped','skill':'recon-asset-discovery','actor':'authorized-operator','objective':'Review public source observation','action_type':'public_source_lookup','candidate':'api.example.com','input_evidence_ids':[ctx['evidence_id']],'max_items':10,'notes':'acceptance'},headers=h)
            assert_ok(cr.status_code==201,cr.text); ctx['request_id']=cr.json()['request']['request_id']; ctx['contract_rev']=cr.json()['contracts']['contract_revision']
            vr=client.post(f"/api/runs/{ctx['rid']}/contracts/requests/{ctx['request_id']}/validate",json={'expected_revision':ctx['contract_rev']},headers=h); assert_ok(vr.status_code==200,vr.text)
            claim_id=str(uuid4()); result_id=str(uuid4()); ctx['claim_id']=claim_id; ctx['result_id']=result_id
            result={'schema_version':1,'contract_type':'skill_result','result_id':result_id,'request_id':ctx['request_id'],'run_id':ctx['rid'],'skill':'recon-asset-discovery','completed_at':utc_now(),'status':'completed','summary':'found candidate','claims':[{'claim_id':claim_id,'classification':'finding_candidate','subject':'api.example.com','statement':'Exposed schema observed','confidence':'high','suggested_severity':'medium','evidence_ids':[ctx['evidence_id']]}],'discovered_candidates':[{'candidate':'api.example.com','relationship':'observed_host','source_evidence_ids':[ctx['evidence_id']]}],'recommended_actions':[],'errors':[]}
            rp=ctx['run_dir']/'contracts'/'results'/f'{result_id}.json'; rp.write_text(json.dumps(result,sort_keys=True),encoding='utf-8'); ctx['result_path']=rp; ctx['source_sha']=sha(rp)
            ctx['contract_rev']=client.get(f"/api/runs/{ctx['rid']}/contracts").json()['contract_revision']
            rr=client.post(f"/api/runs/{ctx['rid']}/contracts/results/{result_id}/validate",json={'expected_revision':ctx['contract_rev']},headers=h); assert_ok(rr.status_code==200,rr.text)
            assert_ok(client.get(f"/api/runs/{ctx['rid']}/findings").json()['findings']==[],'no auto promotion')
            return 'request creation and result validation verified without execution'
        stage('contracts', s5)
        def s6():
            for old,new in [('scoped','collecting'),('collecting','analyzing')]: client.post(f"/api/runs/{ctx['rid']}/state/transition",json={'expected_state':old,'new_state':new,'actor':'authorized-operator','reason':None},headers=h)
            cand=client.get(f"/api/runs/{ctx['rid']}/findings/candidates").json(); assert_ok(cand.get('candidates'), 'candidate available: '+json.dumps(cand, sort_keys=True)[:1000])
            fv=client.get(f"/api/runs/{ctx['rid']}/findings").json(); vc=fv['validation_context']
            pr=client.post(f"/api/runs/{ctx['rid']}/findings",json={'expected_finding_revision':fv['finding_revision'],'expected_contract_revision':vc['contract_revision'],'expected_scope_revision':vc['scope_revision'],'expected_evidence_revision':vc['evidence_revision'],'expected_state':'analyzing','result_id':ctx['result_id'],'claim_id':ctx['claim_id'],'expected_source_sha256':ctx['source_sha'],'actor':'authorized-operator','title':'Public schema','candidate':'api.example.com','severity':'medium','confidence':'high','validation_basis':'response_evidence','validation_reason':'Human reviewed acceptance fixture','impact':'Information exposure','remediation':'Restrict schema','location':'/openapi.json','notes':'acceptance','supplementary_evidence_ids':[ctx['evidence_id']]},headers=h)
            assert_ok(pr.status_code==201,pr.text); ctx['finding_id']=pr.json()['finding']['finding_id']
            assert_ok(pr.json()['finding']['source']['result_sha256']==ctx['source_sha'],'source hash captured')
            assert_ok(client.get(f"/api/runs/{ctx['rid']}/findings/candidates").json()['candidates'][0].get('already_promoted') is True,'candidate promoted')
            vf=client.post(f"/api/runs/{ctx['rid']}/findings/verify",json={'finding_id':ctx['finding_id']},headers=h).json(); assert_ok(vf['results'][0].get('overall_status', vf['results'][0].get('status'))=='verified','finding verified')
            assert_ok(client.delete(f"/api/runs/{ctx['rid']}/findings/{ctx['finding_id']}").status_code in {404,405},'no delete')
            return 'human finding promotion and verification verified'
        stage('findings', s6)
        def s7():
            cat=client.get(f"/api/runs/{ctx['rid']}/mcp").json(); tools=[t['tool_name'] for t in cat['tools']]; assert_ok(tools==['crtsh_lookup','dns_records','epss_score','hudsonrock_lookup','wayback_urls'],tools)
            pf=client.post(f"/api/runs/{ctx['rid']}/mcp/preflight",json={'tool_name':'crtsh_lookup','arguments':{'domain':'api.example.com'}},headers=h); assert_ok(pf.status_code==200,pf.text); assert_ok(fake.http_calls==[],'preflight no provider')
            base={'expected_state':'analyzing','expected_scope_revision':ctx['scope_rev'],'expected_approval_revision':ctx['approval_rev'],'actor':'authorized-operator','purpose':'acceptance','confirmed':True}
            inv=client.post(f"/api/runs/{ctx['rid']}/mcp/invoke",json={**base,'tool_name':'crtsh_lookup','arguments':{'domain':'api.example.com'}},headers=h); assert_ok(inv.status_code==200,inv.text); assert_ok(len(fake.http_calls)==1 and inv.json()['invocation']['transient'],'transient one call')
            out=client.post(f"/api/runs/{ctx['rid']}/mcp/invoke",json={**base,'tool_name':'crtsh_lookup','arguments':{'domain':'evil.test'}},headers=h); assert_ok(out.status_code==409 and len(fake.http_calls)==1,'out-of-scope blocked')
            dns=client.post(f"/api/runs/{ctx['rid']}/mcp/invoke",json={**base,'tool_name':'dns_records','arguments':{'domain':'api.example.com'}},headers=h); assert_ok(dns.status_code==200,dns.text); assert_ok(len(fake.dns_calls)==1,'dns called once')
            rv=client.post(f"/api/runs/{ctx['rid']}/approvals/{ctx['approval_id']}/revoke",json={'expected_revision':ctx['approval_rev'],'actor':'authorized-operator','reason':'done'},headers=h); assert_ok(rv.status_code==200,rv.text); ctx['approval_rev']=rv.json()['approvals']['approval_revision']
            dns2=client.post(f"/api/runs/{ctx['rid']}/mcp/invoke",json={**base,'expected_approval_revision':ctx['approval_rev'],'tool_name':'dns_records','arguments':{'domain':'api.example.com'}},headers=h); assert_ok(dns2.status_code==409 and len(fake.dns_calls)==1,'dns blocked after revoke')
            return 'fixed MCP catalog, preflight, transient invocation, and DNS approval enforcement verified'
        stage('MCP enrichment', s7)
        def s8():
            html=client.get('/').text; css=client.get('/static/app.css').text; js=client.get('/static/app.js').text; alltxt=html+css+js
            for term in ['Overview','Scope','State','Evidence','Approvals','Contracts','Findings','Integrity','MCP']:
                assert_ok(term in alltxt, f'tab/control {term}')
            for bad in ['<script>', 'http://', 'https://', 'innerHTML', 'eval(', 'localStorage', 'sessionStorage', CONTROL_VALUE, 'Run recon', 'Upload result']:
                assert_ok(bad not in alltxt, f'absent {bad}')
            for term in ['disabled by default','transient','unauthenticated attribution']:
                assert_ok(term.lower() in alltxt.lower(), f'ui text {term}')
            return 'static UI and browser security boundaries verified'
        stage('static UI and security boundaries', s8)
        def s9():
            before=files(ctx['run_dir'])
            readonly=[lambda: client.post(f"/api/runs/{ctx['rid']}/mcp/preflight",json={'tool_name':'crtsh_lookup','arguments':{'domain':'api.example.com'}},headers=h), lambda: client.post(f"/api/runs/{ctx['rid']}/action/check",json={'action_type':'target_enumeration','candidate':'api.example.com'},headers=h), lambda: client.post(f"/api/runs/{ctx['rid']}/evidence/verify",json={'evidence_id':ctx['evidence_id']},headers=h), lambda: client.post(f"/api/runs/{ctx['rid']}/contracts/results/{ctx['result_id']}/validate",json={'expected_revision':ctx['contract_rev']},headers=h), lambda: client.post(f"/api/runs/{ctx['rid']}/findings/verify",json={'finding_id':ctx['finding_id']},headers=h)]
            for fn in readonly: fn()
            after=files(ctx['run_dir']); assert_ok(before==after,'read-only operations preserved files')
            assert_ok(not list(ctx['run_dir'].rglob('*.tmp')),'no tmp files')
            return 'file integrity preserved across read-only operations'
        stage('file integrity', s9)
    status='passed' if all(s.status=='PASS' for s in stages) else 'failed'
    return {'status':status,'stages':[asdict(s) for s in stages], 'stage_count':len(stages)}

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument('--json',action='store_true'); args=ap.parse_args(argv)
    try: result=run_acceptance()
    except Exception as exc:
        result={'status':'failed','error':f'{exc.__class__.__name__}: {exc}'}
        if args.json: print(json.dumps(result,indent=2,sort_keys=True))
        else: print(f"FAIL: {result['error']}")
        return 2
    if args.json: print(json.dumps(result,indent=2,sort_keys=True))
    else:
        for s in result['stages']: print(f"{s['status']}: {s['name']} - {s['detail']}")
        print(f"Overall status: {result['status']}")
    return 0 if result['status']=='passed' else 2
if __name__=='__main__': raise SystemExit(main())
