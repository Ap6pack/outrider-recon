from __future__ import annotations
import json, sys, tempfile, unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
except ImportError:  # optional web extra not installed in base environments
    TestClient = None
from outrider import cli, web_view
from outrider.web_app import create_app
from uuid import uuid4
from outrider.state import load_manifest, transition_state
from outrider.evidence import register_evidence
from outrider.approval import grant_approval
from outrider.skill_contract import create_skill_request, utc_now
from outrider.finding import promote_finding

class Args: pass

def make_run(root, name='example.com'):
    a=Args(); a.target=name; a.output_dir=str(root); a.scope=['example.com','*.example.com']; a.exclude=[]; a.actor='authorized-operator'; a.authorization_reference='EXAMPLE-ROE-001'; cli.init_run(a)
    return Path(root)/name

def populate(run):
    transition_state(run,'scoped','authorized-operator'); transition_state(run,'collecting','authorized-operator'); transition_state(run,'analyzing','authorized-operator')
    art=run/'artifacts'/'obs.txt'; art.write_text('api.example.com evidence', encoding='utf-8')
    ev=register_evidence(run,'artifacts/obs.txt','authorized-operator','text','text/plain','local','note')
    grant_approval(run,'target_enumeration','api.example.com','authorized-operator','approved',duration_minutes=30)
    req,path,_=create_skill_request(run,'recon-asset-discovery','authorized-operator','review','public_source_lookup','example.com',[ev.evidence_id])
    claim_id=str(uuid4())
    result={"schema_version":1,"contract_type":"skill_result","result_id":str(uuid4()),"request_id":req.request_id,"run_id":req.run_id,"skill":req.skill,"completed_at":utc_now(),"status":"completed","summary":"found candidate","claims":[{"claim_id":claim_id,"classification":"finding_candidate","subject":"api.example.com","statement":"schema exposed","confidence":"high","suggested_severity":"medium","evidence_ids":[ev.evidence_id]}],"discovered_candidates":[],"recommended_actions":[],"errors":[]}
    rp=run/'contracts'/'results'/f'{result["result_id"]}.json'; rp.write_text(json.dumps(result, sort_keys=True), encoding='utf-8')
    promote_finding(run,rp,claim_id,actor='authorized-operator',title='Public schema',candidate='api.example.com',severity='medium',confidence='high',validation_basis='response_evidence',validation_reason='reviewed',impact='info leak',remediation='restrict',location='/openapi.json')

@unittest.skipIf(TestClient is None, "FastAPI web extra is not installed")
class WebAppTests(unittest.TestCase):
    def client(self, root, token='tok'): return TestClient(create_app(root, control_token=token))


    def test_focused_web_run_scope_smoke(self):
        with tempfile.TemporaryDirectory() as td:
            runs_root = Path(td) / 'runs'; runs_root.mkdir()
            c = self.client(runs_root, token='fixture')
            h = {'X-Outrider-Control-Token': 'fixture'}
            create = c.post('/api/runs', json={'target':'https://example.com/path','actor':'authorized-operator','authorization_reference':'EXAMPLE-ROE-001','in_scope':['example.com','*.example.com'],'out_of_scope':[], 'confirmed': True}, headers=h)
            self.assertEqual(create.status_code, 201, create.text)
            rid = create.json()['run']['run_id']
            self.assertEqual(c.get('/api/runs').json()['total'], 1)
            self.assertEqual(create.json()['run']['current_state'], 'initialized')
            first_scope = c.get(f'/api/runs/{rid}/scope').json()
            first_revision = first_scope['scope_revision']
            check = c.post(f'/api/runs/{rid}/scope/check', json={'candidate':'api.example.com'}, headers=h)
            self.assertEqual(check.status_code, 200, check.text)
            self.assertEqual(check.json()['decision'], 'allow')
            replace = c.put(f'/api/runs/{rid}/scope', json={'expected_revision':first_revision,'actor':'authorized-operator','reason':'Add authorized API subdomains from updated ROE','in_scope':['example.com','*.example.com','api2.example.com'],'out_of_scope':['admin.example.com']}, headers=h)
            self.assertEqual(replace.status_code, 200, replace.text)
            self.assertNotEqual(replace.json()['scope']['scope_revision'], first_revision)
            self.assertEqual(c.post(f'/api/runs/{rid}/scope/check', json={'candidate':'example.com'}, headers=h).json()['decision'], 'allow')
            trans = c.post(f'/api/runs/{rid}/state/transition', json={'expected_state':'initialized','new_state':'scoped','actor':'authorized-operator','reason':None}, headers=h)
            self.assertEqual(trans.status_code, 200, trans.text)
            stale = c.put(f'/api/runs/{rid}/scope', json={'expected_revision':replace.json()['scope']['scope_revision'],'actor':'authorized-operator','reason':'blocked','in_scope':['example.com'],'out_of_scope':[]}, headers=h)
            self.assertEqual(stale.status_code, 409)
            self.assertEqual(c.get('/').status_code, 200); self.assertEqual(c.get('/static/app.css').status_code, 200); self.assertEqual(c.get('/static/app.js').status_code, 200)

    def test_focused_control_plane_smoke_transition(self):
        with tempfile.TemporaryDirectory() as td:
            runs_root = Path(td) / 'runs'
            runs_root.mkdir()
            run = make_run(runs_root)
            rid = load_manifest(run).run_id
            c = self.client(runs_root, token='fixture')

            health = c.get('/api/health')
            self.assertEqual(health.status_code, 200)
            self.assertEqual(health.json()['mode'], 'limited-control')
            self.assertEqual(c.get('/api/session').status_code, 200)
            self.assertEqual(c.get('/').status_code, 200)
            self.assertEqual(c.get('/static/app.css').status_code, 200)
            self.assertEqual(c.get('/static/app.js').status_code, 200)

            body = {
                'expected_state': 'initialized',
                'new_state': 'scoped',
                'actor': 'authorized-operator',
                'reason': None,
            }
            self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', json=body).status_code, 403)
            ok = c.post(
                f'/api/runs/{rid}/state/transition',
                json=body,
                headers={'X-Outrider-Control-Token': 'fixture'},
            )
            self.assertEqual(ok.status_code, 200, ok.text)
            self.assertEqual(ok.json()['state']['current_state'], 'scoped')
            refreshed = c.get(f'/api/runs/{rid}/state')
            self.assertEqual(refreshed.status_code, 200)
            self.assertEqual(refreshed.json()['current_state'], 'scoped')

    def test_health_runs_details_headers_and_static_ui(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.client(td)
            r=c.get('/api/health'); self.assertEqual(r.status_code,200); self.assertEqual(r.json()['mode'],'limited-control')
            self.assertEqual(r.headers['cache-control'],'no-store')
            self.assertIn("default-src 'self'", r.headers['content-security-policy'])
            self.assertEqual(r.headers['x-content-type-options'],'nosniff')
            self.assertNotIn('access-control-allow-origin', r.headers)
            self.assertEqual(c.get('/api/runs').json()['total'],0)
            run=make_run(td); populate(run); rid=load_manifest(run).run_id
            runs=c.get('/api/runs').json(); self.assertEqual(runs['total'],1)
            for view in ['overview','scope','state','evidence','approvals','contracts','findings','integrity']:
                resp=c.get(f'/api/runs/{rid}/{view}')
                self.assertEqual(resp.status_code,200,view)
                body=resp.text
                self.assertNotIn(td, body); self.assertNotIn('Traceback', body); self.assertNotIn('api.example.com evidence', body)
            html=c.get('/').text; js=c.get('/static/app.js').text; css=c.get('/static/app.css').text
            self.assertIn('Run dashboard', html); self.assertIn('guarded run creation', html); self.assertIn('viewport', html)
            for term in ['Overview','Scope','State','Evidence','Approvals','Contracts','Findings','Integrity']:
                self.assertIn(term, html)
            bad_terms=['cdn','analytics','fonts.googleapis','eval(','innerHTML','localStorage','sessionStorage']
            for term in bad_terms:
                self.assertNotIn(term, html+js+css)
            self.assertIn('role="main"', html)

    def test_errors_mutation_routes_docs_and_no_artifact_route(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); populate(run); rid=load_manifest(run).run_id
            before={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
            c=self.client(td)
            self.assertEqual(c.get('/api/runs/not-a-uuid/overview').status_code,422)
            self.assertEqual(c.get(f'/api/runs/00000000-0000-4000-8000-000000000000/overview').status_code,404)
            for method in ['put','patch','delete']:
                self.assertEqual(getattr(c,method)('/api/runs').status_code,405)
                self.assertEqual(getattr(c,method)(f'/api/runs/{rid}/overview').status_code,405)
            self.assertEqual(c.post('/api/runs').status_code,403)
            self.assertEqual(c.post(f'/api/runs/{rid}/state/transition').status_code,403)
            self.assertEqual(c.get('/docs').status_code,404); self.assertEqual(c.get('/openapi.json').status_code,404)
            self.assertEqual(c.get('/artifacts/obs.txt').status_code,404)
            self.assertEqual(c.get('/api/files/manifest.json').status_code,404)
            for path in ['/','/api/runs',f'/api/runs/{rid}/integrity']:
                c.get(path)
            after={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
            self.assertEqual(before, after)


    def test_session_token_and_state_transition_guards(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); rid=load_manifest(run).run_id; c=self.client(td, token='fixture')
            session=c.get('/api/session')
            self.assertEqual(session.status_code,200); self.assertEqual(session.headers['cache-control'],'no-store')
            self.assertEqual(session.json()['control_token'],'fixture')
            self.assertTrue(session.json()['capabilities']['state_transition']); self.assertTrue(session.json()['capabilities']['run_creation']); self.assertTrue(session.json()['capabilities']['scope_edit']); self.assertTrue(session.json()['capabilities']['scope_check'])
            for path in ['/', '/static/app.js', '/api/runs', f'/api/runs/{rid}/state']:
                self.assertNotIn('fixture', c.get(path).text)
            body={"expected_state":"initialized","new_state":"scoped","actor":"authorized-operator","reason":None}
            before=(run/'run.jsonl').read_text()
            self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', json=body).status_code,403)
            self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', json=body, headers={'X-Outrider-Control-Token':'bad'}).status_code,403)
            self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', json=body, headers={'X-Outrider-Control-Token':'fixture','Sec-Fetch-Site':'cross-site'}).status_code,403)
            self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', json=body, headers={'X-Outrider-Control-Token':'fixture','Origin':'http://evil.test'}).status_code,403)
            self.assertEqual((run/'run.jsonl').read_text(), before)
            ok=c.post(f'/api/runs/{rid}/state/transition', json=body, headers={'X-Outrider-Control-Token':'fixture'})
            self.assertEqual(ok.status_code,200,ok.text); self.assertTrue(ok.json()['ok'])
            self.assertEqual(ok.json()['state']['current_state'],'scoped')
            self.assertEqual(len((run/'run.jsonl').read_text().splitlines()), 2)
            stale=c.post(f'/api/runs/{rid}/state/transition', json=body, headers={'X-Outrider-Control-Token':'fixture'})
            self.assertEqual(stale.status_code,409)

    def test_state_transition_request_validation_and_default_token(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); rid=load_manifest(run).run_id; c=self.client(td, token='fixture')
            generated=TestClient(create_app(td)).get('/api/session').json()['control_token']
            self.assertIsInstance(generated,str); self.assertGreater(len(generated),20)
            headers={'X-Outrider-Control-Token':'fixture'}
            self.assertEqual(c.post('/api/runs/not-a-uuid/state/transition', json={}, headers=headers).status_code,422)
            self.assertEqual(c.post('/api/runs/00000000-0000-4000-8000-000000000000/state/transition', json={}, headers=headers).status_code,404)
            self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', data='{', headers={**headers,'Content-Type':'application/json'}).status_code,422)
            self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', json={'expected_state':'initialized','new_state':'scoped'}, headers=headers).status_code,422)
            bad={'expected_state':'initialized','new_state':'completed','actor':'authorized-operator','reason':None}
            before=(run/'run.jsonl').read_text(); self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', json=bad, headers=headers).status_code,409); self.assertEqual((run/'run.jsonl').read_text(), before)
            unknown={**bad,'extra':True}; self.assertEqual(c.post(f'/api/runs/{rid}/state/transition', json=unknown, headers=headers).status_code,422)

    def test_approval_projection_grant_revoke_and_action_check(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); rid=load_manifest(run).run_id; c=self.client(td, token='fixture')
            h={'X-Outrider-Control-Token':'fixture'}
            c.post(f'/api/runs/{rid}/state/transition', json={'expected_state':'initialized','new_state':'scoped','actor':'authorized-operator','reason':None}, headers=h)
            view=c.get(f'/api/runs/{rid}/approvals').json(); rev=view['approval_revision']
            self.assertTrue(view['grant_enabled']); self.assertIn('action_types', view); self.assertEqual(view['max_lifetime_minutes'],10080)
            before=(run/'approvals.jsonl').read_bytes()
            self.assertEqual(c.post(f'/api/runs/{rid}/approvals', json={}, headers={}).status_code,403)
            self.assertEqual((run/'approvals.jsonl').read_bytes(), before)
            bad=c.post(f'/api/runs/{rid}/approvals', json={'expected_revision':rev,'expected_state':'scoped','action_type':'local_analysis','candidate':'api.example.com','actor':'authorized-operator','reason':'x','duration_minutes':30}, headers=h)
            self.assertEqual(bad.status_code,422); self.assertEqual((run/'approvals.jsonl').read_bytes(), before)
            ok=c.post(f'/api/runs/{rid}/approvals', json={'expected_revision':rev,'expected_state':'scoped','action_type':'target_enumeration','candidate':'API.EXAMPLE.COM','actor':'authorized-operator','reason':'Authorized DNS enumeration under ROE','duration_minutes':30,'conditions':'Read-only enumeration only'}, headers=h)
            self.assertEqual(ok.status_code,201,ok.text); body=ok.json(); aid=body['approval']['approval_id']; self.assertEqual(body['approval']['normalized_candidate'],'api.example.com'); self.assertTrue(body['approval']['revocable']); self.assertNotEqual(body['approvals']['approval_revision'], rev)
            self.assertEqual(c.post(f'/api/runs/{rid}/approvals', json={'expected_revision':rev,'expected_state':'scoped','action_type':'target_enumeration','candidate':'api.example.com','actor':'authorized-operator','reason':'duplicate','duration_minutes':30}, headers=h).status_code,409)
            allow=c.post(f'/api/runs/{rid}/action/check', json={'action_type':'target_enumeration','candidate':'api.example.com'}, headers=h)
            self.assertEqual(allow.status_code,200); self.assertEqual(allow.json()['decision'],'allow'); self.assertEqual(allow.json()['matched_approval_id'], aid)
            deny=c.post(f'/api/runs/{rid}/action/check', json={'action_type':'target_enumeration','candidate':'other.example.com'}, headers=h)
            self.assertEqual(deny.status_code,200); self.assertEqual(deny.json()['decision'],'deny')
            rev=body['approvals']['approval_revision']
            revoked=c.post(f'/api/runs/{rid}/approvals/{aid}/revoke', json={'expected_revision':rev,'actor':'authorized-operator','reason':'closed'}, headers=h)
            self.assertEqual(revoked.status_code,200,revoked.text); self.assertNotEqual(revoked.json()['approvals']['approval_revision'], rev)
            self.assertEqual(c.post(f'/api/runs/{rid}/action/check', json={'action_type':'target_enumeration','candidate':'api.example.com'}, headers=h).json()['decision'],'deny')
            self.assertEqual(c.post(f'/api/runs/{rid}/approvals/{aid}/revoke', json={'expected_revision':revoked.json()['approvals']['approval_revision'],'actor':'authorized-operator','reason':'again'}, headers=h).status_code,409)

    def test_static_approval_controls_and_capabilities(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.client(td, token='fixture')
            caps=c.get('/api/session').json()['capabilities']
            self.assertTrue(caps['approval_mutation']); self.assertTrue(caps['action_check'])
            html=c.get('/').text; js=c.get('/static/app.js').text; combined=html+js+c.get('/static/app.css').text
            for term in ['action-check-form','approval-grant-form','approval-revoke-form','approval_revision','expected_state','intrusive-validation-warning','Exact normalized candidate']:
                self.assertIn(term, combined)
            for term in ['innerHTML','eval(','localStorage','sessionStorage','evidence-upload','approval-renewal','Run recon','Call MCP']:
                self.assertNotIn(term, combined)


    def test_cli_validation_and_missing_dependency_guidance(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); file=root/'file'; file.write_text('x'); link=root/'link'; link.symlink_to(root, target_is_directory=True)
            self.assertEqual(cli._valid_web_port('8765'),8765)
            for bad in ['1','65536','abc']:
                with self.assertRaises(Exception): cli._valid_web_port(bad)
            for host in ['127.0.0.1','localhost','::1']:
                args=type('A',(),{'host':host,'port':8765,'runs_root':str(root)})()
                self.assertEqual(cli._validate_web_args(args), root)
            for host in ['0.0.0.0','::','192.168.1.1','example.com']:
                args=type('A',(),{'host':host,'port':8765,'runs_root':str(root)})()
                with self.assertRaises(ValueError): cli._validate_web_args(args)
            for rr in [str(file), str(root/'missing'), str(link)]:
                args=type('A',(),{'host':'127.0.0.1','port':8765,'runs_root':rr})()
                with self.assertRaises(ValueError): cli._validate_web_args(args)
            p=cli.build_parser(); ns=p.parse_args(['web','serve',str(root)]); self.assertEqual(ns.host,'127.0.0.1'); self.assertEqual(ns.port,8765)
            out=StringIO()
            with patch.dict(sys.modules, {'uvicorn': None}), patch.object(sys,'argv',['outrider','web','serve',str(root)]), redirect_stdout(out):
                status=cli.main()
            self.assertEqual(status,2); self.assertIn('pip install -e ".[web]"', out.getvalue()); self.assertNotIn('Traceback', out.getvalue())
            with patch.object(sys,'argv',['outrider','--help']), redirect_stdout(StringIO()):
                with self.assertRaises(SystemExit) as help_exit:
                    cli.main()
            self.assertEqual(help_exit.exception.code, 0)

    def test_evidence_artifact_registration_and_verification_api(self):
        with tempfile.TemporaryDirectory() as td:
            runs_root=Path(td)/'runs'; runs_root.mkdir(); c=self.client(runs_root, token='fixture'); h={'X-Outrider-Control-Token':'fixture'}
            create=c.post('/api/runs', json={'target':'example.com','actor':'authorized-operator','authorization_reference':'EXAMPLE-ROE-001','in_scope':['example.com'],'out_of_scope':[], 'confirmed': True}, headers=h)
            rid=create.json()['run']['run_id']
            c.post(f'/api/runs/{rid}/state/transition', json={'expected_state':'initialized','new_state':'scoped','actor':'authorized-operator','reason':None}, headers=h)
            c.post(f'/api/runs/{rid}/state/transition', json={'expected_state':'scoped','new_state':'collecting','actor':'authorized-operator','reason':None}, headers=h)
            run=web_view._run_dir_for_id(runs_root,rid); art=run/'artifacts'/'obs.txt'; art.write_text('secret-fixture-content', encoding='utf-8')
            inv=c.get(f'/api/runs/{rid}/evidence/artifacts'); self.assertEqual(inv.status_code,200); self.assertIn('artifacts/obs.txt', inv.text); self.assertNotIn('secret-fixture-content', inv.text)
            view=c.get(f'/api/runs/{rid}/evidence').json(); rev=view['evidence_revision']; self.assertTrue(view['registration_enabled'])
            self.assertEqual(c.post(f'/api/runs/{rid}/evidence', json={}).status_code,403)
            before_art=art.read_bytes(); before_state=(run/'run.jsonl').read_text()
            ok=c.post(f'/api/runs/{rid}/evidence', json={'expected_revision':rev,'expected_state':'collecting','relative_artifact_path':'artifacts/obs.txt','actor':'authorized-operator','artifact_type':'text','media_type':'text/plain','source':None,'note':'note'}, headers=h)
            self.assertEqual(ok.status_code,201,ok.text); self.assertEqual(ok.headers['location'], f'/api/runs/{rid}/evidence')
            eid=ok.json()['evidence']['evidence_id']; self.assertEqual(art.read_bytes(), before_art); self.assertEqual((run/'run.jsonl').read_text(), before_state)
            newrev=ok.json()['evidence_view']['evidence_revision']; self.assertNotEqual(newrev, rev)
            v=c.post(f'/api/runs/{rid}/evidence/verify', json={'evidence_id':eid}, headers=h); self.assertEqual(v.status_code,200); self.assertEqual(v.json()['results'][0]['status'],'verified')
            art.write_text('changed', encoding='utf-8')
            v2=c.post(f'/api/runs/{rid}/evidence/verify', json={'evidence_id':None}, headers=h); self.assertEqual(v2.status_code,200); self.assertEqual(v2.json()['results'][0]['status'],'mismatch'); self.assertEqual(v2.json()['evidence_revision'], newrev)
            self.assertEqual(c.get(f'/api/runs/{rid}/artifacts/obs.txt').status_code,404); self.assertEqual(c.get('/api/artifacts/download').status_code,404)

    def test_evidence_registration_rejections_and_static_controls(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); rid=load_manifest(run).run_id; c=self.client(td, token='fixture'); h={'X-Outrider-Control-Token':'fixture'}
            art=run/'artifacts'/'obs.txt'; art.write_text('abc')
            view=c.get(f'/api/runs/{rid}/evidence').json(); rev=view['evidence_revision']; before=(run/'evidence.jsonl').read_bytes(); art_before=art.read_bytes()
            base={'expected_revision':rev,'expected_state':'initialized','relative_artifact_path':'artifacts/obs.txt','actor':'authorized-operator','artifact_type':'text'}
            for payload in ['{', [], {**base,'extra':'x'}, {**base,'relative_artifact_path':'/tmp/x'}, {**base,'relative_artifact_path':'../x'}, {**base,'relative_artifact_path':'manifest.json'}, {**base,'artifact_type':'Bad'}, {**base,'note':' '}]:
                if payload=='{': resp=c.post(f'/api/runs/{rid}/evidence', data='{', headers={**h,'Content-Type':'application/json'})
                else: resp=c.post(f'/api/runs/{rid}/evidence', json=payload, headers=h)
                self.assertEqual(resp.status_code,422, resp.text); self.assertEqual((run/'evidence.jsonl').read_bytes(), before); self.assertEqual(art.read_bytes(), art_before)
            self.assertEqual(c.post(f'/api/runs/{rid}/evidence', json={**base,'expected_revision':'0'*64}, headers=h).status_code,409)
            ok=c.post(f'/api/runs/{rid}/evidence', json=base, headers=h); self.assertEqual(ok.status_code,201)
            self.assertEqual(c.post(f'/api/runs/{rid}/evidence', json={**base,'expected_revision':ok.json()['evidence_view']['evidence_revision']}, headers=h).status_code,409)
            self.assertEqual(c.post(f'/api/runs/{rid}/evidence/verify', json={'evidence_id':'not'}, headers=h).status_code,422)
            self.assertEqual(c.post(f'/api/runs/{rid}/evidence/verify', json={'evidence_id':'00000000-0000-4000-8000-000000000000'}, headers=h).status_code,404)
            combined=c.get('/').text+c.get('/static/app.js').text+c.get('/static/app.css').text
            for term in ['artifact-inventory-area','refresh-inventory','evidence-registration-form','verify-all-evidence','verify-evidence-record','evidence_revision','expected_state','X-Outrider-Control-Token','evidence-registration-confirm']:
                self.assertIn(term, combined)
            for term in ['type="file"','download=','download-link','preview-control','innerHTML','eval(','localStorage','sessionStorage']:
                self.assertNotIn(term, combined)

if __name__=='__main__': unittest.main()

@unittest.skipIf(TestClient is None, "FastAPI web extra is not installed")
class ContractEndpointTests(unittest.TestCase):
    def client(self, root, token='tok'): return TestClient(create_app(root, control_token=token))
    def test_contract_request_create_and_validate_smoke(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); rid=load_manifest(run).run_id; transition_state(run,'scoped','authorized-operator')
            c=self.client(td,'tok'); h={'X-Outrider-Control-Token':'tok'}
            view=c.get(f'/api/runs/{rid}/contracts').json(); rev=view['contract_revision']
            self.assertIn('request_action_types', view); self.assertIn('known_skills', view)
            self.assertEqual(c.post(f'/api/runs/{rid}/contracts/requests', json={}, headers={}).status_code,403)
            body={'expected_revision':rev,'expected_state':'scoped','skill':'recon-asset-discovery','actor':'authorized-operator','objective':'Public lookup','action_type':'public_source_lookup','candidate':'EXAMPLE.COM','input_evidence_ids':[],'max_items':100,'notes':None}
            ok=c.post(f'/api/runs/{rid}/contracts/requests', json=body, headers=h)
            self.assertEqual(ok.status_code,201,ok.text); req=ok.json()['request']; self.assertEqual(req['candidate'],'example.com')
            self.assertNotEqual(ok.json()['contracts']['contract_revision'], rev)
            val=c.post(f'/api/runs/{rid}/contracts/requests/{req["request_id"]}/validate', json={'expected_revision':ok.json()['contracts']['contract_revision']}, headers=h)
            self.assertEqual(val.status_code,200,val.text); self.assertEqual(val.json()['validation_report']['overall_status'],'valid')
            self.assertIn(c.post(f'/api/runs/{rid}/contracts/results', json={}, headers=h).status_code, (404,405))

@unittest.skipIf(TestClient is None, "web extra not installed")
class OnboardingApiTests(unittest.TestCase):
    def test_onboarding_empty_and_existing_run_projection(self):
        with tempfile.TemporaryDirectory() as td:
            client = TestClient(create_app(td, control_token='tok'))
            r = client.get('/api/onboarding')
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers.get('cache-control'), 'no-store')
            body = r.json()
            self.assertTrue(body['first_run'])
            self.assertFalse(body['enrichment_enabled'])
            self.assertIn('HackerOne', body['platform_options'])
            self.assertNotIn('tok', json.dumps(body))
            create = client.post('/api/runs', headers={'X-Outrider-Control-Token':'tok'}, json={'target':'example.com','actor':'operator','authorization_reference':'secret auth','engagement_platform':'HackerOne','traffic_header':{'name':'X-Bug-Bounty','value':'secret traffic'},'in_scope':['example.com'],'out_of_scope':[],'confirmed':True})
            self.assertEqual(create.status_code, 201, create.text)
            body = client.get('/api/onboarding').json()
            self.assertFalse(body['first_run'])
            inv = client.get('/api/runs').json()
            self.assertNotIn('secret auth', json.dumps(inv))
            self.assertNotIn('secret traffic', json.dumps(inv))
            self.assertEqual(inv['runs'][0]['next_action'], 'Review Scope')

    def test_creation_requires_exact_confirmation_and_rejects_unknowns(self):
        with tempfile.TemporaryDirectory() as td:
            client = TestClient(create_app(td, control_token='tok'))
            payload={'target':'example.com','actor':'operator','authorization_reference':'auth','engagement_platform':'HackerOne','in_scope':['example.com'],'out_of_scope':[],'confirmed':'true'}
            self.assertEqual(client.post('/api/runs', headers={'X-Outrider-Control-Token':'tok'}, json=payload).status_code, 422)
            payload['confirmed']=True; payload['run_id']='caller'
            self.assertEqual(client.post('/api/runs', headers={'X-Outrider-Control-Token':'tok'}, json=payload).status_code, 422)
            payload.pop('run_id'); payload['engagement_platform']='Unsupported'
            self.assertEqual(client.post('/api/runs', headers={'X-Outrider-Control-Token':'tok'}, json=payload).status_code, 422)


@unittest.skipIf(TestClient is None, "FastAPI web extra is not installed")
class WebAppBridgeTests(unittest.TestCase):
    H = {'X-Outrider-Control-Token': 'fixture'}

    def _env(self, td):
        td = Path(td)
        runs = td / 'runs'; runs.mkdir()
        targets = td / 'targets'; (targets / 'legacy-one' / 'sub').mkdir(parents=True)
        (targets / 'legacy-one' / 'memory.md').write_text('# notes\napi.example.com\n', encoding='utf-8')
        (targets / 'legacy-one' / 'sub' / 'recon.txt').write_text('recon', encoding='utf-8')
        client = TestClient(create_app(runs, control_token='fixture', targets_root=targets))
        return runs, targets, client

    def test_capabilities_and_source_listing(self):
        with tempfile.TemporaryDirectory() as td:
            runs, targets, c = self._env(td)
            caps = c.get('/api/health').json()['capabilities']
            self.assertTrue(caps['legacy_import'] and caps['materialize'])
            src = c.get('/api/import/sources').json()
            self.assertEqual(src['sources'], ['legacy-one'])
            self.assertEqual(src['base'], str(targets))

    def test_import_creates_run_and_registers_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            runs, targets, c = self._env(td)
            body = {'source': 'legacy-one', 'target': 'example.com', 'actor': 'op', 'authorization_reference': 'ROE', 'in_scope': ['example.com', '*.example.com'], 'out_of_scope': [], 'confirmed': True}
            r = c.post('/api/import-target', headers=self.H, json=body)
            self.assertEqual(r.status_code, 201, r.text)
            self.assertEqual(r.json()['imported']['registered'], 2)
            rid = r.json()['run']['run_id']
            ev = web_view.evidence_view(runs / 'example.com')
            paths = {rec['relative_artifact_path'] for rec in ev['records']}
            self.assertEqual(ev['evidence_count'], 2)
            self.assertIn('artifacts/imported/memory.md', paths)
            self.assertIn('artifacts/imported/sub/recon.txt', paths)
            self.assertTrue(rid)

    def test_import_guards_and_rejections(self):
        with tempfile.TemporaryDirectory() as td:
            runs, targets, c = self._env(td)
            good = {'source': 'legacy-one', 'target': 'example.com', 'actor': 'op', 'authorization_reference': 'ROE', 'in_scope': ['example.com'], 'out_of_scope': [], 'confirmed': True}
            # no token
            self.assertEqual(c.post('/api/import-target', json=good).status_code, 403)
            # traversal / absolute / unknown source
            for bad_source in ['../etc', '/etc', 'nope', 'legacy-one/../..']:
                b = dict(good, source=bad_source)
                self.assertEqual(c.post('/api/import-target', headers=self.H, json=b).status_code, 422, bad_source)
            # confirmation required
            self.assertEqual(c.post('/api/import-target', headers=self.H, json=dict(good, confirmed=False)).status_code, 422)
            # unknown field
            self.assertEqual(c.post('/api/import-target', headers=self.H, json=dict(good, bogus=1)).status_code, 422)

    def test_materialize_endpoint(self):
        with tempfile.TemporaryDirectory() as td:
            runs, targets, c = self._env(td)
            rid = c.post('/api/import-target', headers=self.H, json={'source': 'legacy-one', 'target': 'example.com', 'actor': 'op', 'authorization_reference': 'ROE', 'in_scope': ['example.com'], 'out_of_scope': [], 'confirmed': True}).json()['run']['run_id']
            # guard
            self.assertEqual(c.post(f'/api/runs/{rid}/materialize', json={}).status_code, 403)
            # happy path
            m = c.post(f'/api/runs/{rid}/materialize', headers=self.H, json={})
            self.assertEqual(m.status_code, 200, m.text)
            out = Path(m.json()['path'])
            self.assertTrue(out.is_file())
            self.assertEqual(out, targets / 'example.com' / 'OUTRIDER-RUN.md')
            self.assertIn('Outrider engagement: example.com', out.read_text(encoding='utf-8'))
            # unknown run -> 404
            self.assertEqual(c.post('/api/runs/00000000-0000-4000-8000-000000000000/materialize', headers=self.H, json={}).status_code, 404)
            # bad run_id -> 422
            self.assertEqual(c.post('/api/runs/not-a-uuid/materialize', headers=self.H, json={}).status_code, 422)
            # non-generated clobber -> 409, then force -> 200
            out.write_text('hand-written, no banner', encoding='utf-8')
            self.assertEqual(c.post(f'/api/runs/{rid}/materialize', headers=self.H, json={}).status_code, 409)
            self.assertEqual(c.post(f'/api/runs/{rid}/materialize', headers=self.H, json={'force': True}).status_code, 200)
