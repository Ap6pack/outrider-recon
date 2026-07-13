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
from outrider import cli
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
            create = c.post('/api/runs', json={'target':'https://example.com/path','actor':'authorized-operator','authorization_reference':'EXAMPLE-ROE-001','in_scope':['example.com','*.example.com'],'out_of_scope':[]}, headers=h)
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

if __name__=='__main__': unittest.main()
