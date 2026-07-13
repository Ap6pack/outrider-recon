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
    def client(self, root): return TestClient(create_app(root))

    def test_health_runs_details_headers_and_static_ui(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.client(td)
            r=c.get('/api/health'); self.assertEqual(r.status_code,200); self.assertEqual(r.json()['mode'],'read-only')
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
            self.assertIn('Run dashboard', html); self.assertIn('Read-only', html); self.assertIn('viewport', html)
            for term in ['Overview','Scope','State','Evidence','Approvals','Contracts','Findings','Integrity']:
                self.assertIn(term, html)
            bad_terms=['http://','https://','cdn','analytics','fonts.googleapis','eval(','innerHTML']
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
            for method in ['post','put','patch','delete']:
                self.assertEqual(getattr(c,method)('/api/runs').status_code,405)
                self.assertEqual(getattr(c,method)(f'/api/runs/{rid}/overview').status_code,405)
            self.assertEqual(c.get('/docs').status_code,404); self.assertEqual(c.get('/openapi.json').status_code,404)
            self.assertEqual(c.get('/artifacts/obs.txt').status_code,404)
            self.assertEqual(c.get('/api/files/manifest.json').status_code,404)
            for path in ['/','/api/runs',f'/api/runs/{rid}/integrity']:
                c.get(path)
            after={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
            self.assertEqual(before, after)

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
