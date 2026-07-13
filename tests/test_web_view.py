from __future__ import annotations
import json, tempfile, unittest
from pathlib import Path
from uuid import uuid4
from unittest.mock import patch

from outrider.cli import init_run
from outrider.state import load_manifest, transition_state
from outrider.evidence import register_evidence
from outrider.approval import grant_approval
from outrider.skill_contract import create_skill_request, utc_now
from outrider.finding import promote_finding
from outrider import web_view

class Args: pass

def make_run(root, name='example.com'):
    a=Args(); a.target=name; a.output_dir=str(root); a.scope=['example.com','*.example.com']; a.exclude=[]; a.actor='authorized-operator'; a.authorization_reference='EXAMPLE-ROE-001'; init_run(a)
    return Path(root)/name

def populate(run):
    transition_state(run,'scoped','authorized-operator')
    transition_state(run,'collecting','authorized-operator')
    transition_state(run,'analyzing','authorized-operator')
    art=run/'artifacts'/'obs.txt'; art.write_text('api.example.com evidence', encoding='utf-8')
    ev=register_evidence(run,'artifacts/obs.txt','authorized-operator','text','text/plain','local','note')
    grant_approval(run,'target_enumeration','api.example.com','authorized-operator','approved',duration_minutes=30)
    req,path,_=create_skill_request(run,'recon-asset-discovery','authorized-operator','review','public_source_lookup','example.com',[ev.evidence_id])
    claim_id=str(uuid4())
    result={"schema_version":1,"contract_type":"skill_result","result_id":str(uuid4()),"request_id":req.request_id,"run_id":req.run_id,"skill":req.skill,"completed_at":utc_now(),"status":"completed","summary":"found candidate","claims":[{"claim_id":claim_id,"classification":"finding_candidate","subject":"api.example.com","statement":"schema exposed","confidence":"high","suggested_severity":"medium","evidence_ids":[ev.evidence_id]}],"discovered_candidates":[{"candidate":"api.example.com","relationship":"domain","source_evidence_ids":[ev.evidence_id]}],"recommended_actions":[],"errors":[]}
    rp=run/'contracts'/'results'/f'{result["result_id"]}.json'; rp.write_text(json.dumps(result, sort_keys=True), encoding='utf-8')
    promote_finding(run,rp,claim_id,actor='authorized-operator',title='Public schema',candidate='api.example.com',severity='medium',confidence='high',validation_basis='response_evidence',validation_reason='reviewed',impact='info leak',remediation='restrict',location='/openapi.json')
    return ev, rp

def serial(data):
    return json.dumps(data, sort_keys=True)

class WebViewTests(unittest.TestCase):
    def test_empty_valid_and_multiple_run_discovery(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(web_view.list_runs(td)['total'],0)
            run=make_run(td); populate(run)
            make_run(td,'example.com-two')
            data=web_view.list_runs(td)
            self.assertEqual(data['total'],2)
            self.assertTrue(all('authorization_reference' not in serial(i) for i in data['runs']))
            self.assertNotIn(td, serial(data))

    def test_immediate_child_symlink_malformed_duplicate_and_reread(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); run=make_run(root); rid=load_manifest(run).run_id
            nested=root/'nested'; nested.mkdir(); make_run(nested)
            bad=root/'bad'; bad.mkdir(); (bad/'manifest.json').write_text('{')
            if hasattr(Path, 'symlink_to'):
                link=root/'link'; link.symlink_to(run, target_is_directory=True)
            dup=root/'dup'; dup.mkdir(); (dup/'manifest.json').write_text((run/'manifest.json').read_text()); (dup/'scope.yaml').write_text((run/'scope.yaml').read_text()); (dup/'run.jsonl').write_text((run/'run.jsonl').read_text())
            data=web_view.list_runs(root)
            self.assertTrue(any(i['health']=='error' for i in data['runs']))
            self.assertTrue(any(i.get('summary')=='duplicate run_id detected; no run selected' for i in data['runs']))
            self.assertNotIn(str(nested), serial(data))
            for p in [root/'dup']:
                for child in p.rglob('*'):
                    if child.is_file(): child.unlink()
                p.rmdir()
            self.assertIsNotNone(web_view.view_for_run_id(root,rid,'overview'))
            transition_state(run,'scoped','authorized-operator')
            self.assertEqual(web_view.view_for_run_id(root,rid,'state')['current_state'],'scoped')

    def test_all_views_no_absolute_paths_and_integrity_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); ev,_=populate(run); rid=load_manifest(run).run_id
            for view in ['overview','scope','state','evidence','approvals','contracts','findings','integrity']:
                data=web_view.view_for_run_id(td,rid,view)
                self.assertIsInstance(data, dict)
                text=serial(data)
                self.assertNotIn(td, text)
                self.assertNotIn('EXAMPLE-ROE-001', text)
                self.assertNotIn('api.example.com evidence', text)
            self.assertEqual(web_view.view_for_run_id(td,rid,'evidence')['records'][0]['verification_status'],'verified')
            (run/ev.path).write_text('changed', encoding='utf-8')
            self.assertNotEqual(web_view.view_for_run_id(td,rid,'integrity')['evidence_verification_counts']['mismatch'],0)

    def test_symlink_root_rejected_and_no_write_functions_or_network(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); runs=root/'runs'; runs.mkdir(); link=root/'runs-link'; link.symlink_to(runs, target_is_directory=True)
            with self.assertRaises(ValueError): web_view.list_runs(link)
            run=make_run(runs); rid=load_manifest(run).run_id
            before={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
            with patch('outrider.state.transition_state', side_effect=AssertionError), patch('outrider.approval.grant_approval', side_effect=AssertionError), patch('outrider.evidence.register_evidence', side_effect=AssertionError), patch('outrider.finding.promote_finding', side_effect=AssertionError):
                web_view.list_runs(runs); web_view.view_for_run_id(runs,rid,'integrity')
            after={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
            self.assertEqual(before, after)

if __name__=='__main__': unittest.main()
