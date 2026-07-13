from __future__ import annotations
import json, subprocess, sys, tempfile, unittest
from pathlib import Path
from uuid import UUID, uuid4

from outrider.cli import init_run
from outrider.skill_contract import *
from outrider.state import transition_state, load_manifest
from outrider.evidence import register_evidence
from outrider.approval import grant_approval

ROOT=Path(__file__).resolve().parents[1]

class Args: pass

def make_run(td):
    a=Args(); a.target='example.com'; a.output_dir=str(td); a.scope=['example.com']; a.exclude=[]; a.actor='authorized-operator'; a.authorization_reference='EXAMPLE-ROE-001'; init_run(a)
    return Path(td)/'example.com'

class SkillContractTests(unittest.TestCase):
    def test_catalog_matches_skill_dirs(self):
        expected=tuple(sorted(p.parent.name for p in (ROOT/'skills').glob('*/SKILL.md')))
        self.assertEqual(list_known_skills(ROOT), expected)
        self.assertEqual(len(expected), 11)
        self.assertNotIn('_shared', expected)
        self.assertTrue(all(LOWER_TOKEN.fullmatch(x) for x in expected))

    def test_init_contract_dirs_and_rerun_preserves(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td)
            for rel in ['contracts','contracts/requests','contracts/results']:
                self.assertTrue((run/rel).is_dir())
            (run/'contracts/requests/keep.json').write_text('{}')
            before=(run/'run.jsonl').read_text(),(run/'evidence.jsonl').read_text(),(run/'approvals.jsonl').read_text()
            make_run(td)
            self.assertTrue((run/'contracts/requests/keep.json').exists())
            self.assertEqual(before, ((run/'run.jsonl').read_text(),(run/'evidence.jsonl').read_text(),(run/'approvals.jsonl').read_text()))

    def test_request_create_validate_policy(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td)
            with self.assertRaises(SkillContractValidationError):
                create_skill_request(run,'recon-asset-discovery','authorized-operator','obj','public_source_lookup','example.com')
            transition_state(run,'scoped','authorized-operator')
            req,path,rep=create_skill_request(run,'recon-asset-discovery','authorized-operator','obj','public_source_lookup','HTTP://Example.COM/')
            self.assertEqual(req.requested_action['candidate'],'example.com')
            self.assertEqual(rep.overall_status,'valid')
            self.assertEqual(validate_skill_request(run,path).overall_status,'valid')
            self.assertEqual(UUID(req.request_id).version,4)
            self.assertEqual(req.run_id,load_manifest(run).run_id)
            self.assertIn('contracts/requests', str(path))
            with self.assertRaises(SkillContractValidationError):
                create_skill_request(run,'unknown','authorized-operator','obj','local_analysis')
            with self.assertRaises(SkillContractValidationError):
                create_skill_request(run,'recon-asset-discovery','authorized-operator','obj','intrusive_validation','example.com')
            with self.assertRaises(SkillContractValidationError):
                create_skill_request(run,'recon-asset-discovery','authorized-operator','obj','target_enumeration','example.com')
            grant_approval(run,'target_enumeration','example.com','authorized-operator','ok',duration_minutes=5)
            self.assertEqual(create_skill_request(run,'recon-asset-discovery','authorized-operator','obj','target_enumeration','example.com')[2].overall_status,'valid')

    def test_request_validation_rejects_bad_json_fields_and_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); transition_state(run,'scoped','authorized-operator')
            req,path,_=create_skill_request(run,'recon-asset-discovery','authorized-operator','obj','public_source_lookup','example.com')
            bad=run/'contracts/requests/bad.json'; bad.write_text('{')
            self.assertFalse(validate_skill_request(run,bad).structural_valid)
            data=req.to_dict(); data['extra']=1; bad.write_text(json.dumps(data))
            self.assertFalse(validate_skill_request(run,bad).structural_valid)
            data=req.to_dict(); data['input_evidence_ids']=[str(uuid4())]; bad.write_text(json.dumps(data))
            self.assertEqual(validate_skill_request(run,bad).overall_status,'error')

    def test_result_validation_and_recommendation_assessments(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); transition_state(run,'scoped','authorized-operator')
            req,path,_=create_skill_request(run,'recon-asset-discovery','authorized-operator','obj','public_source_lookup','example.com')
            art=run/'artifacts/out.txt'; art.write_text('ct api.example.com')
            ev=register_evidence(run,'artifacts/out.txt','authorized-operator','text')
            result={"schema_version":1,"contract_type":"skill_result","result_id":str(uuid4()),"request_id":req.request_id,"run_id":req.run_id,"skill":req.skill,"completed_at":utc_now(),"status":"completed","summary":"one obs","claims":[{"claim_id":str(uuid4()),"classification":"observation","subject":"api.example.com","statement":"seen","confidence":"high","suggested_severity":None,"evidence_ids":[ev.evidence_id]}],"discovered_candidates":[{"candidate":"outside.example","relationship":"domain","source_evidence_ids":[ev.evidence_id]}],"recommended_actions":[{"action_type":"target_enumeration","candidate":"api.example.com","priority":"medium","reason":"confirm"}],"errors":[]}
            rp=run/'contracts/results/res.json'; rp.write_text(json.dumps(result))
            rep=validate_skill_result(run,rp)
            self.assertEqual(rep.overall_status,'valid')
            self.assertEqual(rep.discovered_candidate_scope_assessments[0]['decision'],'deny')
            self.assertEqual(rep.recommended_action_policy_assessments[0]['decision'],'deny')
            result['claims'][0]['classification']='validated_finding'; rp.write_text(json.dumps(result))
            self.assertFalse(validate_skill_result(run,rp).structural_valid)

    def test_schemas_and_skill_docs(self):
        req=json.loads((ROOT/'contracts/skill-request-v1.schema.json').read_text())
        res=json.loads((ROOT/'contracts/skill-result-v1.schema.json').read_text())
        self.assertEqual(req['required'], REQUEST_REQUIRED)
        self.assertEqual(set(req['properties']['requested_action']['properties']['action_type']['enum']), set(REQUEST_ACTIONS))
        self.assertEqual(res['required'], RESULT_REQUIRED)
        self.assertEqual(set(res['properties']['status']['enum']), set(RESULT_STATUSES))
        self.assertEqual(set(res['properties']['claims']['items']['properties']['classification']['enum']), set(CLAIM_CLASSIFICATIONS))
        self.assertTrue(req['additionalProperties'] is False and res['additionalProperties'] is False)
        for p in (ROOT/'skills').glob('*/SKILL.md'):
            text=p.read_text()
            self.assertIn('## Structured Outrider run contract', text)
            self.assertIn('../_shared/run-contract.md', text)
            self.assertIn(f'`{p.parent.name}`', text)
            self.assertIn('evidence IDs', text)
            self.assertIn('do not expand scope', text)
        self.assertIn('Router role', (ROOT/'skills/offensive-osint/SKILL.md').read_text())

if __name__=='__main__': unittest.main()

class ContractInventoryRevisionTests(unittest.TestCase):
    def test_revision_inventory_lookup_and_catalog(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); empty=__import__('outrider.skill_contract',fromlist=['contract_revision']).contract_revision(run)
            self.assertEqual(empty, __import__('outrider.skill_contract',fromlist=['contract_revision']).contract_revision(run))
            transition_state(run,'scoped','authorized-operator')
            req,_,_=create_skill_request(run,'recon-asset-discovery','authorized-operator','obj','public_source_lookup','example.com')
            result={"schema_version":1,"contract_type":"skill_result","result_id":str(uuid4()),"request_id":req.request_id,"run_id":req.run_id,"skill":req.skill,"completed_at":utc_now(),"status":"completed","summary":"s","claims":[],"discovered_candidates":[{"candidate":"api.example.com","relationship":"domain","source_evidence_ids":[]}],"recommended_actions":[],"errors":[]}
            # use blocked result to avoid evidence fixture for inventory-only test
            result={"schema_version":1,"contract_type":"skill_result","result_id":str(uuid4()),"request_id":req.request_id,"run_id":req.run_id,"skill":req.skill,"completed_at":utc_now(),"status":"blocked","summary":"blocked","claims":[],"discovered_candidates":[],"recommended_actions":[],"errors":[{"message":"manual"}]}
            (run/'contracts/results/result.json').write_text(json.dumps(result))
            from outrider.skill_contract import contract_revision, list_contract_inventory, find_skill_request_by_id, request_action_catalog, REQUEST_ACTIONS
            changed=contract_revision(run); self.assertNotEqual(empty, changed)
            inv=list_contract_inventory(run); self.assertEqual(inv['request_count'],1); self.assertEqual(inv['result_count'],1); self.assertNotIn(str(Path(td)), json.dumps(inv))
            req_id=inv['requests'][0]['contract_id']; self.assertEqual(find_skill_request_by_id(run, req_id).status, 'found')
            catalog=request_action_catalog(); self.assertEqual({c['action_type'] for c in catalog}, set(REQUEST_ACTIONS)); self.assertNotIn('intrusive_validation',{c['action_type'] for c in catalog})
            self.assertEqual([c['action_type'] for c in catalog], sorted(c['action_type'] for c in catalog))
