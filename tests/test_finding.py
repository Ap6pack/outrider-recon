from __future__ import annotations
import hashlib, json, tempfile, unittest
from pathlib import Path
from uuid import UUID, uuid4

from outrider.cli import init_run
from outrider.evidence import register_evidence
from outrider.finding import *
from outrider.skill_contract import create_skill_request, utc_now, validate_skill_result
from outrider.state import load_manifest, load_state, transition_state

class Args: pass

def make_run(td, scope=None):
    a=Args(); a.target='example.com'; a.output_dir=str(td); a.scope=scope or ['example.com','*.example.com']; a.exclude=[]; a.actor='authorized-operator'; a.authorization_reference='EXAMPLE-ROE-001'; init_run(a)
    return Path(td)/'example.com'

def ready_run(td):
    run=make_run(td); transition_state(run,'scoped','authorized-operator'); transition_state(run,'collecting','authorized-operator'); transition_state(run,'analyzing','authorized-operator'); return run

def make_source(run, classification='finding_candidate', status='completed', candidate='api.example.com'):
    req,path,_=create_skill_request(run,'recon-asset-discovery','authorized-operator','review','public_source_lookup','example.com')
    art=run/'artifacts'/f'evidence-{uuid4()}.txt'; art.write_text('OpenAPI schema at api.example.com', encoding='utf-8')
    ev=register_evidence(run,art.relative_to(run).as_posix(),'authorized-operator','text')
    claim_id=str(uuid4())
    result={"schema_version":1,"contract_type":"skill_result","result_id":str(uuid4()),"request_id":req.request_id,"run_id":req.run_id,"skill":req.skill,"completed_at":utc_now(),"status":status,"summary":"candidate","claims":[{"claim_id":claim_id,"classification":classification,"subject":candidate+"/openapi.json","statement":"The endpoint returns an OpenAPI schema without authentication.","confidence":"high","suggested_severity":"medium","evidence_ids":[ev.evidence_id]}],"discovered_candidates":[],"recommended_actions":[],"errors":[] if status in {'completed','partial'} else [{"code":"blocked","message":"blocked"}]}
    rp=run/'contracts/results'/f'{result["result_id"]}.json'; rp.write_text(json.dumps(result, sort_keys=True), encoding='utf-8')
    return req, rp, claim_id, ev, result

def promote(run, rp, claim_id, **kw):
    args=dict(actor='authorized-operator',title='Public OpenAPI schema exposes internal API structure',candidate='api.example.com',severity='medium',confidence='high',validation_basis='response_evidence',validation_reason='The registered response contains a valid OpenAPI schema.',impact='The schema exposes undocumented API routes and object structures.',remediation='Restrict schema access and remove unnecessary production documentation.',location='/openapi.json')
    args.update(kw)
    return promote_finding(run, rp, claim_id, **args)

class FindingTests(unittest.TestCase):
    def test_init_creates_empty_findings_and_rerun_preserves_files(self):
        with tempfile.TemporaryDirectory() as td:
            run=make_run(td); manifest=load_manifest(run).run_id
            self.assertTrue((run/'findings.jsonl').exists()); self.assertEqual((run/'findings.jsonl').read_text(),'')
            (run/'findings.jsonl').write_text('{"keep":true}\n')
            before={rel:(run/rel).read_text() for rel in ['run.jsonl','evidence.jsonl','approvals.jsonl','findings.md']}
            make_run(td)
            self.assertEqual(load_manifest(run).run_id, manifest)
            self.assertEqual((run/'findings.jsonl').read_text(),'{"keep":true}\n')
            for rel,text in before.items(): self.assertEqual((run/rel).read_text(), text)
            (run/'findings.jsonl').unlink(); make_run(td)
            self.assertTrue((run/'findings.jsonl').exists()); self.assertEqual(load_state(run).event_count,1)

    def test_promote_success_duplicate_and_verify_changes(self):
        with tempfile.TemporaryDirectory() as td:
            run=ready_run(td); req,rp,cid,ev,result=make_source(run)
            before={rel:(run/rel).read_bytes() for rel in ['manifest.json','scope.yaml','run.jsonl','evidence.jsonl','approvals.jsonl','findings.md',f'contracts/requests/{req.request_id}.json',f'contracts/results/{result["result_id"]}.json',ev.path]}
            rec=promote(run,rp,cid)
            self.assertEqual(rec.classification,'validated_finding')
            self.assertEqual(rec.source.claim.classification,'finding_candidate')
            self.assertEqual(rec.source.result_sha256, hashlib.sha256(rp.read_bytes()).hexdigest())
            self.assertEqual(rec.source.result_path, f'contracts/results/{result["result_id"]}.json')
            self.assertEqual(rec.evidence_ids,[ev.evidence_id])
            self.assertEqual(load_finding_registry(run).finding_count,1)
            for rel,data in before.items(): self.assertEqual((run/rel).read_bytes(), data, rel)
            with self.assertRaises(FindingPromotionRefusal): promote(run,rp,cid,title='Changed')
            self.assertEqual(load_finding_registry(run).finding_count,1)
            ver=verify_all_findings(run)[0]; self.assertEqual(ver.overall_status,'verified'); self.assertEqual(ver.current_scope_status,'currently_in_scope')
            rp.write_text(json.dumps({**result,'summary':'changed'}, sort_keys=True)); self.assertEqual(verify_all_findings(run)[0].overall_status,'source_changed')
            rp.write_text(json.dumps(result, sort_keys=True)); (run/ev.path).write_text('changed')
            self.assertEqual(verify_all_findings(run)[0].overall_status,'evidence_mismatch')
            (run/ev.path).write_text('OpenAPI schema at api.example.com')
            self.assertEqual(verify_all_findings(run)[0].overall_status,'verified')
            (run/'scope.yaml').write_text((run/'scope.yaml').read_text().replace('out_of_scope: []','out_of_scope:\n  - "api.example.com"'))
            self.assertEqual(verify_all_findings(run)[0].current_scope_status,'currently_out_of_scope')
            self.assertEqual(load_finding_registry(run).finding_count,1)

    def test_refusals_and_validation_errors_append_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            run=ready_run(td); req,rp,cid,ev,result=make_source(run)
            with self.assertRaises(FindingPromotionRefusal): promote(run,rp,cid,candidate='outside.example')
            with self.assertRaises(FindingPromotionRefusal): promote(run,rp,cid,confidence='low')
            bad_req,bad_rp,bad_cid,_,_=make_source(run,'observation')
            with self.assertRaises(FindingPromotionRefusal): promote(run,bad_rp,bad_cid)
            blocked_req,blocked_rp,blocked_cid,_,_=make_source(run,'finding_candidate','blocked')
            self.assertEqual(validate_skill_result(run, blocked_rp).overall_status, 'valid')
            with self.assertRaises(FindingPromotionRefusal): promote(run,blocked_rp,blocked_cid)
            bad=dict(result); bad['claims'][0]['classification']='validated_finding'; rp.write_text(json.dumps(bad))
            with self.assertRaises(FindingValidationError): promote(run,rp,cid)
            with self.assertRaises(FindingValidationError): promote(run,'/etc/passwd',cid)
            self.assertEqual(load_finding_registry(run).finding_count,0)

    def test_registry_validation_and_schema_constants(self):
        with tempfile.TemporaryDirectory() as td:
            run=ready_run(td); _,rp,cid,ev,_=make_source(run); rec=promote(run,rp,cid)
            data=rec.to_dict(); path=run/'findings.jsonl'
            self.assertEqual(UUID(data['event_id']).version,4); self.assertEqual(UUID(data['finding_id']).version,4)
            variants=[('sequence',2),('event_type','bad'),('classification','finding_candidate'),('severity','bad'),('confidence','low'),('validation_basis','bad')]
            for key,val in variants:
                bad=dict(data); bad[key]=val; path.write_text(json.dumps(bad)+'\n')
                with self.assertRaises(FindingValidationError): load_finding_registry(run)
            bad=dict(data); bad['extra']=1; path.write_text(json.dumps(bad)+'\n')
            with self.assertRaises(FindingValidationError): load_finding_registry(run)
            path.write_text(json.dumps(data)+'\n\n')
            with self.assertRaises(FindingValidationError): load_finding_registry(run)
            path.write_text('[]\n')
            with self.assertRaises(FindingValidationError): load_finding_registry(run)
            schema=json.loads((Path(__file__).resolve().parents[1]/'contracts/finding-v1.schema.json').read_text())
            self.assertEqual(set(schema['properties']['severity']['enum']), set(SEVERITIES))
            self.assertEqual(set(schema['properties']['confidence']['enum']), set(PROMOTED_CONFIDENCES))
            self.assertEqual(set(schema['properties']['validation_basis']['enum']), set(VALIDATION_BASES))
            self.assertEqual(schema['properties']['classification']['const'], CLASSIFICATION)
            self.assertEqual(schema['properties']['event_type']['const'], EVENT_TYPE)
            self.assertFalse(schema['additionalProperties'])
            self.assertFalse(schema['properties']['source']['additionalProperties'])
            self.assertFalse(schema['properties']['source']['properties']['claim']['additionalProperties'])

if __name__=='__main__': unittest.main()
