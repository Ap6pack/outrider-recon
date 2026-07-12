import hashlib
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from outrider import cli
from outrider.evidence import EvidenceRefusalError, EvidenceValidationError, load_evidence_registry, register_evidence, verify_all_evidence
from outrider.state import load_manifest, load_state, transition_state

class EvidenceTests(unittest.TestCase):
    def run_cli(self,*argv):
        out=StringIO()
        with patch.object(sys,'argv',['outrider',*argv]), redirect_stdout(out):
            code=cli.main()
        return code,out.getvalue()
    def make_run(self,tmp):
        code,_=self.run_cli('init','example.com','--output-dir',tmp,'--actor','authorized-operator','--authorization-reference','EXAMPLE-ROE-001')
        self.assertEqual(code,0)
        return Path(tmp)/'example.com'
    def artifact(self,run,name='artifacts/http/homepage-response.txt',data=b'HTTP/1.1 200 OK\n'):
        p=run/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data); return p

    def test_init_evidence_files_and_rerun_preserves(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=self.make_run(tmp)
            self.assertEqual((run/'evidence.jsonl').read_text(),'')
            self.assertTrue((run/'artifacts').is_dir())
            aid=self.artifact(run,'artifacts/a.txt',b'a')
            (run/'evidence.jsonl').write_text('{"x":1}\n')
            manifest_id=load_manifest(run).run_id; events=(run/'run.jsonl').read_text()
            self.run_cli('init','example.com','--output-dir',tmp)
            self.assertEqual((run/'evidence.jsonl').read_text(),'{"x":1}\n')
            self.assertEqual(aid.read_bytes(),b'a')
            self.assertEqual(load_manifest(run).run_id,manifest_id)
            self.assertEqual((run/'run.jsonl').read_text(),events)
            (run/'evidence.jsonl').unlink(); aid.unlink(); (run/'artifacts').rmdir()
            self.run_cli('init','example.com','--output-dir',tmp)
            self.assertTrue((run/'evidence.jsonl').exists()); self.assertTrue((run/'artifacts').is_dir())
            self.assertEqual((run/'run.jsonl').read_text(),events)

    def test_register_records_hash_sequence_metadata_and_no_state_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=self.make_run(tmp); p=self.artifact(run,data=b'abc')
            manifest_before=(run/'manifest.json').read_text(); state_before=(run/'run.jsonl').read_text()
            r=register_evidence(run,'artifacts/http/homepage-response.txt','authorized-operator','http-response','text/plain','manual-capture','note')
            self.assertEqual(UUID(r.evidence_id).version,4); self.assertEqual(r.run_id,load_manifest(run).run_id)
            self.assertEqual(r.sequence,1); self.assertEqual(r.actor,'authorized-operator'); self.assertEqual(r.artifact_type,'http-response')
            self.assertEqual(r.media_type,'text/plain'); self.assertEqual(r.source,'manual-capture'); self.assertEqual(r.note,'note')
            self.assertEqual(r.sha256,hashlib.sha256(b'abc').hexdigest()); self.assertEqual(r.size_bytes,3)
            self.assertIsNotNone(__import__('datetime').datetime.fromisoformat(r.registered_at).tzinfo)
            self.assertEqual(p.read_bytes(),b'abc'); self.assertEqual((run/'manifest.json').read_text(),manifest_before); self.assertEqual((run/'run.jsonl').read_text(),state_before)
            self.assertEqual(load_state(run).current_state,'initialized')
            lines=(run/'evidence.jsonl').read_text().splitlines(); self.assertEqual(len(lines),1); json.loads(lines[0])
            p2=self.artifact(run,'artifacts/bin.dat',b'\x00\xff')
            r2=register_evidence(run,'artifacts/bin.dat','authorized-operator','other')
            self.assertEqual(r2.sequence,2); self.assertEqual(r2.size_bytes,2)

    def test_registry_validation_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=self.make_run(tmp); self.artifact(run); r=register_evidence(run,'artifacts/http/homepage-response.txt','authorized-operator','http-response')
            base=r.to_dict()
            cases=[]
            dup=base.copy(); dup['sequence']=2; cases.append([base,dup])
            gap=base.copy(); gap['sequence']=2; cases.append([gap])
            bad=base.copy(); bad['run_id']='wrong'; cases.append([bad])
            bad=base.copy(); bad['evidence_id']='bad'; cases.append([bad])
            bad=base.copy(); bad['artifact_type']='HTTP'; cases.append([bad])
            bad=base.copy(); bad['sha256']=bad['sha256'].upper(); cases.append([bad])
            bad=base.copy(); bad['size_bytes']=-1; cases.append([bad])
            bad=base.copy(); bad['event_type']='x'; cases.append([bad])
            bad=base.copy(); del bad['actor']; cases.append([bad])
            bad=base.copy(); bad['registered_at']='nope'; cases.append([bad])
            for i,records in enumerate(cases):
                (run/'evidence.jsonl').write_text('\n'.join(json.dumps(x) for x in records)+'\n')
                with self.assertRaises(EvidenceValidationError, msg=i): load_evidence_registry(run)
            (run/'evidence.jsonl').write_text('{bad\n')
            with self.assertRaises(EvidenceValidationError): load_evidence_registry(run)
            (run/'evidence.jsonl').write_text(json.dumps(base)+'\n\n')
            with self.assertRaises(EvidenceValidationError): load_evidence_registry(run)
            (run/'evidence.jsonl').write_text('[]\n')
            with self.assertRaises(EvidenceValidationError): load_evidence_registry(run)

    def test_path_safety_and_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=self.make_run(tmp); self.artifact(run)
            before=(run/'evidence.jsonl').read_text()
            invalid=['/tmp/x','../x','artifacts/../../x','manifest.json','run.jsonl','scope.yaml','evidence.jsonl','artifacts/missing']
            for path in invalid:
                with self.assertRaises(EvidenceValidationError): register_evidence(run,path,'authorized-operator','other')
            d=run/'artifacts/dir'; d.mkdir()
            with self.assertRaises(EvidenceValidationError): register_evidence(run,'artifacts/dir','authorized-operator','other')
            os.symlink('http/homepage-response.txt', run/'artifacts/link')
            with self.assertRaises(EvidenceValidationError): register_evidence(run,'artifacts/link','authorized-operator','other')
            (run/'artifacts/parentreal').mkdir(); os.symlink('parentreal', run/'artifacts/parentlink')
            with self.assertRaises(EvidenceValidationError): register_evidence(run,'artifacts/parentlink/x','authorized-operator','other')
            self.assertEqual((run/'evidence.jsonl').read_text(),before)
            register_evidence(run,'artifacts/http/homepage-response.txt','authorized-operator','http-response')
            with self.assertRaises(EvidenceRefusalError): register_evidence(run,'artifacts/http/homepage-response.txt','authorized-operator','http-response')

    def test_verification_statuses_and_archived(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=self.make_run(tmp); p=self.artifact(run,data=b'abc'); r=register_evidence(run,'artifacts/http/homepage-response.txt','authorized-operator','http-response')
            self.assertEqual(verify_all_evidence(run)[0].status,'verified')
            p.write_bytes(b'abcd'); self.assertEqual(verify_all_evidence(run)[0].status,'mismatch')
            p.unlink(); self.assertEqual(verify_all_evidence(run)[0].status,'missing')
            p.symlink_to('/tmp/nope'); self.assertEqual(verify_all_evidence(run)[0].status,'unsafe'); p.unlink()
            self.assertEqual(verify_all_evidence(run,'00000000-0000-4000-8000-000000000000')[0].status,'missing')
            p.write_bytes(b'abc')
            transition_state(run,'scoped','authorized-operator'); transition_state(run,'collecting','authorized-operator'); transition_state(run,'analyzing','authorized-operator'); transition_state(run,'reporting','authorized-operator'); transition_state(run,'completed','authorized-operator'); transition_state(run,'archived','authorized-operator')
            self.assertEqual(verify_all_evidence(run)[0].status,'verified')
            self.artifact(run,'artifacts/new.txt',b'n')
            with self.assertRaises(EvidenceRefusalError): register_evidence(run,'artifacts/new.txt','authorized-operator','other')

    def test_cli_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=self.make_run(tmp); self.artifact(run)
            code,out=self.run_cli('evidence','register',str(run),'artifacts/http/homepage-response.txt','--actor','authorized-operator','--type','http-response','--json')
            self.assertEqual(code,0); rec=json.loads(out); self.assertIn('evidence_id',rec)
            code,out=self.run_cli('evidence','list',str(run)); self.assertEqual(code,0); self.assertIn(rec['evidence_id'],out); self.assertIn(rec['path'],out)
            code,out=self.run_cli('evidence','list',str(run),'--json'); self.assertEqual(code,0); self.assertEqual(json.loads(out)['evidence_count'],1)
            code,out=self.run_cli('evidence','verify',str(run),'--json'); self.assertEqual(code,0); self.assertTrue(json.loads(out)['verified'])
            (run/'artifacts/http/homepage-response.txt').write_text('changed')
            code,out=self.run_cli('evidence','verify',str(run)); self.assertEqual(code,1); self.assertNotIn('Traceback',out)
            code,out=self.run_cli('evidence','register',str(run),'artifacts/http/homepage-response.txt','--actor','authorized-operator','--type','http-response'); self.assertEqual(code,1)
            code,out=self.run_cli('evidence','register',str(run),'../x','--actor','authorized-operator','--type','other'); self.assertEqual(code,2)
            (run/'evidence.jsonl').write_text('{bad\n')
            code,out=self.run_cli('evidence','verify',str(run)); self.assertEqual(code,2); self.assertNotIn('Traceback',out)

if __name__ == '__main__':
    unittest.main()
