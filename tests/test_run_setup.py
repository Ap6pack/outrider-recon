import tempfile
from pathlib import Path
import unittest

from outrider.run_setup import WebRunRequest, create_web_run_atomic, safe_run_dir_name, RunConflictError, RunSetupError
from outrider.state import load_manifest, load_state
from outrider.scope import evaluate_scope_path, scope_revision

class RunSetupTests(unittest.TestCase):
    def test_web_run_creation_is_atomic_and_normalizes_url(self):
        with tempfile.TemporaryDirectory() as d:
            run = create_web_run_atomic(d, WebRunRequest('https://Example.com:443/path?q=1','op','ROE',['example.com','*.example.com'],[]))
            self.assertEqual(run.name, 'example.com')
            self.assertEqual(load_manifest(run).target, 'example.com')
            self.assertEqual(load_state(run).current_state, 'initialized')
            self.assertEqual(evaluate_scope_path(run, 'api.example.com').decision, 'allow')
            self.assertTrue(scope_revision(run))
            self.assertFalse(list(Path(d).glob('.outrider-create-*')))
            for rel in ['manifest.json','scope.yaml','run.jsonl','evidence.jsonl','approvals.jsonl','findings.jsonl','artifacts','contracts/requests','contracts/results','assets.json','web_surface.json','identity_fabric.json','bb_intel.json','findings.md','technique_cards.md','surface.md','report.md']:
                self.assertTrue((run / rel).exists(), rel)
    def test_safe_names_and_rejections(self):
        self.assertEqual(safe_run_dir_name('192.0.2.1'), 'ipv4-192-0-2-1')
        self.assertTrue(safe_run_dir_name('2001:db8::1').startswith('ipv6-'))
        with tempfile.TemporaryDirectory() as d:
            create_web_run_atomic(d, WebRunRequest('example.com','op','ROE',['example.com'],[]))
            with self.assertRaises(RunConflictError):
                create_web_run_atomic(d, WebRunRequest('example.com','op','ROE',['example.com'],[]))
            for bad in ['*.example.com','192.0.2.0/24','/tmp/x','../example.com','https://u:p@example.com','organization']:
                with self.subTest(bad=bad):
                    with self.assertRaises(Exception):
                        create_web_run_atomic(d, WebRunRequest(bad,'op','ROE',['example.com'],[]))
    def test_scope_policy_rejections_create_no_files(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RunSetupError):
                create_web_run_atomic(d, WebRunRequest('example.com','op','ROE',['other.com'],[]))
            self.assertEqual(list(Path(d).iterdir()), [])
            with self.assertRaises(RunSetupError):
                create_web_run_atomic(d, WebRunRequest('example.com','op','ROE',['example.com'],['example.com']))

if __name__ == '__main__':
    unittest.main()
