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

class WebEngagementMetadataTests(unittest.TestCase):
    def test_platform_and_traffic_header_are_stored_and_survive_scope_replace(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run_dir = create_web_run_atomic(root, WebRunRequest('example.com','op','auth',['example.com'],[], 'HackerOne', {'name':'X-Bug-Bounty','value':'H1-op'}))
            text = (run_dir / 'scope.yaml').read_text(encoding='utf-8')
            self.assertIn('engagement_platform: HackerOne', text)
            self.assertIn('X-Bug-Bounty', text)
            from outrider.scope import replace_scope_rules_atomic, scope_revision
            replace_scope_rules_atomic(run_dir, scope_revision(run_dir), 'op', 'update', ['example.com','*.example.com'], [], 'example.com')
            text = (run_dir / 'scope.yaml').read_text(encoding='utf-8')
            self.assertIn('engagement_platform: HackerOne', text)
            self.assertIn('X-Bug-Bounty', text)

    def test_sensitive_and_partial_traffic_headers_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaises(RunSetupError):
                create_web_run_atomic(root, WebRunRequest('example.com','op','auth',['example.com'],[], 'HackerOne', {'name':'Authorization','value':'secret'}))
            with self.assertRaises(RunSetupError):
                create_web_run_atomic(root, WebRunRequest('other.com','op','auth',['other.com'],[], 'HackerOne', {'name':'X-Bug-Bounty'}))

    def test_url_path_in_scope_with_host_target_succeeds_and_enforces_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Host target is in scope by reachability against a URL/path rule.
            run_dir = create_web_run_atomic(
                root,
                WebRunRequest('www.example.com', 'op', 'auth', ['www.example.com/book/'], []),
            )
            self.assertEqual(evaluate_scope_path(run_dir, 'www.example.com').decision, 'allow')
            self.assertEqual(evaluate_scope_path(run_dir, 'https://www.example.com/book/x').decision, 'allow')
            self.assertEqual(evaluate_scope_path(run_dir, 'https://www.example.com/admin').decision, 'deny')

    def test_url_path_scope_rejects_target_host_not_referenced(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # apex isn't the host of any rule -> not reachable -> rejected at setup
            with self.assertRaises(RunSetupError):
                create_web_run_atomic(
                    root,
                    WebRunRequest('example.com', 'op', 'auth', ['www.example.com/book/'], []),
                )
