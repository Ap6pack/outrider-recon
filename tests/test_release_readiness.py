from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import release_audit

class ReleaseReadinessTests(unittest.TestCase):
    def test_audit_human_and_json_output(self):
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            code=release_audit.main([])
        self.assertIn('PASS:', buf.getvalue())
        self.assertIn('Overall status:', buf.getvalue())
        self.assertIn(code, (0,1))
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            code=release_audit.main(['--json'])
        data=json.loads(buf.getvalue())
        self.assertIn('overall_status', data)
        self.assertIn('versions', data)
        self.assertIn(code, (0,1))

    def test_warning_and_failure_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.check_call(['cp','-a',str(ROOT)+'/.',str(root)])
            shutil.rmtree(root/'.git')
            for cache in root.rglob('__pycache__'):
                shutil.rmtree(cache)
            (root/'fixture.txt').write_text('token = "' + 'abcdefghijklmnopqrstuvwxyz' + '"')
            buf=io.StringIO()
            with contextlib.redirect_stdout(buf): code=release_audit.main(['--root',str(root),'--json'])
            self.assertEqual(code, 1)
            (root/'outrider/skill_catalog.json').write_text('{"schema_version":1,"skills":[]}')
            buf=io.StringIO()
            with contextlib.redirect_stdout(buf): code=release_audit.main(['--root',str(root),'--json'])
            self.assertEqual(code, 2)

    def test_version_inventory_and_independent_domains(self):
        versions=release_audit.Audit(ROOT).versions()
        self.assertEqual(versions['python_package'],'0.1.0')
        self.assertEqual(versions['claude_plugin'],'3.0.0')
        self.assertNotEqual(versions['python_package'], versions['claude_plugin'])
        self.assertEqual(set(versions['schemas'].values()), {1})

    def test_skill_catalog_matches_shipped_dirs_and_installed_metadata(self):
        expected=tuple(sorted(p.parent.name for p in (ROOT/'skills').glob('*/SKILL.md') if p.parent.name!='_shared'))
        from outrider.skill_contract import list_known_skills
        from outrider.package_resources import packaged_skill_catalog
        self.assertEqual(len(expected), 11)
        self.assertEqual(list_known_skills(ROOT), expected)
        self.assertEqual(packaged_skill_catalog(), expected)
        self.assertEqual(list_known_skills(), expected)

    def test_schemas_static_plugin_and_adrs(self):
        from outrider.package_resources import schema_json, web_static_path
        for name in ['skill-request-v1.schema.json','skill-result-v1.schema.json','finding-v1.schema.json']:
            self.assertEqual(json.loads((ROOT/'contracts'/name).read_text()), schema_json(name))
        for name in ['index.html','app.css','app.js']:
            self.assertTrue(web_static_path(name).exists())
        self.assertEqual(json.loads((ROOT/'.claude-plugin/plugin.json').read_text())['version'], '3.0.0')
        for i in range(1,8):
            self.assertTrue(list((ROOT/'docs/adr').glob(f'{i:04d}-*.md')))

    def test_package_metadata_boundaries(self):
        py=release_audit.load_pyproject(ROOT/'pyproject.toml')
        deps='\n'.join(py['project'].get('dependencies',[])).lower()
        self.assertNotIn('fastapi', deps)
        self.assertNotIn('uvicorn', deps)
        self.assertIn('web', py['project']['optional-dependencies'])
        data=py['tool']['setuptools']['package-data']['outrider']
        self.assertIn('web_static/*', data)
        self.assertIn('skill_catalog.json', data)
        self.assertIn('schemas/*.json', data)

    def test_archive_content_assertions_when_dist_exists(self):
        dist=ROOT/'dist'
        wheels=list(dist.glob('*.whl')) if dist.exists() else []
        sdists=list(dist.glob('*.tar.gz')) if dist.exists() else []
        if not wheels or not sdists:
            self.skipTest('dist artifacts are built in the release-readiness CI job')
        for artifact in wheels+sdists:
            result=release_audit.inspect_archive(artifact)
            self.assertTrue(result['has_license'])
            self.assertTrue(result['has_metadata'])
            self.assertTrue(result['has_web_static'])
            self.assertTrue(result['has_schemas'])
            self.assertTrue(result['has_skill_catalog'])
            self.assertFalse(result['unexpected'])

    def test_detect_unexpected_artifacts_and_secret_like_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); subprocess.check_call(['cp','-a',str(ROOT)+'/.',str(root)])
            (root/'.git').rename(root/'git-disabled')
            (root/'runs').mkdir(exist_ok=True); (root/'runs'/'manifest.json').write_text('{}')
            (root/'fixture.txt').write_text('token = "' + 'abcdefghijklmnopqrstuvwxyz' + '"')
            audit=release_audit.Audit(root).run()
            by={c.name:c for c in audit.checks}
            self.assertEqual(by['no obvious tracked run/build artifacts'].status, 'FAIL')
            self.assertEqual(by['obvious secret-like patterns'].status, 'WARN')
            self.assertIn('false positives', (ROOT/'docs/release-readiness.md').read_text())

    def test_cli_version_and_module_invocation(self):
        for cmd in ([sys.executable,'-m','outrider','--version'], [sys.executable,'-m','outrider','--help']):
            cp=subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr+cp.stdout)
        from outrider.cli import package_version
        self.assertRegex(package_version(), r'^\d+\.\d+\.\d+')

    def test_audit_is_read_only_and_no_network(self):
        before={p: p.stat().st_mtime_ns for p in ROOT.rglob('*') if p.is_file() and '.git' not in p.parts}
        def deny_network(*args, **kwargs):
            raise AssertionError('network not allowed')
        with mock.patch('socket.socket', side_effect=deny_network):
            release_audit.Audit(ROOT).run()
        after={p: p.stat().st_mtime_ns for p in before}
        self.assertEqual(before, after)

if __name__ == '__main__':
    unittest.main()
