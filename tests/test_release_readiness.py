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

def copy_repo_fixture(root: Path) -> None:
    subprocess.check_call(['cp','-a',str(ROOT)+'/.',str(root)])
    # Strip local, git-ignored working-directory artifacts so the fixture reflects
    # a clean checkout. Without .git the audit rglob-scans everything, so a `runs/`
    # folder (created the moment someone runs `outrider init` or the web portal) or
    # a repo-local virtualenv would otherwise trip check_artifacts and mask the
    # WARN-vs-FAIL behavior this test asserts.
    for pattern in ['__pycache__', '.pytest_cache', 'build', 'dist', '*.egg-info', 'runs', '.venv', 'venv']:
        for path in root.rglob(pattern):
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()

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
            copy_repo_fixture(root)
            shutil.rmtree(root/'.git')
            (root/'fixture.txt').write_text('token = "' + 'abcdefghijklmnopqrstuvwxyz' + '"')
            buf=io.StringIO()
            with contextlib.redirect_stdout(buf): code=release_audit.main(['--root',str(root),'--json'])
            self.assertEqual(code, 0)
            (root/'outrider/skill_catalog.json').write_text('{"schema_version":1,"skills":[]}')
            buf=io.StringIO()
            with contextlib.redirect_stdout(buf): code=release_audit.main(['--root',str(root),'--json'])
            self.assertEqual(code, 2)

    def test_version_inventory_and_unified_domain(self):
        versions=release_audit.Audit(ROOT).versions()
        self.assertEqual(versions['version'],'4.0.0')
        self.assertEqual(versions['plugin_version'],'4.0.0')
        self.assertEqual(versions['version'], versions['plugin_version'])
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
        self.assertEqual(json.loads((ROOT/'.claude-plugin/plugin.json').read_text())['version'], '4.0.0')
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
            root=Path(td); copy_repo_fixture(root)
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
        self.assertEqual(package_version(), '4.0.0')


    def test_lint_workflow_separates_core_and_web_tests(self):
        import yaml
        workflow = (ROOT/'.github/workflows/lint.yml').read_text()
        parsed = yaml.safe_load(workflow)
        jobs = parsed['jobs']
        self.assertIn('python-core-tests', jobs)
        self.assertIn('web-control-tests', jobs)
        self.assertIn('release-readiness', jobs)
        self.assertNotIn('python-cli-tests', jobs)

        for job in jobs.values():
            self.assertNotIn('continue-on-error', job)

        core = jobs['python-core-tests']
        self.assertEqual(core['name'], 'Python core tests (${{ matrix.python-version }})')
        self.assertFalse(core['strategy']['fail-fast'])
        self.assertEqual(core['strategy']['matrix']['python-version'], ['3.10', '3.11', '3.12'])
        core_steps = '\n'.join(str(step.get('run', '')) for step in core['steps'])
        self.assertIn('python -m pip install -e .', core_steps)
        self.assertNotIn('.[web]', core_steps)
        self.assertIn('python -m compileall outrider tests mcp-server tools', core_steps)
        self.assertIn('python -m unittest discover -s tests -p "test_*.py"', core_steps)

        web = jobs['web-control-tests']
        self.assertEqual(web['name'], 'Web control-plane tests (3.12)')
        setup = next(step for step in web['steps'] if step.get('uses') == 'actions/setup-python@v5')
        self.assertEqual(setup['with']['python-version'], '3.12')
        web_steps = '\n'.join(str(step.get('run', '')) for step in web['steps'])
        self.assertIn('python -m pip install -e ".[web,enrichment]"', web_steps)
        self.assertIn('python -c "import fastapi, httpx, uvicorn"', web_steps)
        self.assertIn('python -m unittest tests.test_web_view tests.test_web_app', web_steps)
        self.assertIn('python -m unittest discover -s tests -p "test_*.py"', web_steps)

        release = jobs['release-readiness']
        release_setup = next(step for step in release['steps'] if step.get('uses') == 'actions/setup-python@v5')
        self.assertEqual(release_setup['with']['python-version'], '3.12')
        all_versions = set()
        for job in jobs.values():
            matrix = job.get('strategy', {}).get('matrix', {})
            all_versions.update(matrix.get('python-version', []))
            for step in job.get('steps', []):
                if step.get('uses') == 'actions/setup-python@v5':
                    version = step.get('with', {}).get('python-version')
                    if isinstance(version, str) and version.startswith('3.'):
                        all_versions.add(version)
        self.assertTrue({'3.10', '3.11', '3.12'}.issubset(all_versions))


    def test_release_notes_changelog_and_workflow(self):
        changelog=(ROOT/'CHANGELOG.md').read_text()
        self.assertIn('## [Unreleased]', changelog)
        self.assertRegex(changelog, r'## \[4\.0\.0\] - 2026-09-11')
        unreleased=changelog.split('## [Unreleased]',1)[1].split('---',1)[0]
        self.assertNotIn('scope-wide active-enumeration authorization', unreleased)
        for rel in ['README.md','4.0.0.md','release-checklist.md']:
            self.assertTrue((ROOT/'docs/releases'/rel).exists())
        notes=(ROOT/'docs/releases/4.0.0.md').read_text().lower()
        self.assertIn('outrider_recon-4.0.0-py3-none-any.whl', notes)
        self.assertIn('outrider-recon-bundle-4.0.0.zip', notes)
        docs='\n'.join(p.read_text(errors='ignore') for p in [ROOT/'README.md', ROOT/'docs/installation.md', ROOT/'docs/architecture.md'])
        self.assertNotIn('independent version domains', docs)
        wf=(ROOT/'.github/workflows/release-candidate.yml').read_text()
        import yaml
        parsed=yaml.safe_load(wf)
        self.assertIsInstance(parsed, dict)
        self.assertIn('workflow_dispatch:', wf)
        self.assertNotIn('pull_request:', wf)
        self.assertNotIn('push:', wf)
        self.assertIn('contents: read', wf)
        clean_web_step = next(
            step for step in parsed['jobs']['build-candidates']['steps']
            if step.get('name') == 'Clean web install smoke'
        )
        clean_web_script = clean_web_step['run']
        self.assertIn('TemporaryDirectory', clean_web_script)
        self.assertRegex(clean_web_script, r'runs_root\s*=\s*Path\([^\n]+\)\s*/\s*[\"\']runs[\"\']')
        self.assertIn('runs_root.mkdir()', clean_web_script)
        self.assertRegex(clean_web_script, r'create_app\(\s*runs_root(?:\s*,\s*control_token=)?')
        self.assertIn('control_token="fixture"', clean_web_script)
        self.assertNotRegex(clean_web_script, r'create_app\(\s*\)')
        for path in ['/api/health', '/', '/static/app.css', '/static/app.js']:
            self.assertIn(path, clean_web_script)
        self.assertIn('health.status_code == 200', clean_web_script)
        self.assertIn('client.get("/").status_code == 200', clean_web_script)
        self.assertNotIn('uvicorn', clean_web_script.lower())
        self.assertNotIn('0.0.0.0', clean_web_script)
        for bad in ['contents: write','packages: write','id-token: write','actions: write','twine upload','gh release create','git tag','git push','secrets.']:
            self.assertNotIn(bad, wf)
        for needed in ['tools/release_audit.py','unittest discover','compileall','python -m build','twine check','tools/build_release_bundle.py','SHA256SUMS','Clean base install','Clean web install','actions/upload-artifact@v4']:
            self.assertIn(needed, wf)


    def test_post_release_documentation_truth_alignment(self):
        release_link = 'https://github.com/Ap6pack/outrider-recon/releases/tag/v4.0.0'
        readme = (ROOT/'README.md').read_text()
        self.assertIn('## Current release candidates', readme)
        self.assertIn(release_link, readme)
        self.assertIn('does not publish automatically', readme)
        self.assertNotIn('published as a GitHub release', readme)
        self.assertTrue(readme.rstrip().endswith('> _Raw recon tells you what exists. Outrider helps decide what matters first._'))
        release_index = (ROOT/'docs/releases/README.md').read_text()
        self.assertIn('v4.0.0', release_index)
        self.assertIn('workflow_dispatch', release_index)
        self.assertIn('does not automatically tag, publish GitHub releases, upload to PyPI', release_index)
        notes = (ROOT/'docs/releases/4.0.0.md').read_text()
        self.assertIn('4.0.0', notes)
        self.assertIn('outrider_recon-4.0.0-py3-none-any.whl', notes)
        self.assertIn('outrider-recon-bundle-4.0.0.zip', notes)
        self.assertIn('loopback-only', notes)
        self.assertIn('v4.0.0', notes)
        readiness = (ROOT/'docs/release-readiness.md').read_text()
        self.assertIn('**Audit date:** 2026-09-11', readiness)
        self.assertIn('This preparation PR does not create release tags or release records', readiness)
        install = (ROOT/'docs/installation.md').read_text()
        self.assertIn('deterministic local run, scope, state, evidence, approval, action-policy, contract, finding, and review controls', install)
        self.assertIn('Denied MCP decisions perform no HTTP or DNS request', install)
        architecture = (ROOT/'docs/architecture.md').read_text()
        self.assertIn('skill request/result contract creation and validation', architecture)
        self.assertIn('deterministic human-reviewed finding promotion and verification', architecture)
        self.assertNotIn('web UI are' + ' not implemented', architecture)
        combined = '\n'.join((ROOT/p).read_text(errors='ignore') for p in ['README.md','docs/releases/README.md','docs/releases/4.0.0.md','docs/installation.md'])
        self.assertIn('The same `SHA256SUMS` file covers all three', combined)
        self.assertIn("grep 'outrider-recon-bundle-4.0.0.zip' SHA256SUMS | sha256sum -c -", combined)
        self.assertIn("grep -E 'outrider_recon-4.0.0-py3-none-any.whl|outrider_recon-4.0.0.tar.gz' SHA256SUMS | sha256sum -c -", combined)

    def test_skill_inventory_and_schema_version_preservation(self):
        # Skills are versioned as part of the plugin/content release, not per-file
        # frontmatter, so the audit tracks the shipped skill inventory (names/count).
        expected=[
            'analysis-and-reporting', 'cloud-and-infra', 'identity-fabric', 'offensive-osint',
            'osint-methodology', 'people-breach-intel', 'post-discovery', 'recon-asset-discovery',
            'report-template', 'secrets-and-dorks', 'web-surface']
        skills=release_audit.Audit(ROOT).versions()['skills']
        self.assertEqual(skills, expected)
        self.assertEqual(len(skills), 11)
        self.assertNotIn('_shared', skills)
        self.assertEqual(set(release_audit.Audit(ROOT).versions()['schemas'].values()), {1})

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
