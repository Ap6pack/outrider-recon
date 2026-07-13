from __future__ import annotations

import contextlib, hashlib, io, json, os, subprocess, sys, tempfile, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_release_bundle

class ReleaseBundleTests(unittest.TestCase):
    def build(self, td: str, *extra: str):
        return subprocess.run([sys.executable, str(ROOT/'tools/build_release_bundle.py'), '--output-dir', td, '--source-date-epoch', '1783900800', *extra], cwd=ROOT, text=True, capture_output=True)

    def test_bundle_contents_manifest_and_determinism(self):
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            cp=self.build(td1); self.assertEqual(cp.returncode,0,cp.stderr+cp.stdout)
            archive=Path(td1)/'outrider-recon-bundle-3.0.1.zip'
            self.assertTrue(archive.exists())
            with zipfile.ZipFile(archive) as z:
                names=z.namelist()
                self.assertTrue(all(n.startswith('outrider-recon-bundle-3.0.1/') for n in names))
                self.assertFalse(any('/tests/' in n or '/.github/' in n or '__pycache__' in n or '/dist/' in n or n.startswith('/') or '..' in Path(n).parts for n in names))
                for required in ['README.md','.claude-plugin/plugin.json','pyproject.toml','outrider/skill_catalog.json','contracts/skill-request-v1.schema.json','skills/_shared/run-contract.md','tools/build_release_bundle.py']:
                    self.assertIn('outrider-recon-bundle-3.0.1/'+required, names)
                skills={Path(n).parts[2] for n in names if n.endswith('/SKILL.md') and Path(n).parts[1]=='skills' and Path(n).parts[2] != '_shared'}
                self.assertEqual(len(skills),11)
                manifest=json.loads(z.read('outrider-recon-bundle-3.0.1/RELEASE-MANIFEST.json'))
                self.assertEqual(manifest['python_version'],'0.2.0')
                self.assertEqual(manifest['plugin_version'],'3.0.1')
                self.assertEqual(manifest['skill_count'],11)
                self.assertEqual(set(manifest['schema_versions'].values()), {1})
                paths=[f['path'] for f in manifest['files']]
                self.assertEqual(paths, sorted(paths))
                self.assertNotIn('RELEASE-MANIFEST.json', paths)
                for entry in manifest['files'][:25]:
                    data=z.read('outrider-recon-bundle-3.0.1/'+entry['path'])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])
                    self.assertEqual(len(data), entry['size_bytes'])
            cp2=self.build(td2); self.assertEqual(cp2.returncode,0,cp2.stderr+cp2.stdout)
            h1=hashlib.sha256(archive.read_bytes()).hexdigest()
            h2=hashlib.sha256((Path(td2)/archive.name).read_bytes()).hexdigest()
            self.assertEqual(h1,h2)

    def test_output_refusal_force_and_json(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(self.build(td).returncode,0)
            self.assertEqual(self.build(td).returncode,2)
            cp=self.build(td,'--force','--json')
            self.assertEqual(cp.returncode,0,cp.stderr+cp.stdout)
            data=json.loads(cp.stdout)
            self.assertEqual(data['bundle_filename'],'outrider-recon-bundle-3.0.1.zip')
            self.assertRegex(data['bundle_sha256'], r'^[0-9a-f]{64}$')

    def test_rejects_unexpected_symlink(self):
        original=build_release_bundle.ALLOWLIST_FILES
        try:
            with tempfile.TemporaryDirectory(dir=ROOT) as td:
                rel=Path(td).relative_to(ROOT)/'bad-link'
                os.symlink('/etc/passwd', ROOT/rel)
                build_release_bundle.ALLOWLIST_FILES = []
                build_release_bundle.ALLOWLIST_DIRS = [str(rel.parent)]
                with self.assertRaises(build_release_bundle.BundleError):
                    build_release_bundle.collect_files()
        finally:
            try: (ROOT/rel).unlink()
            except Exception: pass
            build_release_bundle.ALLOWLIST_FILES = original
            build_release_bundle.ALLOWLIST_DIRS = ['outrider', 'contracts', 'skills', 'mcp-server', 'docs', 'examples']

if __name__ == '__main__':
    unittest.main()
