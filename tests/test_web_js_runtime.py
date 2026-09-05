from __future__ import annotations
import shutil, subprocess, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'tools' / 'web_js_runtime_check.js'


class WebJsRuntimeTests(unittest.TestCase):
    """Guards against the class of bug where app.js calls a helper that is never
    defined (a render-time ReferenceError that `node --check` cannot see). The
    harness loads app.js under a DOM stub and runs the form render paths."""

    @unittest.skipUnless(shutil.which('node'), 'node is required for the app.js runtime check')
    def test_app_js_helpers_defined_and_render_paths_run(self):
        self.assertTrue(HARNESS.is_file(), f'missing harness: {HARNESS}')
        proc = subprocess.run(
            [shutil.which('node'), str(HARNESS)],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        self.assertEqual(
            proc.returncode, 0,
            msg=f'app.js runtime check failed\nstdout={proc.stdout!r}\nstderr={proc.stderr!r}',
        )
        self.assertIn('web js runtime check: OK', proc.stdout)


if __name__ == '__main__':
    unittest.main()
