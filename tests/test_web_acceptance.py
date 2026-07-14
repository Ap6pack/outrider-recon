from __future__ import annotations
import unittest
try:
    from fastapi.testclient import TestClient  # noqa: F401
except ImportError:
    TestClient = None
from tools.web_acceptance import run_acceptance

@unittest.skipIf(TestClient is None, 'FastAPI web extra is not installed')
class WebAcceptanceTests(unittest.TestCase):
    def test_complete_web_control_plane_acceptance(self):
        result = run_acceptance()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['stage_count'], 9)
        self.assertTrue(all(stage['status'] == 'PASS' for stage in result['stages']))
