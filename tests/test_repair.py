import shutil
import tempfile
import unittest
from pathlib import Path

from outrider.run_setup import WebRunRequest, create_web_run_atomic
from outrider.repair import diagnose_run, repair_run
from outrider.evidence import load_evidence_registry, register_evidence
from outrider.state import load_state


class RepairTests(unittest.TestCase):
    def _run(self, td):
        return create_web_run_atomic(Path(td), WebRunRequest("example.com", "op", "ROE", ["example.com"], []))

    def test_healthy_run_has_no_issues(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertTrue(diagnose_run(self._run(td))["ok"])

    def test_trailing_malformed_line_is_dropped_and_backed_up(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._run(td)
            (run / "artifacts" / "a.txt").write_text("x", encoding="utf-8")
            register_evidence(run, "artifacts/a.txt", "op", "text")
            good = (run / "evidence.jsonl").read_text(encoding="utf-8")
            # Simulate a crash mid-append: a truncated trailing line.
            (run / "evidence.jsonl").write_text(good + '{"partial": ', encoding="utf-8")
            with self.assertRaises(Exception):  # the registry no longer loads
                load_evidence_registry(run)
            di = diagnose_run(run)
            self.assertEqual([i["kind"] for i in di["safe_repairable"] if i["target"] == "evidence.jsonl"], ["trailing_malformed_line"])
            result = repair_run(run, apply=True)
            self.assertTrue(result["ok"])
            self.assertEqual((run / "evidence.jsonl").read_text(encoding="utf-8"), good)
            self.assertTrue(any(p.name.startswith("evidence.jsonl.corrupt-") for p in run.iterdir()))
            # The registry loads again after repair, with its one real record intact.
            self.assertEqual(load_evidence_registry(run).evidence_count, 1)

    def test_midfile_malformed_line_is_manual_and_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._run(td)
            body = '{"a":1}\nGARBAGE\n{"b":2}\n'
            (run / "evidence.jsonl").write_text(body, encoding="utf-8")
            di = diagnose_run(run)
            self.assertTrue(any(i["kind"] == "malformed_line_midfile" and i["severity"] == "manual" for i in di["issues"]))
            result = repair_run(run, apply=True)
            self.assertFalse(result["ok"])
            self.assertEqual((run / "evidence.jsonl").read_text(encoding="utf-8"), body)  # untouched

    def test_missing_default_file_and_dir_recreated(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._run(td)
            (run / "assets.json").unlink()
            (run / "findings.md").unlink()
            shutil.rmtree(run / "artifacts")
            result = repair_run(run, apply=True)
            kinds = {(r["kind"], r["target"]) for r in result["repaired"]}
            self.assertIn(("missing_default_file", "assets.json"), kinds)
            self.assertIn(("missing_markdown", "findings.md"), kinds)
            self.assertIn(("missing_dir", "artifacts"), kinds)
            self.assertTrue((run / "assets.json").is_file() and (run / "findings.md").is_file() and (run / "artifacts").is_dir())
            self.assertTrue(result["ok"])

    def test_missing_ledger_recreated_empty(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._run(td)
            (run / "evidence.jsonl").unlink()
            result = repair_run(run, apply=True)
            self.assertTrue((run / "evidence.jsonl").is_file())
            self.assertEqual((run / "evidence.jsonl").read_text(encoding="utf-8"), "")

    def test_missing_manifest_is_manual_and_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._run(td)
            (run / "manifest.json").unlink()
            result = repair_run(run, apply=True)
            self.assertFalse(result["ok"])
            self.assertEqual(result["repaired"], [])
            self.assertTrue(any(i["kind"] == "manifest_unreadable" for i in result["manual"]))

    def test_damaged_state_log_is_manual_never_autofixed(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._run(td)
            original = (run / "run.jsonl").read_text(encoding="utf-8")
            (run / "run.jsonl").write_text(original + '{"partial": ', encoding="utf-8")
            result = repair_run(run, apply=True)
            self.assertTrue(any(i["kind"] == "damaged_state_log" and i["severity"] == "manual" for i in result["issues"]))
            self.assertTrue((run / "run.jsonl").read_text(encoding="utf-8").endswith('{"partial": '))  # untouched

    def test_missing_scope_is_manual(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._run(td)
            (run / "scope.yaml").unlink()
            di = diagnose_run(run)
            self.assertTrue(any(i["kind"] == "missing_scope" and i["severity"] == "manual" for i in di["issues"]))


if __name__ == "__main__":
    unittest.main()
