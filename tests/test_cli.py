import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from outrider import cli


class NormalizeRunNameTests(unittest.TestCase):
    def test_removes_http_scheme(self):
        self.assertEqual(cli.normalize_run_name("http://example.com"), "example.com")

    def test_removes_https_scheme(self):
        self.assertEqual(cli.normalize_run_name("https://example.com"), "example.com")

    def test_removes_trailing_slashes(self):
        self.assertEqual(cli.normalize_run_name("https://example.com///"), "example.com")

    def test_preserves_normal_domain_or_run_name(self):
        self.assertEqual(cli.normalize_run_name("example.com"), "example.com")
        self.assertEqual(cli.normalize_run_name("acme-q3-recon"), "acme-q3-recon")


class CliCommandTests(unittest.TestCase):
    expected_json_sidecars = set(cli.DEFAULT_FILES)
    expected_markdown_templates = {
        "findings.md",
        "technique_cards.md",
        "surface.md",
        "report.md",
    }
    expected_files = {
        "scope.yaml",
        "run.jsonl",
        *expected_json_sidecars,
        *expected_markdown_templates,
    }

    def run_cli(self, *argv):
        stdout = StringIO()
        with patch.object(sys, "argv", ["outrider", *argv]), redirect_stdout(stdout):
            status = cli.main()
        return status, stdout.getvalue()

    def test_init_creates_expected_run_files_and_preserves_edits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            status, output = self.run_cli(
                "init",
                "https://example.com/",
                "--scope",
                "example.com",
                "--scope",
                "*.example.com",
                "--exclude",
                "admin.example.com",
                "--exclude",
                "legacy.example.com",
                "--output-dir",
                tmpdir,
            )

            self.assertEqual(status, 0)
            run_dir = Path(tmpdir) / "example.com"
            self.assertTrue(run_dir.is_dir())
            self.assertIn(f"Initialized Outrider run: {run_dir}", output)

            for filename in self.expected_files:
                self.assertTrue((run_dir / filename).exists(), f"missing {filename}")

            scope_yaml = (run_dir / "scope.yaml").read_text(encoding="utf-8")
            self.assertIn("target: example.com", scope_yaml)
            self.assertIn("  - example.com", scope_yaml)
            self.assertIn("  - *.example.com", scope_yaml)
            self.assertIn("  - admin.example.com", scope_yaml)
            self.assertIn("  - legacy.example.com", scope_yaml)

            events = [
                json.loads(line)
                for line in (run_dir / "run.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event"], "run_initialized")
            self.assertEqual(events[0]["target"], "example.com")
            self.assertEqual(events[0]["run_dir"], str(run_dir))
            self.assertIn("created_at", events[0])

            edited_report = "# Operator edited report\n\nKeep this content.\n"
            (run_dir / "report.md").write_text(edited_report, encoding="utf-8")

            rerun_status, rerun_output = self.run_cli(
                "init",
                "example.com",
                "--output-dir",
                tmpdir,
            )

            self.assertEqual(rerun_status, 0)
            self.assertIn("No files created; run folder already existed.", rerun_output)
            self.assertEqual((run_dir / "report.md").read_text(encoding="utf-8"), edited_report)
            rerun_events = (run_dir / "run.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(rerun_events), 2)

    def test_show_returns_failure_for_missing_run_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_dir = Path(tmpdir) / "missing"
            status, output = self.run_cli("show", str(missing_dir))

            self.assertEqual(status, 1)
            self.assertIn(f"Run folder not found: {missing_dir}", output)

    def test_show_reports_present_and_missing_expected_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            init_status, _ = self.run_cli("init", "example.com", "--output-dir", tmpdir)
            self.assertEqual(init_status, 0)
            run_dir = Path(tmpdir) / "example.com"

            show_status, show_output = self.run_cli("show", str(run_dir))
            self.assertEqual(show_status, 0)
            self.assertIn(f"Outrider run: {run_dir}", show_output)
            for filename in self.expected_files:
                self.assertIn(f"[ok] {filename}", show_output)

            (run_dir / "assets.json").unlink()
            missing_status, missing_output = self.run_cli("show", str(run_dir))
            self.assertEqual(missing_status, 0)
            self.assertIn("[missing] assets.json", missing_output)
            self.assertIn("[ok] scope.yaml", missing_output)


if __name__ == "__main__":
    unittest.main()
