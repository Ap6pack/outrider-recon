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
        "manifest.json",
        "scope.yaml",
        "run.jsonl",
        "evidence.jsonl",
        "approvals.jsonl",
        "artifacts",
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
            self.assertIn("  - \"example.com\"", scope_yaml)
            self.assertIn("  - \"*.example.com\"", scope_yaml)
            self.assertIn("  - \"admin.example.com\"", scope_yaml)
            self.assertIn("  - \"legacy.example.com\"", scope_yaml)

            events = [
                json.loads(line)
                for line in (run_dir / "run.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "run_initialized")
            self.assertEqual(events[0]["new_state"], "initialized")
            self.assertEqual(events[0]["sequence"], 1)
            self.assertIn("occurred_at", events[0])

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
            self.assertEqual(len(rerun_events), 1)

    def test_init_uses_empty_out_of_scope_list_and_preserves_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            status, _ = self.run_cli("init", "example.com", "--output-dir", tmpdir)
            self.assertEqual(status, 0)
            run_dir = Path(tmpdir) / "example.com"
            scope_path = run_dir / "scope.yaml"
            scope_yaml = scope_path.read_text(encoding="utf-8")
            self.assertIn("out_of_scope: []", scope_yaml)
            edited_scope = "in_scope:\n  - edited.example.com\nout_of_scope: []\n"
            scope_path.write_text(edited_scope, encoding="utf-8")
            rerun_status, _ = self.run_cli("init", "example.com", "--output-dir", tmpdir)
            self.assertEqual(rerun_status, 0)
            self.assertEqual(scope_path.read_text(encoding="utf-8"), edited_scope)

    def test_scope_check_cli_allow_deny_error_and_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run"
            run_dir.mkdir()
            (run_dir / "scope.yaml").write_text(
                "in_scope:\n  - example.com\n  - '*.example.com'\nout_of_scope:\n  - blocked.example.com\n",
                encoding="utf-8",
            )
            allow_status, allow_output = self.run_cli("scope-check", str(run_dir), "example.com")
            self.assertEqual(allow_status, 0)
            self.assertIn("ALLOW", allow_output)
            deny_status, deny_output = self.run_cli("scope-check", str(run_dir), "other.example.net")
            self.assertEqual(deny_status, 1)
            self.assertIn("DENY", deny_output)
            excluded_status, excluded_output = self.run_cli("scope-check", str(run_dir), "blocked.example.com")
            self.assertEqual(excluded_status, 1)
            self.assertIn("DENY", excluded_output)
            json_status, json_output = self.run_cli("scope-check", str(run_dir), "https://api.example.com/path", "--json")
            self.assertEqual(json_status, 0)
            payload = json.loads(json_output)
            self.assertEqual(payload["decision"], "allow")
            self.assertEqual(payload["normalized_candidate"], "api.example.com")
            self.assertEqual(payload["matched_rule"], "*.example.com")
            self.assertEqual(payload["matched_rule_source"], "in_scope")
            self.assertIn("reason", payload)
            missing_status, missing_output = self.run_cli("scope-check", str(Path(tmpdir) / "missing"), "example.com")
            self.assertEqual(missing_status, 2)
            self.assertIn("ERROR", missing_output)
            (run_dir / "scope.yaml").write_text("in_scope: []\n", encoding="utf-8")
            invalid_status, invalid_output = self.run_cli("scope-check", str(run_dir), "example.com")
            self.assertEqual(invalid_status, 2)
            self.assertIn("ERROR", invalid_output)

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

class ApprovalCliTests(unittest.TestCase):
    def run_cli(self, *argv):
        stdout = StringIO()
        with patch.object(sys, "argv", ["outrider", *argv]), redirect_stdout(stdout):
            status = cli.main()
        return status, stdout.getvalue()
    def test_approval_and_action_check_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_cli('init','example.com','--scope','example.com','--scope','*.example.com','--output-dir',tmp,'--actor','authorized-operator','--authorization-reference','EXAMPLE-ROE-001')[0],0)
            run=str(Path(tmp)/'example.com')
            self.assertEqual(self.run_cli('state','transition',run,'scoped','--actor','authorized-operator')[0],0)
            st,out=self.run_cli('approval','grant',run,'target_read_only_request','api.example.com','--actor','authorized-operator','--reason','Approved bounded read-only review','--duration-minutes','60','--json')
            self.assertEqual(st,0); grant=json.loads(out); aid=grant['approval_id']; self.assertEqual(grant['status'],'active')
            st,out=self.run_cli('approval','list',run,'--json'); self.assertEqual(st,0); self.assertEqual(json.loads(out)['active_count'],1)
            st,out=self.run_cli('action-check',run,'target_read_only_request','--candidate','api.example.com','--json'); self.assertEqual(st,0); self.assertEqual(json.loads(out)['decision'],'allow')
            st,out=self.run_cli('action-check',run,'target_enumeration','--candidate','api.example.com'); self.assertEqual(st,1); self.assertIn('DENY',out)
            st,out=self.run_cli('approval','revoke',run,aid,'--actor','authorized-operator','--reason','Approval withdrawn','--json'); self.assertEqual(st,0); self.assertEqual(json.loads(out)['event_type'],'approval_revoked')
            st,out=self.run_cli('action-check',run,'target_read_only_request','--candidate','api.example.com'); self.assertEqual(st,1); self.assertNotIn('Traceback',out)
            st,out=self.run_cli('approval','grant',run,'public_source_lookup','api.example.com','--actor','authorized-operator','--reason','x','--duration-minutes','60'); self.assertEqual(st,1); self.assertNotIn('Traceback',out)
