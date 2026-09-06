import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import mock_open, patch
from unittest import mock

from outrider import cli


class NormalizeRunNameTests(unittest.TestCase):
    def test_removes_http_scheme(self):
        self.assertEqual(cli.normalize_run_name("http://example.com"), "example.com")

    def test_removes_https_scheme(self):
        self.assertEqual(cli.normalize_run_name("https://example.com"), "example.com")

    def test_removes_trailing_slashes(self):
        self.assertEqual(
            cli.normalize_run_name("https://example.com///"), "example.com"
        )

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
        "findings.jsonl",
        "artifacts",
        "contracts",
        "contracts/requests",
        "contracts/results",
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
            self.assertIn('  - "example.com"', scope_yaml)
            self.assertIn('  - "*.example.com"', scope_yaml)
            self.assertIn('  - "admin.example.com"', scope_yaml)
            self.assertIn('  - "legacy.example.com"', scope_yaml)

            events = [
                json.loads(line)
                for line in (run_dir / "run.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
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
            self.assertEqual(
                (run_dir / "report.md").read_text(encoding="utf-8"), edited_report
            )
            rerun_events = (
                (run_dir / "run.jsonl").read_text(encoding="utf-8").splitlines()
            )
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
            rerun_status, _ = self.run_cli(
                "init", "example.com", "--output-dir", tmpdir
            )
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
            allow_status, allow_output = self.run_cli(
                "scope-check", str(run_dir), "example.com"
            )
            self.assertEqual(allow_status, 0)
            self.assertIn("ALLOW", allow_output)
            deny_status, deny_output = self.run_cli(
                "scope-check", str(run_dir), "other.example.net"
            )
            self.assertEqual(deny_status, 1)
            self.assertIn("DENY", deny_output)
            excluded_status, excluded_output = self.run_cli(
                "scope-check", str(run_dir), "blocked.example.com"
            )
            self.assertEqual(excluded_status, 1)
            self.assertIn("DENY", excluded_output)
            json_status, json_output = self.run_cli(
                "scope-check", str(run_dir), "https://api.example.com/path", "--json"
            )
            self.assertEqual(json_status, 0)
            payload = json.loads(json_output)
            self.assertEqual(payload["decision"], "allow")
            self.assertEqual(payload["normalized_candidate"], "api.example.com")
            self.assertEqual(payload["matched_rule"], "*.example.com")
            self.assertEqual(payload["matched_rule_source"], "in_scope")
            self.assertIn("reason", payload)
            missing_status, missing_output = self.run_cli(
                "scope-check", str(Path(tmpdir) / "missing"), "example.com"
            )
            self.assertEqual(missing_status, 2)
            self.assertIn("ERROR", missing_output)
            (run_dir / "scope.yaml").write_text("in_scope: []\n", encoding="utf-8")
            invalid_status, invalid_output = self.run_cli(
                "scope-check", str(run_dir), "example.com"
            )
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


class ContractCliTests(unittest.TestCase):
    def run_cli(self, *argv):
        stdout = StringIO()
        with patch.object(sys, "argv", ["outrider", *argv]), redirect_stdout(stdout):
            status = cli.main()
        return status, stdout.getvalue()

    def test_contract_request_create_validate_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.run_cli("init", "example.com", "--scope", "example.com", "--output-dir", tmpdir, "--actor", "authorized-operator")
            run = str(Path(tmpdir) / "example.com")
            status, out = self.run_cli("contract", "request", "create", run, "recon-asset-discovery", "--actor", "authorized-operator", "--objective", "obj", "--action-type", "public_source_lookup", "--candidate", "example.com")
            self.assertEqual(status, 1)
            self.assertNotIn("Traceback", out)
            self.run_cli("state", "transition", run, "scoped", "--actor", "authorized-operator")
            status, out = self.run_cli("contract", "request", "create", run, "recon-asset-discovery", "--actor", "authorized-operator", "--objective", "obj", "--action-type", "public_source_lookup", "--candidate", "example.com", "--json")
            self.assertEqual(status, 0)
            payload = json.loads(out)
            self.assertEqual(payload["overall_status"], "valid")
            request_file = str(Path(run) / payload["created_file"])
            status, out = self.run_cli("contract", "request", "validate", run, request_file)
            self.assertEqual(status, 0)
            self.assertIn("VALID", out)
            bad = Path(run) / "contracts" / "requests" / "bad.json"
            bad.write_text("{", encoding="utf-8")
            status, out = self.run_cli("contract", "request", "validate", run, str(bad))
            self.assertEqual(status, 2)
            self.assertNotIn("Traceback", out)

class WebFirstLauncherTests(unittest.TestCase):
    def test_no_argument_main_launches_portal_and_creates_default_runs_root(self):
        with tempfile.TemporaryDirectory() as td:
            cwd = Path.cwd()
            calls = []
            try:
                import os
                os.chdir(td)
                with mock.patch.dict(sys.modules, {'uvicorn': mock.Mock(run=lambda app, host, port: calls.append((host, port))), 'outrider.web_app': mock.Mock(create_app=lambda *a, **k: object())}), mock.patch('outrider.cli._open_browser_when_ready') as open_browser:
                    self.assertEqual(cli.main([]), 0)
                self.assertTrue((Path(td) / 'runs').is_dir())
                self.assertEqual(calls, [('127.0.0.1', 8765)])
                open_browser.assert_called_once()
            finally:
                os.chdir(cwd)

    def test_no_browser_avoids_browser_open(self):
        fake_uvicorn = mock.Mock()
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(sys.modules, {'uvicorn': fake_uvicorn, 'outrider.web_app': mock.Mock(create_app=lambda *a, **k: object())}), mock.patch('outrider.cli._open_browser_when_ready') as open_browser:
            self.assertEqual(cli.main(['--runs-root', td, '--no-browser']), 0)
            fake_uvicorn.run.assert_called_once()
            open_browser.assert_not_called()

    def test_symlink_and_file_roots_are_rejected_for_implicit_launcher(self):
        fake_uvicorn = mock.Mock()
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(sys.modules, {'uvicorn': fake_uvicorn, 'outrider.web_app': mock.Mock(create_app=lambda *a, **k: object())}):
            file_root = Path(td) / 'file'
            file_root.write_text('x')
            self.assertEqual(cli.main(['--runs-root', str(file_root), '--no-browser']), 2)
            if hasattr(Path, 'symlink_to'):
                target = Path(td) / 'target'; target.mkdir()
                link = Path(td) / 'link'; link.symlink_to(target, target_is_directory=True)
                self.assertEqual(cli.main(['--runs-root', str(link), '--no-browser']), 2)
            fake_uvicorn.run.assert_not_called()

    def test_subcommand_does_not_trigger_implicit_launch(self):
        with mock.patch('outrider.cli.launch_local_portal') as launch:
            with self.assertRaises(SystemExit):
                cli.main(['init'])
            launch.assert_not_called()


class LoopCliTests(unittest.TestCase):
    CASE = Path(__file__).resolve().parents[1] / "outrider" / "benchmark" / "ground_truth" / "case-a-subdomain-swagger.json"

    def run_cli(self, *argv):
        stdout = StringIO()
        with patch.object(sys, "argv", ["outrider", *argv]), redirect_stdout(stdout):
            status = cli.main()
        return status, stdout.getvalue()

    def _build_run(self, td):
        from outrider.benchmark.corpus import load_case
        from outrider.benchmark.run import run_case
        run_dir, _ = run_case(load_case(self.CASE), td)
        return str(run_dir)

    def test_orchestrate_run_requires_live(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._build_run(td)
            status, out = self.run_cli("orchestrate", "run", run, "--actor", "op")
            self.assertEqual(status, 2)
            self.assertIn("requires --live", out)

    def test_orchestrate_status_json(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._build_run(td)
            status, out = self.run_cli("orchestrate", "status", run, "--json")
            self.assertEqual(status, 0)
            payload = json.loads(out)
            self.assertGreaterEqual(payload["request_count"], 1)
            self.assertEqual(payload["invalid_result_count"], 0)

    def test_verify_candidates_json(self):
        with tempfile.TemporaryDirectory() as td:
            run = self._build_run(td)
            status, out = self.run_cli("verify", "candidates", run, "--json")
            self.assertEqual(status, 0)
            payload = json.loads(out)
            self.assertGreaterEqual(payload["summary"]["verdict_count"], 1)
            self.assertTrue(any(v["subject"] == "api.example.com" for v in payload["verdicts"]))

    def test_benchmark_run_tally_only_json(self):
        status, out = self.run_cli("benchmark", "run", "--tally-only", "--json")
        self.assertEqual(status, 0)
        totals = json.loads(out)["totals"]
        self.assertEqual(totals["promoted_findings_total"], 0)
        self.assertEqual(totals["schema_validity_rate"], 1.0)

    def test_benchmark_analyze_misses_json(self):
        status, out = self.run_cli("benchmark", "analyze-misses", "--json")
        self.assertEqual(status, 0)
        misses = json.loads(out)
        self.assertTrue(all(m["missing_discovered"] == [] for m in misses))


class BridgeCliTests(unittest.TestCase):
    def run_cli(self, *argv):
        stdout = StringIO()
        with patch.object(sys, "argv", ["outrider", *argv]), redirect_stdout(stdout):
            status = cli.main()
        return status, stdout.getvalue()

    def _legacy_source(self, root):
        src = Path(root) / "legacy" / "example-target"
        (src / "sub").mkdir(parents=True)
        (src / "memory.md").write_text("# notes\napi.example.com\n", encoding="utf-8")
        (src / "sub" / "recon.txt").write_text("recon data", encoding="utf-8")
        return src

    def test_import_target_registers_files_as_evidence_and_is_idempotent(self):
        from outrider import web_view
        with tempfile.TemporaryDirectory() as td:
            src = self._legacy_source(td)
            runs = Path(td) / "runs"
            status, out = self.run_cli(
                "import-target", str(src), "--target", "example.com", "--actor", "op",
                "--authorization-reference", "ROE-1", "--output-dir", str(runs),
            )
            self.assertEqual(status, 0)
            run_dir = runs / "example.com"
            self.assertTrue((run_dir / "manifest.json").is_file())
            ev = web_view.evidence_view(run_dir)
            paths = {r["relative_artifact_path"] for r in ev["records"]}
            self.assertEqual(ev["evidence_count"], 2)
            self.assertIn("artifacts/imported/memory.md", paths)
            self.assertIn("artifacts/imported/sub/recon.txt", paths)
            self.assertTrue(all(r["artifact_type"] == "legacy-import" for r in ev["records"]))
            # re-run: idempotent, nothing newly registered
            status2, _ = self.run_cli(
                "import-target", str(src), "--target", "example.com", "--actor", "op",
                "--authorization-reference", "ROE-1", "--output-dir", str(runs),
            )
            self.assertEqual(status2, 0)
            self.assertEqual(web_view.evidence_view(run_dir)["evidence_count"], 2)

    def test_import_target_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            src = self._legacy_source(td)
            runs = Path(td) / "runs"
            status, out = self.run_cli(
                "import-target", str(src), "--target", "example.com", "--actor", "op",
                "--authorization-reference", "ROE-1", "--output-dir", str(runs), "--dry-run",
            )
            self.assertEqual(status, 0)
            self.assertIn("[dry-run]", out)
            self.assertFalse((runs / "example.com").exists())

    def test_materialize_renders_view_and_never_clobbers_operator_files(self):
        from outrider import web_view
        from outrider.state import load_manifest
        with tempfile.TemporaryDirectory() as td:
            src = self._legacy_source(td)
            runs = Path(td) / "runs"
            targets = Path(td) / "targets"
            self.run_cli(
                "import-target", str(src), "--target", "example.com", "--actor", "op",
                "--authorization-reference", "ROE-1", "--output-dir", str(runs),
            )
            run_dir = runs / "example.com"
            status, _ = self.run_cli("materialize", str(run_dir), "--targets-root", str(targets))
            self.assertEqual(status, 0)
            out_file = targets / "example.com" / "OUTRIDER-RUN.md"
            body = out_file.read_text(encoding="utf-8")
            self.assertIn("Outrider engagement: example.com", body)
            self.assertIn("Registered evidence", body)
            self.assertIn("artifacts/imported/memory.md", body)
            # refuse to overwrite a non-generated file, allow with --force
            out_file.write_text("hand-written notes, no banner", encoding="utf-8")
            refuse, _ = self.run_cli("materialize", str(run_dir), "--targets-root", str(targets))
            self.assertEqual(refuse, 1)
            self.assertEqual(out_file.read_text(encoding="utf-8"), "hand-written notes, no banner")
            forced, _ = self.run_cli("materialize", str(run_dir), "--targets-root", str(targets), "--force")
            self.assertEqual(forced, 0)
            self.assertIn("Outrider engagement", out_file.read_text(encoding="utf-8"))
            # resolve by run_id too
            rid = load_manifest(run_dir).run_id
            by_id, _ = self.run_cli("materialize", rid, "--runs-root", str(runs), "--targets-root", str(targets))
            self.assertEqual(by_id, 0)

    def test_materialize_unknown_run_returns_error(self):
        with tempfile.TemporaryDirectory() as td:
            status, out = self.run_cli("materialize", "not-a-real-run", "--runs-root", str(td), "--targets-root", str(td))
            self.assertEqual(status, 1)
            self.assertIn("run not found", out)

    def test_parse_target_memory_extracts_labelled_fields_and_scoped_assets(self):
        from outrider import bridge
        mem = (
            "# Example — Testing Memory\n\n"
            "**Target:** Example (example.com)\n"
            "**Program:** HackerOne Public Bug Bounty\n"
            "**Researcher:** @op\n"
            "**Main Scope URL:** https://www.example.com/book/\n\n"
            "## In-Scope Assets\n\n"
            "| Asset | Type | Notes |\n|---|---|---|\n"
            "| https://www.example.com/book/ | URL | Primary |\n"
            "| https://www.example.com/account/cashback | URL | Also |\n\n"
            "### Known Related Domains\n\n"
            "| Domain | Purpose |\n|---|---|\n"
            "| *.related.example | related, NOT authorized scope |\n\n"
            "## High-Value Attack Surfaces\n1. booking flow\n"
        )
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "legacy"; src.mkdir()
            (src / "memory.md").write_text(mem, encoding="utf-8")
            s = bridge.parse_target_memory(src)
            # target is made consistent with the explicit in-scope host
            self.assertEqual(s["target"], "www.example.com")
            self.assertEqual(s["engagement_platform"], "HackerOne")
            self.assertEqual(s["actor"], "op")
            self.assertEqual(s["authorization_reference"], "HackerOne Public Bug Bounty")
            # URLs are reduced to their host and deduped (scope model is host-based)
            self.assertEqual(s["in_scope"], ["www.example.com"])
            # the nuanced "related domains" table must not be swept into scope
            self.assertNotIn("*.related.example", "\n".join(s["in_scope"]))
            # no memory.md -> {}
            empty = Path(td) / "empty"; empty.mkdir()
            self.assertEqual(bridge.parse_target_memory(empty), {})
            # malformed content -> never raises, returns at most partial
            bad = Path(td) / "bad"; bad.mkdir(); (bad / "memory.md").write_text("\x00 not a header", encoding="utf-8")
            self.assertIsInstance(bridge.parse_target_memory(bad), dict)
