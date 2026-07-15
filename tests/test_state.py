import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from outrider import cli
from outrider.state import (
    InvalidTransitionError,
    StateValidationError,
    bootstrap_legacy_run,
    load_manifest,
    load_state,
    state_revision,
    transition_state,
)


class StateTestCase(unittest.TestCase):
    def run_cli(self, *argv):
        stdout = StringIO()
        with patch.object(sys, "argv", ["outrider", *argv]), redirect_stdout(stdout):
            status = cli.main()
        return status, stdout.getvalue()

    def init_run(self, tmp, actor="authorized-operator"):
        status, _ = self.run_cli("init", "example.com", "--output-dir", tmp, "--actor", actor, "--authorization-reference", "EXAMPLE-ROE-001")
        self.assertEqual(status, 0)
        return Path(tmp) / "example.com"


class ManifestAndInitialEventTests(StateTestCase):
    def test_new_init_creates_valid_manifest_and_one_initial_event_and_rerun_preserves(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.init_run(tmp)
            manifest = load_manifest(run)
            self.assertEqual(manifest.schema_version, 1)
            self.assertEqual(UUID(manifest.run_id).version, 4)
            self.assertEqual(manifest.target, "example.com")
            self.assertIsNotNone(datetime.fromisoformat(manifest.created_at).tzinfo)
            self.assertEqual(manifest.created_by, "authorized-operator")
            self.assertEqual(manifest.authorization_reference, "EXAMPLE-ROE-001")
            events = [json.loads(line) for line in (run / "run.jsonl").read_text().splitlines()]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["schema_version"], 1)
            self.assertEqual(events[0]["sequence"], 1)
            self.assertEqual(events[0]["run_id"], manifest.run_id)
            self.assertEqual(UUID(events[0]["event_id"]).version, 4)
            self.assertEqual(load_state(run).current_state, "initialized")
            before_id = manifest.run_id
            self.run_cli("init", "example.com", "--output-dir", tmp, "--actor", "other")
            self.assertEqual(load_manifest(run).run_id, before_id)
            self.assertEqual(len((run / "run.jsonl").read_text().splitlines()), 1)

    def test_state_revision_hashes_exact_event_log_and_rejects_missing_or_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.init_run(tmp)
            expected = __import__('hashlib').sha256((run / 'run.jsonl').read_bytes()).hexdigest()
            self.assertEqual(state_revision(run), expected)
            before = state_revision(run)
            transition_state(run, 'scoped', 'authorized-operator')
            self.assertNotEqual(state_revision(run), before)
            data = (run / 'run.jsonl').read_bytes()
            (run / 'run.jsonl').write_bytes(data + b' ')
            self.assertEqual(state_revision(run), __import__('hashlib').sha256((run / 'run.jsonl').read_bytes()).hexdigest())
            (run / 'run.jsonl').unlink()
            with self.assertRaises(StateValidationError):
                state_revision(run)
            target = run / 'target.jsonl'; target.write_text('x')
            (run / 'run.jsonl').symlink_to(target)
            with self.assertRaises(StateValidationError):
                state_revision(run)

    def test_null_optional_metadata_accepted_and_bad_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            status, _ = self.run_cli("init", "example.com", "--output-dir", tmp)
            self.assertEqual(status, 0)
            run = Path(tmp) / "example.com"
            self.assertIsNone(load_manifest(run).created_by)
            data = json.loads((run / "manifest.json").read_text())
            bad_cases = [
                {**data, "scope_file": "/abs"},
                {**data, "event_log": "../run.jsonl"},
                {**data, "run_id": "not-a-uuid"},
                {**data, "created_at": "not-time"},
                {k: v for k, v in data.items() if k != "target"},
                {**data, "schema_version": "1"},
            ]
            for bad in bad_cases:
                (run / "manifest.json").write_text(json.dumps(bad))
                with self.assertRaises(StateValidationError):
                    load_manifest(run)
            (run / "manifest.json").write_text("{")
            with self.assertRaises(StateValidationError):
                load_manifest(run)


class TransitionTests(StateTestCase):
    def test_valid_chain_cancellation_backward_reason_and_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.init_run(tmp)
            self.assertEqual(transition_state(run, "scoped", "authorized-operator").current_state, "scoped")
            self.assertEqual(transition_state(run, "collecting", "authorized-operator").current_state, "collecting")
            self.assertEqual(transition_state(run, "analyzing", "authorized-operator").current_state, "analyzing")
            with self.assertRaises(InvalidTransitionError):
                transition_state(run, "collecting", "authorized-operator")
            self.assertEqual(transition_state(run, "collecting", "authorized-operator", "more collection").current_state, "collecting")
            self.assertEqual(transition_state(run, "cancelled", "authorized-operator", "operator stopped").current_state, "cancelled")
            self.assertEqual(transition_state(run, "archived", "authorized-operator").current_state, "archived")
            with self.assertRaises(InvalidTransitionError):
                transition_state(run, "completed", "authorized-operator")

    def test_rejections_do_not_append_and_scoped_validates_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.init_run(tmp)
            before = (run / "run.jsonl").read_text()
            with self.assertRaises(InvalidTransitionError):
                transition_state(run, "completed", "authorized-operator")
            self.assertEqual((run / "run.jsonl").read_text(), before)
            (run / "scope.yaml").write_text("in_scope: []\n")
            with self.assertRaises(StateValidationError):
                transition_state(run, "scoped", "authorized-operator")
            self.assertEqual((run / "run.jsonl").read_text(), before)
            (run / "scope.yaml").unlink()
            with self.assertRaises(StateValidationError):
                transition_state(run, "scoped", "authorized-operator")

    def test_completed_chain_and_previous_state_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.init_run(tmp)
            for state in ["scoped", "collecting", "analyzing", "reporting", "completed", "archived"]:
                transition_state(run, state, "authorized-operator")
            events = [json.loads(line) for line in (run / "run.jsonl").read_text().splitlines()]
            self.assertEqual([e["sequence"] for e in events], list(range(1, 8)))
            self.assertEqual(events[1]["previous_state"], "initialized")
            self.assertEqual(load_state(run).current_state, "archived")


class EventLogValidationTests(StateTestCase):
    def corrupt_event(self, run, edit):
        lines = (run / "run.jsonl").read_text().splitlines()
        event = json.loads(lines[-1])
        edit(event)
        lines[-1] = json.dumps(event)
        (run / "run.jsonl").write_text("\n".join(lines) + "\n")

    def test_malformed_duplicate_gap_mismatch_unknown_and_invalid_embedded_transition(self):
        edits = [
            lambda e: e.update(sequence=3),
            lambda e: e.update(run_id="00000000-0000-4000-8000-000000000000"),
            lambda e: e.update(occurred_at="bad"),
            lambda e: e.update(new_state="unknown"),
            lambda e: e.update(previous_state="scoped"),
        ]
        for edit in edits:
            with self.subTest(edit=edit), tempfile.TemporaryDirectory() as tmp:
                run = self.init_run(tmp)
                transition_state(run, "cancelled", "authorized-operator", "stop")
                self.corrupt_event(run, edit)
                with self.assertRaises(StateValidationError):
                    load_state(run)
        with tempfile.TemporaryDirectory() as tmp:
            run = self.init_run(tmp)
            line = (run / "run.jsonl").read_text().splitlines()[0]
            (run / "run.jsonl").write_text(line + "\nnot json\n")
            with self.assertRaises(StateValidationError):
                load_state(run)

    def test_duplicate_event_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.init_run(tmp)
            transition_state(run, "cancelled", "authorized-operator", "stop")
            lines = [json.loads(line) for line in (run / "run.jsonl").read_text().splitlines()]
            lines[1]["event_id"] = lines[0]["event_id"]
            (run / "run.jsonl").write_text("\n".join(json.dumps(e) for e in lines) + "\n")
            with self.assertRaises(StateValidationError):
                load_state(run)


class LegacyAndCliTests(StateTestCase):
    def test_bootstrap_preserves_legacy_lines_and_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "legacy"; run.mkdir()
            (run / "scope.yaml").write_text("in_scope:\n  - example.com\nout_of_scope: []\n")
            original = '{"event":"run_initialized","target":"example.com"}\n'
            (run / "run.jsonl").write_text(original)
            show_status, show_output = self.run_cli("state", "show", str(run))
            self.assertEqual(show_status, 0); self.assertIn("unavailable", show_output)
            status, output = self.run_cli("state", "bootstrap", str(run), "--target", "example.com", "--actor", "authorized-operator")
            self.assertEqual(status, 0); self.assertIn("preserved", output)
            self.assertTrue((run / "run.jsonl").read_text().startswith(original))
            self.assertEqual(load_state(run).legacy_event_count, 1)
            self.assertEqual(load_state(run).current_state, "initialized")
            self.assertEqual(self.run_cli("state", "bootstrap", str(run), "--target", "example.com", "--actor", "authorized-operator")[0], 1)
            self.assertEqual(self.run_cli("state", "show", str(run), "--json")[0], 0)

    def test_cli_transition_codes_and_no_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.init_run(tmp)
            ok, out = self.run_cli("state", "transition", str(run), "scoped", "--actor", "authorized-operator")
            self.assertEqual(ok, 0); self.assertIn("Run ID:", out)
            rejected, out = self.run_cli("state", "transition", str(run), "completed", "--actor", "authorized-operator")
            self.assertEqual(rejected, 1); self.assertNotIn("Traceback", out)
            (run / "run.jsonl").write_text("bad\n")
            malformed, out = self.run_cli("state", "show", str(run))
            self.assertEqual(malformed, 2); self.assertNotIn("Traceback", out)
            missing, _ = self.run_cli("state", "show", str(Path(tmp) / "missing"))
            self.assertEqual(missing, 2)

    def test_bootstrap_requires_valid_scope_actor_and_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "legacy"; run.mkdir()
            (run / "run.jsonl").write_text("{}\n")
            (run / "scope.yaml").write_text("in_scope: []\n")
            with self.assertRaises(Exception):
                bootstrap_legacy_run(run, "example.com", "authorized-operator")
            (run / "scope.yaml").write_text("in_scope:\n  - example.com\nout_of_scope: []\n")
            with self.assertRaises(StateValidationError):
                bootstrap_legacy_run(run, "", "authorized-operator")
            with self.assertRaises(StateValidationError):
                bootstrap_legacy_run(run, "example.com", "")


if __name__ == "__main__":
    unittest.main()
