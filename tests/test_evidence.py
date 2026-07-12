import hashlib
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from uuid import UUID

from outrider.cli import init_run
from argparse import Namespace
from outrider.evidence import EvidenceRegistrationError, EvidenceValidationError, load_evidence_registry, register_evidence, verify_all_evidence, verify_evidence
from outrider.state import load_manifest, load_state, transition_state


class EvidenceTests(unittest.TestCase):
    def make_run(self):
        tmp = tempfile.TemporaryDirectory()
        init_run(Namespace(target="example.com", output_dir=tmp.name, scope=None, exclude=None, actor="authorized-operator", authorization_reference="EXAMPLE-ROE-001"))
        return tmp, Path(tmp.name) / "example.com"

    def artifact(self, run_dir, name="artifacts/http/homepage-response.txt", data=b"HTTP/1.1 200 OK\n"):
        path = run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_init_storage_rerun_preserves_registry_artifacts_manifest_and_state(self):
        tmp, run_dir = self.make_run()
        with tmp:
            self.assertTrue((run_dir / "evidence.jsonl").is_file())
            self.assertEqual((run_dir / "evidence.jsonl").read_text(), "")
            self.assertTrue((run_dir / "artifacts").is_dir())
            manifest_id = load_manifest(run_dir).run_id
            events_before = (run_dir / "run.jsonl").read_text()
            (run_dir / "evidence.jsonl").write_text('{"keep":true}\n')
            self.artifact(run_dir, "artifacts/keep.txt", b"keep")
            init_run(Namespace(target="example.com", output_dir=tmp.name, scope=None, exclude=None, actor=None, authorization_reference=None))
            self.assertEqual((run_dir / "evidence.jsonl").read_text(), '{"keep":true}\n')
            self.assertEqual((run_dir / "artifacts/keep.txt").read_bytes(), b"keep")
            self.assertEqual(load_manifest(run_dir).run_id, manifest_id)
            self.assertEqual((run_dir / "run.jsonl").read_text(), events_before)
            (run_dir / "evidence.jsonl").unlink()
            init_run(Namespace(target="example.com", output_dir=tmp.name, scope=None, exclude=None, actor=None, authorization_reference=None))
            self.assertTrue((run_dir / "evidence.jsonl").exists())
            self.assertEqual((run_dir / "run.jsonl").read_text(), events_before)

    def test_register_text_binary_sequences_fields_and_no_state_or_manifest_change(self):
        tmp, run_dir = self.make_run()
        with tmp:
            text = self.artifact(run_dir)
            binary = self.artifact(run_dir, "artifacts/bin/blob.bin", b"\x00\xff\x01")
            manifest_before = (run_dir / "manifest.json").read_text()
            state_before = (run_dir / "run.jsonl").read_text()
            r1 = register_evidence(run_dir, "artifacts/http/homepage-response.txt", "authorized-operator", "http-response", "text/plain", "manual-capture", "Initial response snapshot")
            r2 = register_evidence(run_dir, "artifacts/bin/blob.bin", "authorized-operator", "other")
            self.assertEqual(r1.sequence, 1); self.assertEqual(r2.sequence, 2)
            self.assertEqual(UUID(r1.evidence_id).version, 4)
            self.assertEqual(r1.run_id, load_manifest(run_dir).run_id)
            self.assertIsNotNone(datetime.fromisoformat(r1.registered_at).tzinfo)
            self.assertEqual(r1.actor, "authorized-operator"); self.assertEqual(r1.artifact_type, "http-response")
            self.assertEqual(r1.media_type, "text/plain"); self.assertEqual(r1.source, "manual-capture"); self.assertEqual(r1.note, "Initial response snapshot")
            self.assertEqual(r1.sha256, hashlib.sha256(text.read_bytes()).hexdigest())
            self.assertEqual(r1.size_bytes, len(text.read_bytes()))
            self.assertEqual(r2.sha256, hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual(len((run_dir / "evidence.jsonl").read_text().splitlines()), 2)
            for line in (run_dir / "evidence.jsonl").read_text().splitlines():
                self.assertIsInstance(json.loads(line), dict)
            self.assertEqual((run_dir / "manifest.json").read_text(), manifest_before)
            self.assertEqual((run_dir / "run.jsonl").read_text(), state_before)
            self.assertEqual(load_state(run_dir).current_state, "initialized")

    def test_reject_archived_duplicate_and_failed_registration_appends_nothing(self):
        tmp, run_dir = self.make_run()
        with tmp:
            self.artifact(run_dir)
            register_evidence(run_dir, "artifacts/http/homepage-response.txt", "authorized-operator", "http-response")
            before = (run_dir / "evidence.jsonl").read_text()
            with self.assertRaises(EvidenceRegistrationError):
                register_evidence(run_dir, "artifacts/http/homepage-response.txt", "authorized-operator", "http-response")
            self.assertEqual((run_dir / "evidence.jsonl").read_text(), before)
            transition_state(run_dir, "scoped", "authorized-operator")
            transition_state(run_dir, "collecting", "authorized-operator")
            transition_state(run_dir, "analyzing", "authorized-operator")
            transition_state(run_dir, "reporting", "authorized-operator")
            transition_state(run_dir, "completed", "authorized-operator")
            transition_state(run_dir, "archived", "authorized-operator")
            self.artifact(run_dir, "artifacts/http/other.txt", b"x")
            with self.assertRaises(EvidenceRegistrationError):
                register_evidence(run_dir, "artifacts/http/other.txt", "authorized-operator", "http-response")
            self.assertEqual((run_dir / "evidence.jsonl").read_text(), before)

    def test_registry_validation_rejects_malformed_records(self):
        tmp, run_dir = self.make_run()
        with tmp:
            self.artifact(run_dir)
            r = register_evidence(run_dir, "artifacts/http/homepage-response.txt", "authorized-operator", "http-response")
            good = r.to_dict()
            cases = [
                "{bad", "[]", json.dumps({**good, "sequence": 2}), json.dumps({**good, "run_id": "00000000-0000-4000-8000-000000000000"}),
                json.dumps({**good, "evidence_id": "bad"}), json.dumps({**good, "evidence_id": "00000000-0000-1000-8000-000000000000"}),
                json.dumps({**good, "registered_at": "not-date"}), json.dumps({**good, "artifact_type": "HTTP"}), json.dumps({**good, "artifact_type": "-bad"}),
                json.dumps({**good, "sha256": "A"*64}), json.dumps({**good, "sha256": "0"*63}), json.dumps({**good, "size_bytes": -1}),
                json.dumps({**good, "event_type": "other"}), json.dumps({k:v for k,v in good.items() if k != "actor"}), json.dumps({**good, "actor": 7}),
            ]
            for payload in cases:
                with self.subTest(payload=payload[:30]):
                    (run_dir / "evidence.jsonl").write_text(payload + "\n")
                    with self.assertRaises(EvidenceValidationError):
                        load_evidence_registry(run_dir)
            (run_dir / "evidence.jsonl").write_text(json.dumps(good)+"\n\n")
            with self.assertRaises(EvidenceValidationError): load_evidence_registry(run_dir)
            other = {**good, "sequence": 2}
            (run_dir / "evidence.jsonl").write_text(json.dumps(good)+"\n"+json.dumps(other)+"\n")
            with self.assertRaises(EvidenceValidationError): load_evidence_registry(run_dir)
            other = {**good, "sequence": 2, "evidence_id": "00000000-0000-4000-8000-000000000000"}
            (run_dir / "evidence.jsonl").write_text(json.dumps(good)+"\n"+json.dumps(other)+"\n")
            with self.assertRaises(EvidenceValidationError): load_evidence_registry(run_dir)

    def test_path_safety_and_normalization(self):
        tmp, run_dir = self.make_run()
        with tmp:
            self.artifact(run_dir)
            before = (run_dir / "evidence.jsonl").read_text()
            invalid = ["/tmp/x", "../outside.txt", "artifacts/../../outside.txt", "manifest.json", "run.jsonl", "scope.yaml", "evidence.jsonl", "artifacts/missing.txt", "artifacts"]
            for path in invalid:
                with self.subTest(path=path):
                    with self.assertRaises(EvidenceValidationError): register_evidence(run_dir, path, "authorized-operator", "http-response")
            (run_dir / "artifacts/dir").mkdir()
            with self.assertRaises(EvidenceValidationError): register_evidence(run_dir, "artifacts/dir", "authorized-operator", "http-response")
            os.symlink(run_dir / "artifacts/http/homepage-response.txt", run_dir / "artifacts/link.txt")
            with self.assertRaises(EvidenceValidationError): register_evidence(run_dir, "artifacts/link.txt", "authorized-operator", "http-response")
            outside = Path(tmp.name) / "outside"; outside.mkdir(); (outside / "x.txt").write_text("x")
            os.symlink(outside, run_dir / "artifacts/symdir")
            with self.assertRaises(EvidenceValidationError): register_evidence(run_dir, "artifacts/symdir/x.txt", "authorized-operator", "http-response")
            fifo = run_dir / "artifacts/fifo"; os.mkfifo(fifo)
            with self.assertRaises(EvidenceValidationError): register_evidence(run_dir, "artifacts/fifo", "authorized-operator", "http-response")
            self.assertEqual((run_dir / "evidence.jsonl").read_text(), before)
            r = register_evidence(run_dir, "artifacts/http/homepage-response.txt", "authorized-operator", "http-response")
            self.assertEqual(r.path, "artifacts/http/homepage-response.txt")

    def test_verification_statuses_selection_read_only_archived_empty(self):
        tmp, run_dir = self.make_run()
        with tmp:
            a = self.artifact(run_dir, "artifacts/a.txt", b"a")
            b = self.artifact(run_dir, "artifacts/b.txt", b"bb")
            r1 = register_evidence(run_dir, "artifacts/a.txt", "authorized-operator", "other")
            r2 = register_evidence(run_dir, "artifacts/b.txt", "authorized-operator", "other")
            ev_before = (run_dir / "evidence.jsonl").read_text(); state_before = (run_dir / "run.jsonl").read_text()
            self.assertEqual(verify_evidence(run_dir, r1.evidence_id).status, "verified")
            b.write_bytes(b"changed")
            results = verify_all_evidence(run_dir)
            self.assertEqual([x.status for x in results], ["verified", "mismatch"])
            self.assertEqual(verify_evidence(run_dir, r2.evidence_id).actual_size, len(b"changed"))
            a.unlink()
            self.assertEqual(verify_evidence(run_dir, r1.evidence_id).status, "missing")
            b.unlink(); os.symlink(run_dir / "artifacts/a.txt", b)
            self.assertEqual(verify_evidence(run_dir, r2.evidence_id).status, "unsafe")
            self.assertEqual(verify_evidence(run_dir, "00000000-0000-4000-8000-000000000000").status, "missing")
            self.assertEqual((run_dir / "evidence.jsonl").read_text(), ev_before)
            self.assertEqual((run_dir / "run.jsonl").read_text(), state_before)
            empty_tmp, empty_run = self.make_run()
            with empty_tmp:
                self.assertEqual(verify_all_evidence(empty_run), ())
            transition_state(run_dir, "scoped", "authorized-operator")
            transition_state(run_dir, "collecting", "authorized-operator")
            transition_state(run_dir, "analyzing", "authorized-operator")
            transition_state(run_dir, "reporting", "authorized-operator")
            transition_state(run_dir, "completed", "authorized-operator")
            transition_state(run_dir, "archived", "authorized-operator")
            self.assertTrue(verify_all_evidence(run_dir))

if __name__ == "__main__":
    unittest.main()
