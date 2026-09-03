from __future__ import annotations
import tempfile
import unittest
from pathlib import Path

from outrider.benchmark.corpus import load_case
from outrider.benchmark.run import run_case
from outrider.finding import list_finding_candidates, list_findings, promote_finding_by_ids
from outrider.state import transition_state
from outrider.verifier import (
    VERDICTS,
    deterministic_falsifier,
    list_verifications,
    verification_summary,
    verify_candidates,
)

ROOT = Path(__file__).resolve().parents[1]
CASE_A = ROOT / "outrider" / "benchmark" / "ground_truth" / "case-a-subdomain-swagger.json"


def _run_with_candidate(td):
    """Materialize case-a, which surfaces a finding_candidate for api.example.com."""
    run_dir, _ = run_case(load_case(CASE_A), td)
    return run_dir


def _api_candidate(run_dir):
    for cand in list_finding_candidates(run_dir)["candidates"]:
        if cand["subject"] == "api.example.com":
            return cand
    raise AssertionError("api.example.com finding_candidate not found")


class VerifierTests(unittest.TestCase):
    def test_supported_verdict_written_and_nothing_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            run = _run_with_candidate(td)
            findings_before = (run / "findings.jsonl").read_text(encoding="utf-8")
            verdicts = verify_candidates(run)
            self.assertTrue(verdicts)
            api = [v for v in verdicts if v.subject == "api.example.com"]
            self.assertEqual(len(api), 1)
            self.assertEqual(api[0].verdict, "supported")
            self.assertEqual(api[0].evidence_status, "verified")
            # Advisory only: findings registry is untouched.
            self.assertEqual((run / "findings.jsonl").read_text(encoding="utf-8"), findings_before)
            self.assertEqual(list_findings(run).finding_count, 0)
            # Verdicts are persisted and readable.
            persisted = list_verifications(run)
            self.assertEqual(len(persisted), len(verdicts))
            self.assertTrue(all(p["contract_type"] == "verification" for p in persisted))
            self.assertTrue(all(p["verdict"] in VERDICTS for p in persisted))
            summary = verification_summary(run)
            self.assertGreaterEqual(summary["counts"]["supported"], 1)

    def test_refuted_verdict_does_not_block_human_promotion(self):
        with tempfile.TemporaryDirectory() as td:
            run = _run_with_candidate(td)
            # An analyzer that refutes everything (as a strict LLM falsifier might).
            verdicts = verify_candidates(run, analyzer=lambda c: ("refuted", "independent falsifier rejected the claim"))
            self.assertTrue(all(v.verdict == "refuted" for v in verdicts))
            # The human reviewer can still promote the refuted candidate.
            transition_state(run, "collecting", "authorized-operator")
            transition_state(run, "analyzing", "authorized-operator")
            cand = _api_candidate(run)
            record = promote_finding_by_ids(
                run, cand["result_id"], cand["claim_id"],
                actor="authorized-operator", title="Exposed OpenAPI schema",
                candidate="api.example.com", severity="high", confidence="high",
                validation_basis="evidence_review", validation_reason="reviewer confirmed exposure",
                impact="schema discloses write endpoints", remediation="require auth on /openapi.json",
            )
            self.assertEqual(record.affected_candidate, "api.example.com")
            self.assertEqual(list_findings(run).finding_count, 1)

    def test_tampered_evidence_is_not_supported(self):
        with tempfile.TemporaryDirectory() as td:
            run = _run_with_candidate(td)
            # Tamper the cited artifact after registration; evidence now mismatches.
            (run / "artifacts" / "ct.txt").write_text("tampered contents", encoding="utf-8")
            verdicts = verify_candidates(run)
            api = [v for v in verdicts if v.subject == "api.example.com"][0]
            self.assertNotEqual(api.verdict, "supported")
            self.assertEqual(api.verdict, "refuted")
            self.assertEqual(api.evidence_status, "mismatch")

    def test_deterministic_falsifier_branches(self):
        self.assertEqual(deterministic_falsifier({"evidence_assessments": [{"verification_status": "verified"}], "subject_scope_decision": {"decision": "allow"}})[0], "supported")
        self.assertEqual(deterministic_falsifier({"evidence_assessments": [{"verification_status": "mismatch"}], "subject_scope_decision": {"decision": "allow"}})[0], "refuted")
        self.assertEqual(deterministic_falsifier({"evidence_assessments": [{"verification_status": "missing"}], "subject_scope_decision": {"decision": "allow"}})[0], "insufficient_evidence")
        self.assertEqual(deterministic_falsifier({"evidence_assessments": [{"verification_status": "verified"}], "subject_scope_decision": {"decision": "deny"}})[0], "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
