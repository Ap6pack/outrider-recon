import json, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from outrider.approval import *
from outrider.state import transition_state, load_manifest, load_state


class ApprovalTests(unittest.TestCase):
    def make_run(self):
        from outrider.cli import init_run
        import argparse

        tmp = tempfile.TemporaryDirectory()
        init_run(
            argparse.Namespace(
                target="example.com",
                output_dir=tmp.name,
                scope=["example.com", "*.example.com"],
                exclude=["blocked.example.com"],
                actor="authorized-operator",
                authorization_reference="EXAMPLE-ROE-001",
            )
        )
        run = Path(tmp.name) / "example.com"
        transition_state(run, "scoped", "authorized-operator")
        return tmp, run

    def test_scope_wide_active_authorization(self):
        tmp, run = self.make_run()
        self.addCleanup(tmp.cleanup)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # Before any grant, an active action on an in-scope candidate is denied.
        self.assertEqual(
            evaluate_action(run, "target_enumeration", "api.example.com", now=now).decision,
            "deny",
        )
        g = grant_approval(
            run, "target_enumeration", None, "authorized-operator",
            "Scope-wide active authorization at setup",
            duration_minutes=10080, scope_wide=True, now=now,
        )
        self.assertEqual(g.candidate, SCOPE_WIDE_CANDIDATE)
        self.assertEqual(g.candidate_type, SCOPE_WIDE_CANDIDATE_TYPE)
        self.assertEqual(g.status, "active")
        # Any in-scope candidate is authorized without a per-candidate grant.
        for cand in ("api.example.com", "deep.sub.example.com", "example.com"):
            d = evaluate_action(run, "target_enumeration", cand, now=now)
            self.assertEqual(d.decision, "allow", cand)
            self.assertEqual(d.matched_approval_id, g.approval_id)
            self.assertIn("scope-wide", d.reason)
        # Out-of-scope candidate is still denied; explicit exclusion too.
        self.assertEqual(evaluate_action(run, "target_enumeration", "evil.com", now=now).decision, "deny")
        self.assertEqual(evaluate_action(run, "target_enumeration", "blocked.example.com", now=now).decision, "deny")
        # A different active action type is not covered by this grant.
        self.assertEqual(evaluate_action(run, "target_read_only_request", "api.example.com", now=now).decision, "deny")
        # The grant survives a ledger reload and lists as scope-wide.
        summary = load_approval_registry(run, now)
        self.assertTrue(any(a.candidate_type == SCOPE_WIDE_CANDIDATE_TYPE and a.status == "active" for a in summary.approvals))
        # Revocation returns the loop to deny for active actions.
        revoke_approval(run, g.approval_id, "authorized-operator", "engagement complete", now=now)
        self.assertEqual(evaluate_action(run, "target_enumeration", "api.example.com", now=now).decision, "deny")

    def test_scope_wide_rejects_intrusive_and_duplicates(self):
        tmp, run = self.make_run()
        self.addCleanup(tmp.cleanup)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(ApprovalPolicyError):
            grant_approval(run, "intrusive_validation", None, "op", "no", duration_minutes=60, scope_wide=True, now=now)
        with self.assertRaises(ApprovalPolicyError):
            grant_approval(run, "public_source_lookup", None, "op", "no", duration_minutes=60, scope_wide=True, now=now)
        grant_approval(run, "target_enumeration", None, "op", "first", duration_minutes=60, scope_wide=True, now=now)
        with self.assertRaises(ApprovalPolicyError):
            grant_approval(run, "target_enumeration", None, "op", "dup", duration_minutes=60, scope_wide=True, now=now)

    def test_grant_list_revoke_and_decisions(self):
        tmp, run = self.make_run()
        self.addCleanup(tmp.cleanup)
        before_m = (run / "manifest.json").read_text()
        before_s = (run / "run.jsonl").read_text()
        before_e = (run / "evidence.jsonl").read_text()
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        g = grant_approval(
            run,
            "target_read_only_request",
            "HTTPS://API.EXAMPLE.COM/path",
            "authorized-operator",
            "Approved bounded read-only review",
            duration_minutes=60,
            conditions="No authentication attempts",
            now=now,
        )
        self.assertEqual(g.sequence, 1)
        self.assertEqual(UUID(g.approval_id).version, 4)
        self.assertEqual(g.candidate, "api.example.com")
        self.assertEqual(g.candidate_type, "domain")
        self.assertEqual(g.status, "active")
        self.assertEqual((run / "manifest.json").read_text(), before_m)
        self.assertEqual((run / "run.jsonl").read_text(), before_s)
        self.assertEqual((run / "evidence.jsonl").read_text(), before_e)
        self.assertEqual(
            evaluate_action(
                run, "target_read_only_request", "api.example.com", now=now
            ).decision,
            "allow",
        )
        self.assertEqual(
            evaluate_action(
                run, "target_read_only_request", "x.api.example.com", now=now
            ).decision,
            "deny",
        )
        self.assertEqual(
            evaluate_action(
                run, "target_read_only_request", "blocked.example.com", now=now
            ).decision,
            "deny",
        )
        self.assertEqual(
            evaluate_action(
                run, "target_enumeration", "api.example.com", now=now
            ).decision,
            "deny",
        )
        ev = revoke_approval(
            run,
            g.approval_id,
            "authorized-operator",
            "Approval withdrawn",
            now=now + timedelta(minutes=1),
        )
        self.assertEqual(ev.event_type, "approval_revoked")
        self.assertEqual(
            list_approvals(run, now + timedelta(minutes=2)).approvals[0].status,
            "revoked",
        )
        self.assertEqual(
            evaluate_action(
                run,
                "target_read_only_request",
                "api.example.com",
                now=now + timedelta(minutes=2),
            ).decision,
            "deny",
        )
        g2 = grant_approval(
            run,
            "target_read_only_request",
            "api.example.com",
            "authorized-operator",
            "again",
            duration_minutes=1,
            now=now + timedelta(minutes=3),
        )
        self.assertEqual(
            list_approvals(run, now + timedelta(minutes=5)).approvals[-1].status,
            "expired",
        )
        self.assertEqual(
            evaluate_action(run, "local_analysis", now=now).decision, "allow"
        )
        self.assertEqual(
            evaluate_action(
                run, "public_source_lookup", "api.example.com", now=now
            ).decision,
            "allow",
        )
        for a in PROHIBITED:
            self.assertEqual(
                evaluate_action(run, a, "api.example.com", now=now).decision, "deny"
            )
            with self.assertRaises(ApprovalPolicyError):
                grant_approval(
                    run,
                    a,
                    "api.example.com",
                    "authorized-operator",
                    "x",
                    duration_minutes=1,
                    now=now,
                )

    def test_validation_and_missing_registry(self):
        tmp, run = self.make_run()
        self.addCleanup(tmp.cleanup)
        (run / "approvals.jsonl").unlink()
        self.assertEqual(list_approvals(run).approval_count, 0)
        with self.assertRaises(ApprovalPolicyError):
            grant_approval(
                run,
                "local_analysis",
                "api.example.com",
                "authorized-operator",
                "x",
                duration_minutes=1,
            )
        with self.assertRaises(ApprovalValidationError):
            grant_approval(
                run,
                "target_read_only_request",
                "http://u:p@api.example.com",
                "authorized-operator",
                "x",
                duration_minutes=1,
            )
        g = grant_approval(
            run,
            "target_read_only_request",
            "api.example.com",
            "authorized-operator",
            "x",
            duration_minutes=1,
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        with self.assertRaises(ApprovalPolicyError):
            grant_approval(
                run,
                "target_read_only_request",
                "api.example.com",
                "authorized-operator",
                "x",
                duration_minutes=1,
                now=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
        with self.assertRaises(ApprovalPolicyError):
            revoke_approval(
                run,
                g.approval_id,
                "authorized-operator",
                "too late",
                now=datetime(2026, 1, 2, tzinfo=timezone.utc),
            )
        (run / "approvals.jsonl").write_text("{bad\n")
        with self.assertRaises(ApprovalValidationError):
            list_approvals(run)

    def test_state_restrictions_and_scope_changes(self):
        tmp, run = self.make_run()
        self.addCleanup(tmp.cleanup)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        g = grant_approval(
            run,
            "target_read_only_request",
            "api.example.com",
            "authorized-operator",
            "x",
            duration_minutes=60,
            now=now,
        )
        (run / "scope.yaml").write_text(
            "in_scope:\n  - example.com\nout_of_scope: []\n"
        )
        self.assertEqual(
            evaluate_action(
                run, "target_read_only_request", "api.example.com", now=now
            ).decision,
            "deny",
        )
        self.assertEqual((run / "approvals.jsonl").read_text().count("\n"), 1)

    def test_revision_and_policy_catalog_metadata(self):
        tmp, run = self.make_run()
        self.addCleanup(tmp.cleanup)
        import hashlib

        empty = approval_revision(run)
        self.assertEqual(empty, hashlib.sha256(b"").hexdigest())
        (run / "approvals.jsonl").unlink()
        self.assertEqual(approval_revision(run), empty)
        self.assertFalse((run / "approvals.jsonl").exists())

        catalog = approval_policy_catalog()
        self.assertEqual([row["action_type"] for row in catalog], sorted(ACTION_TYPES))
        self.assertEqual(len(catalog), len(ACTION_TYPES))
        by_action = {row["action_type"]: row for row in catalog}
        for action_type in ACTION_TYPES:
            self.assertEqual(by_action[action_type]["action_class"], action_class(action_type))
            self.assertEqual(by_action[action_type]["grantable"], action_type in APPROVABLE)
            self.assertEqual(by_action[action_type]["approval_required"], action_type in APPROVABLE)
            self.assertEqual(by_action[action_type]["permanently_prohibited"], action_type in PROHIBITED)
            self.assertEqual(by_action[action_type]["allowed_states"], sorted(ALLOWED_STATES.get(action_type, [])))
        self.assertFalse(by_action["local_analysis"]["candidate_required"])
        self.assertTrue(by_action["target_enumeration"]["candidate_required"])

        before = approval_revision(run)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        first = grant_approval(run, "target_enumeration", "api.example.com", "authorized-operator", "x", duration_minutes=1, now=now)
        after_grant = approval_revision(run)
        self.assertNotEqual(before, after_grant)
        self.assertEqual(list_approvals(run, now + timedelta(days=1)).approvals[0].status, "expired")
        self.assertEqual(approval_revision(run), after_grant)
        second = grant_approval(run, "target_enumeration", "other.example.com", "authorized-operator", "x", duration_minutes=10, now=now)
        before_revoke = approval_revision(run)
        revoke_approval(run, second.approval_id, "authorized-operator", "closed", now=now + timedelta(minutes=1))
        self.assertNotEqual(approval_revision(run), before_revoke)


if __name__ == "__main__":
    unittest.main()
