from __future__ import annotations
import tempfile, unittest
from pathlib import Path

from outrider.cli import init_run
from outrider.state import transition_state, state_revision
from outrider.evidence import register_evidence
from outrider.approval import grant_approval
from outrider.finding import list_finding_candidates, list_findings
from outrider.executors import StubExecutor, ResultScript, ExecutorError, TransientExecutorError
from outrider.skill_contract import create_skill_request
from outrider.orchestrator import (
    run_orchestration,
    orchestration_status,
    OrchestrationBounds,
    SeedRequest,
    _mark_inflight,
    _inflight_ids,
)


class Args:
    pass


def make_run(td):
    a = Args()
    a.target = "example.com"; a.output_dir = str(td); a.scope = ["example.com", "*.example.com"]
    a.exclude = []; a.actor = "authorized-operator"; a.authorization_reference = "EXAMPLE-ROE-001"
    init_run(a)
    return Path(td) / "example.com"


def _seed(evidence_id, *, recommend):
    """Seed ('*') script: an observation plus recommended next actions."""
    return ResultScript(
        status="completed",
        summary="seed analysis",
        claims=[{
            "classification": "observation", "subject": "example.com",
            "statement": "root observed", "confidence": "high",
            "suggested_severity": None, "evidence_ids": [evidence_id],
        }],
        recommended_actions=recommend,
    )


def _candidate_script(evidence_id):
    """api.example.com script: a finding_candidate + only handoff/active recs."""
    return ResultScript(
        status="completed",
        summary="candidate analysis",
        claims=[{
            "classification": "finding_candidate", "subject": "api.example.com",
            "statement": "exposed API schema", "confidence": "high",
            "suggested_severity": "medium", "evidence_ids": [evidence_id],
        }],
        recommended_actions=[
            {"action_type": "target_enumeration", "candidate": "api.example.com", "priority": "high", "reason": "enumerate"},
            {"action_type": "intrusive_validation", "candidate": "api.example.com", "priority": "high", "reason": "exploit"},
        ],
    )


class OrchestratorLoopTests(unittest.TestCase):
    def _prepare(self, td):
        run = make_run(td)
        transition_state(run, "scoped", "authorized-operator")
        (run / "artifacts" / "out.txt").write_text("crt api.example.com", encoding="utf-8")
        ev = register_evidence(run, "artifacts/out.txt", "authorized-operator", "text")
        return run, ev.evidence_id

    def test_loop_reaches_finding_candidate_without_promoting(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            scripts = {
                "*": _seed(ev, recommend=[
                    {"action_type": "public_source_lookup", "candidate": "api.example.com", "priority": "medium", "reason": "lookup"},
                    {"action_type": "target_enumeration", "candidate": "api.example.com", "priority": "high", "reason": "enum"},
                    {"action_type": "intrusive_validation", "candidate": "api.example.com", "priority": "high", "reason": "exploit"},
                ]),
                "api.example.com": _candidate_script(ev),
            }
            report = run_orchestration(
                run, executor=StubExecutor(scripts), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")],
            )
            self.assertEqual(report.stop_reason, "quiescent")
            self.assertEqual(report.hops, 2)                 # seed + public_source_lookup hop
            self.assertEqual(report.requests_created, 2)     # seed + 1 auto-dispatched passive hop
            self.assertEqual(report.results_valid, 2)
            self.assertEqual(report.results_invalid, 0)
            # ACTIVE without approval and INTRUSIVE are deferred, never dispatched.
            reasons = {(d["action_type"]) for d in report.deferred}
            self.assertIn("target_enumeration", reasons)
            self.assertIn("intrusive_validation", reasons)
            self.assertTrue(any("handoff_only" in d["reason"] for d in report.deferred if d["action_type"] == "intrusive_validation"))
            # The loop surfaced a finding_candidate but promoted nothing.
            self.assertEqual(list_findings(run).finding_count, 0)
            self.assertEqual((run / "findings.jsonl").read_text(encoding="utf-8"), "")
            cands = list_finding_candidates(run)
            self.assertGreaterEqual(cands["candidate_count"], 1)

    def test_active_hop_dispatched_only_after_approval(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            scripts = {"*": _seed(ev, recommend=[
                {"action_type": "target_enumeration", "candidate": "api.example.com", "priority": "high", "reason": "enum"},
            ])}
            # Without approval: the ACTIVE hop is deferred.
            report = run_orchestration(
                run, executor=StubExecutor(scripts), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")],
            )
            self.assertEqual(report.requests_created, 1)      # seed only
            self.assertTrue(any(d["action_type"] == "target_enumeration" for d in report.deferred))

        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            grant_approval(run, "target_enumeration", "api.example.com", "authorized-operator", "authorized", duration_minutes=30)
            scripts = {
                "*": _seed(ev, recommend=[
                    {"action_type": "target_enumeration", "candidate": "api.example.com", "priority": "high", "reason": "enum"},
                ]),
                "api.example.com": ResultScript(status="completed", summary="enum done", claims=[{
                    "classification": "observation", "subject": "api.example.com",
                    "statement": "enumerated", "confidence": "medium", "suggested_severity": None,
                    "evidence_ids": [ev]}]),
            }
            report = run_orchestration(
                run, executor=StubExecutor(scripts), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")],
            )
            # With a standing approval the ACTIVE hop is now dispatched.
            self.assertEqual(report.requests_created, 2)
            self.assertTrue(any(e.get("event") == "result_valid" for e in report.log))
            self.assertFalse(any(d["action_type"] == "target_enumeration" for d in report.deferred))

    def test_scope_wide_grant_dispatches_active_hop_unattended(self):
        # A scope-wide active authorization lets the loop enumerate a newly
        # discovered in-scope candidate that was never individually approved.
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            grant_approval(run, "target_enumeration", None, "authorized-operator", "scope-wide at setup", duration_minutes=10080, scope_wide=True)
            scripts = {
                "*": _seed(ev, recommend=[
                    {"action_type": "target_enumeration", "candidate": "api.example.com", "priority": "high", "reason": "enum"},
                ]),
                "api.example.com": ResultScript(status="completed", summary="enum done", claims=[{
                    "classification": "observation", "subject": "api.example.com",
                    "statement": "enumerated", "confidence": "medium", "suggested_severity": None,
                    "evidence_ids": [ev]}]),
            }
            report = run_orchestration(
                run, executor=StubExecutor(scripts), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")],
            )
            self.assertEqual(report.requests_created, 2)  # seed + unattended active hop
            self.assertFalse(any(d["action_type"] == "target_enumeration" for d in report.deferred))
            # Intrusive is still handoff-only even under a scope-wide active grant.
            self.assertEqual(list_findings(run).finding_count, 0)

    def test_transient_executor_error_is_an_executor_error(self):
        self.assertTrue(issubclass(TransientExecutorError, ExecutorError))

    def test_transient_failure_is_retried_then_succeeds(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)

            class Flaky(StubExecutor):
                fails = 2
                def run(self, run_dir, request):
                    if self.fails:
                        self.fails -= 1
                        raise TransientExecutorError("timeout")
                    return super().run(run_dir, request)

            report = run_orchestration(
                run, executor=Flaky({"*": _seed(ev, recommend=[])}), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")],
                bounds=OrchestrationBounds(max_transient_retries=2, retry_backoff_seconds=0.0),
            )
            self.assertEqual(report.transient_retries, 2)
            self.assertEqual(report.results_valid, 1)
            self.assertEqual(report.stop_reason, "quiescent")
            self.assertEqual(_inflight_ids(run), set())  # marker cleared on success

    def test_exhausted_transient_triggers_passive_replan(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)

            class SeedTransient(StubExecutor):
                def run(self, run_dir, request):
                    if request.requested_action.get("action_type") == "local_analysis":
                        raise TransientExecutorError("always down")
                    return super().run(run_dir, request)

            report = run_orchestration(
                run, executor=SeedTransient({"*": _seed(ev, recommend=[])}), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed", candidate="api.example.com")],
                bounds=OrchestrationBounds(max_transient_retries=1, retry_backoff_seconds=0.0),
            )
            self.assertEqual(report.transient_retries, 1)
            self.assertEqual(report.replanned, 1)
            self.assertTrue(any(e["event"] == "replanned" for e in report.log))
            self.assertEqual(_inflight_ids(run), set())

    def test_permanent_failure_triggers_passive_replan(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)

            class SeedFails(StubExecutor):
                def run(self, run_dir, request):
                    if request.requested_action.get("action_type") == "local_analysis":
                        raise ExecutorError("boom")
                    return super().run(run_dir, request)

            report = run_orchestration(
                run, executor=SeedFails({"*": _seed(ev, recommend=[])}), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed", candidate="api.example.com")],
            )
            self.assertEqual(report.replanned, 1)
            events = [e["event"] for e in report.log]
            self.assertEqual(events, ["executor_failed", "replanned", "result_valid"])  # fallback lookup ran and validated

    def test_invalid_result_triggers_passive_replan(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            # The seed candidate's script cites an unregistered evidence id -> invalid result;
            # the fallback public_source_lookup on the same candidate has no such problem.
            scripts = {
                "*": _seed(ev, recommend=[]),  # seed (local_analysis) is fine
            }

            class SeedInvalid(StubExecutor):
                def run(self, run_dir, request):
                    if request.requested_action.get("action_type") == "local_analysis":
                        payload_script = ResultScript(status="completed", summary="bad", claims=[{
                            "classification": "observation", "subject": "api.example.com",
                            "statement": "cites missing evidence", "confidence": "high",
                            "suggested_severity": None, "evidence_ids": ["00000000-0000-4000-8000-000000000000"]}])
                        from outrider.executors import build_result_payload, _write_result_atomic
                        return _write_result_atomic(Path(run_dir), build_result_payload(
                            run_dir, request, status=payload_script.status, summary=payload_script.summary,
                            claims=payload_script.claims))
                    return super().run(run_dir, request)

            report = run_orchestration(
                run, executor=SeedInvalid(scripts), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed", candidate="api.example.com")],
            )
            self.assertEqual(report.results_invalid, 1)
            self.assertEqual(report.replanned, 1)

    def test_interrupted_active_hop_is_deferred_on_resume(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            # A standing approval lets us create an active request that then "crashed" mid-flight.
            grant_approval(run, "target_enumeration", "api.example.com", "authorized-operator", "auth", duration_minutes=60)
            req, _path, _cid = create_skill_request(run, "offensive-osint", "authorized-operator", "enum", "target_enumeration", "api.example.com", [], 100, None)
            _mark_inflight(run, req.request_id)  # simulate crash after dispatch, before result
            report = run_orchestration(run, executor=StubExecutor({"*": _seed(ev, recommend=[])}), actor="authorized-operator")
            # The interrupted ACTIVE request is deferred for human review, never re-dispatched.
            self.assertEqual(report.hops, 0)
            self.assertTrue(any(i["action_type"] == "target_enumeration" for i in report.interrupted))
            self.assertTrue(any(d.get("reason", "").startswith("interrupted") for d in report.deferred))
            self.assertEqual(_inflight_ids(run), set())  # stale marker cleared

    def test_resume_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            scripts = {
                "*": _seed(ev, recommend=[
                    {"action_type": "public_source_lookup", "candidate": "api.example.com", "priority": "medium", "reason": "lookup"},
                ]),
                "api.example.com": _candidate_script(ev),
            }
            seeds = [SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")]
            first = run_orchestration(run, executor=StubExecutor(scripts), actor="authorized-operator", seeds=seeds)
            self.assertEqual(first.requests_created, 2)
            # Re-running with the same seeds must create nothing new and run no hops.
            second = run_orchestration(run, executor=StubExecutor(scripts), actor="authorized-operator", seeds=seeds)
            self.assertEqual(second.requests_created, 0)
            self.assertEqual(second.hops, 0)
            self.assertEqual(second.stop_reason, "quiescent")

    def test_external_state_change_halts_loop(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)

            class TransitioningExecutor(StubExecutor):
                def run(self, run_dir, request):
                    path = super().run(run_dir, request)
                    # Simulate a concurrent external state transition.
                    transition_state(run_dir, "collecting", "someone-else")
                    return path

            scripts = {"*": _seed(ev, recommend=[
                {"action_type": "public_source_lookup", "candidate": "api.example.com", "priority": "medium", "reason": "lookup"},
            ])}
            report = run_orchestration(
                run, executor=TransitioningExecutor(scripts), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")],
            )
            self.assertEqual(report.stop_reason, "external_state_change")
            self.assertEqual(report.hops, 1)

    def test_status_reports_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            scripts = {"*": _seed(ev, recommend=[])}
            run_orchestration(
                run, executor=StubExecutor(scripts), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")],
            )
            status = orchestration_status(run)
            self.assertEqual(status["current_state"], "scoped")
            self.assertEqual(status["request_count"], 1)
            self.assertEqual(status["result_count"], 1)
            self.assertEqual(status["valid_result_count"], 1)
            self.assertEqual(status["pending_request_count"], 0)

    def test_bounds_cap_hops(self):
        with tempfile.TemporaryDirectory() as td:
            run, ev = self._prepare(td)
            # Seed recommends a passive lookup; cap max_hops at 1 so only the seed runs.
            scripts = {
                "*": _seed(ev, recommend=[
                    {"action_type": "public_source_lookup", "candidate": "api.example.com", "priority": "medium", "reason": "lookup"},
                ]),
                "api.example.com": _candidate_script(ev),
            }
            report = run_orchestration(
                run, executor=StubExecutor(scripts), actor="authorized-operator",
                seeds=[SeedRequest(skill="offensive-osint", action_type="local_analysis", objective="seed")],
                bounds=OrchestrationBounds(max_hops=1),
            )
            self.assertEqual(report.hops, 1)
            self.assertEqual(report.stop_reason, "max_hops")


if __name__ == "__main__":
    unittest.main()
