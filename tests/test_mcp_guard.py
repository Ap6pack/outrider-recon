import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest import mock

from outrider.approval import grant_approval, revoke_approval
from outrider.mcp_guard import TOOL_POLICIES, authorize_mcp_tool, normalize_domain_candidate
from outrider.state import initialize_state, transition_state


def make_run(root, target="example.com", scopes=("example.com",), exclusions=()):
    run = Path(root) / target.replace("*", "wild")
    run.mkdir()
    in_scope = "".join(f"  - {json.dumps(item)}\n" for item in scopes)
    out_scope = "".join(f"  - {json.dumps(item)}\n" for item in exclusions) or " []\n"
    (run / "scope.yaml").write_text(f"in_scope:\n{in_scope}out_of_scope:\n{out_scope}", encoding="utf-8")
    initialize_state(run, target, actor="authorized-operator", authorization_reference="EXAMPLE-ROE-001")
    return run


class MCPGuardTests(unittest.TestCase):
    def scoped(self, run):
        transition_state(run, "scoped", actor="authorized-operator")

    def test_policy_mappings_are_fixed_and_safe(self):
        self.assertEqual(set(TOOL_POLICIES), {"crtsh_lookup", "hudsonrock_lookup", "wayback_urls", "dns_records", "epss_score"})
        self.assertEqual(TOOL_POLICIES["crtsh_lookup"].action_type, "public_source_lookup")
        self.assertEqual(TOOL_POLICIES["hudsonrock_lookup"].action_type, "public_source_lookup")
        self.assertEqual(TOOL_POLICIES["wayback_urls"].action_type, "public_source_lookup")
        self.assertEqual(TOOL_POLICIES["epss_score"].action_type, "public_source_lookup")
        self.assertEqual(TOOL_POLICIES["dns_records"].action_type, "target_enumeration")
        self.assertEqual(TOOL_POLICIES["epss_score"].candidate_source, "manifest_target")
        self.assertFalse(any(p.action_type in {"intrusive_validation", "credential_abuse"} for p in TOOL_POLICIES.values()))

    def test_unknown_tool_and_bad_run_are_policy_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(authorize_mcp_tool("unknown", tmp, domain="example.com").decision, "error")
            missing = authorize_mcp_tool("crtsh_lookup", Path(tmp) / "missing", domain="example.com")
            self.assertEqual(missing.decision, "error")
            self.assertIn("manifest.json", missing.reason)
            bad = Path(tmp) / "bad"; bad.mkdir(); (bad / "manifest.json").write_text("{bad", encoding="utf-8")
            self.assertEqual(authorize_mcp_tool("crtsh_lookup", bad, domain="example.com").decision, "error")

    def test_valid_run_returns_run_id_and_evaluates_state_each_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp)
            denied = authorize_mcp_tool("crtsh_lookup", run, domain="example.com")
            self.assertEqual(denied.decision, "deny")
            self.assertEqual(denied.workflow_state, "initialized")
            self.scoped(run)
            allowed = authorize_mcp_tool("crtsh_lookup", run, domain="example.com")
            self.assertEqual(allowed.decision, "allow")
            self.assertIsNotNone(allowed.run_id)
            self.assertEqual(allowed.normalized_policy_candidate, "example.com")

    def test_workflow_states_for_passive_and_dns(self):
        for state, expected in [("scoped", "allow"), ("collecting", "allow"), ("analyzing", "allow"), ("reporting", "allow")]:
            with self.subTest(state=state):
                with tempfile.TemporaryDirectory() as tmp:
                    run = make_run(tmp)
                    transition_state(run, "scoped", actor="authorized-operator")
                    if state == "collecting": transition_state(run, "collecting", actor="authorized-operator")
                    if state == "analyzing": transition_state(run, "collecting", actor="authorized-operator"); transition_state(run, "analyzing", actor="authorized-operator")
                    if state == "reporting": transition_state(run, "collecting", actor="authorized-operator"); transition_state(run, "analyzing", actor="authorized-operator"); transition_state(run, "reporting", actor="authorized-operator")
                    self.assertEqual(authorize_mcp_tool("crtsh_lookup", run, domain="example.com").decision, expected)
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp); self.scoped(run)
            grant_approval(run, "target_enumeration", "example.com", "authorized-operator", "ok", duration_minutes=60)
            self.assertEqual(authorize_mcp_tool("dns_records", run, domain="example.com").decision, "allow")

    def test_scope_rules_and_no_dns_for_scope(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("socket.getaddrinfo", side_effect=AssertionError("dns used")):
            run = make_run(tmp, scopes=("*.example.com",), exclusions=("blocked.example.com",))
            self.scoped(run)
            self.assertEqual(authorize_mcp_tool("crtsh_lookup", run, domain="api.example.com").decision, "allow")
            self.assertEqual(authorize_mcp_tool("crtsh_lookup", run, domain="example.com").decision, "deny")
            self.assertEqual(authorize_mcp_tool("crtsh_lookup", run, domain="blocked.example.com").decision, "deny")

    def test_scope_changes_are_not_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp); self.scoped(run)
            self.assertEqual(authorize_mcp_tool("crtsh_lookup", run, domain="example.com").decision, "allow")
            (run / "scope.yaml").write_text("in_scope:\n  - other.example\nout_of_scope:\n  - example.com\n", encoding="utf-8")
            self.assertEqual(authorize_mcp_tool("crtsh_lookup", run, domain="example.com").decision, "deny")

    def test_domain_safety(self):
        self.assertEqual(normalize_domain_candidate(" Example.COM. "), "example.com")
        for value in ["https://example.com", "example.com/a", "example.com?q", "example.com#x", "u@example.com", "example.com:443", "*.example.com", "127.0.0.1", "bad..com", ""]:
            with self.subTest(value=value):
                with self.assertRaises(Exception):
                    normalize_domain_candidate(value)

    def test_epss_uses_manifest_target_not_cve(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, target="example.com", scopes=("example.com",)); self.scoped(run)
            decision = authorize_mcp_tool("epss_score", run)
            self.assertEqual(decision.decision, "allow")
            self.assertEqual(decision.normalized_policy_candidate, "example.com")

    def test_dns_requires_exact_active_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, scopes=("example.com", "*.example.com")); self.scoped(run)
            self.assertEqual(authorize_mcp_tool("dns_records", run, domain="api.example.com").decision, "deny")
            grant_approval(run, "target_enumeration", "example.com", "authorized-operator", "parent", duration_minutes=60)
            self.assertEqual(authorize_mcp_tool("dns_records", run, domain="api.example.com").decision, "deny")
            approval = grant_approval(run, "target_enumeration", "api.example.com", "authorized-operator", "exact", duration_minutes=60)
            self.assertEqual(authorize_mcp_tool("dns_records", run, domain="api.example.com").decision, "allow")
            revoke_approval(run, approval.approval_id, "authorized-operator", "done")
            self.assertEqual(authorize_mcp_tool("dns_records", run, domain="api.example.com").decision, "deny")

    def test_malformed_approval_registry_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp); self.scoped(run); (run / "approvals.jsonl").write_text("not json\n", encoding="utf-8")
            self.assertEqual(authorize_mcp_tool("dns_records", run, domain="example.com").decision, "error")


if __name__ == "__main__":
    unittest.main()
