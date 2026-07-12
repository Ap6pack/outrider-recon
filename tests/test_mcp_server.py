import asyncio
import importlib.util
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from outrider.approval import grant_approval, revoke_approval
from outrider.state import initialize_state, transition_state

try:
    import httpx  # noqa: F401
except ModuleNotFoundError:
    import types

    httpx_stub = types.ModuleType("httpx")

    class TimeoutException(Exception):
        pass

    class HTTPStatusError(Exception):
        def __init__(self, message="", request=None, response=None):
            super().__init__(message)
            self.request = request
            self.response = response

    class Timeout:
        def __init__(self, *_args, **_kwargs):
            pass

    class AsyncClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("httpx.AsyncClient must be mocked in MCP server tests")

    httpx_stub.TimeoutException = TimeoutException
    httpx_stub.HTTPStatusError = HTTPStatusError
    httpx_stub.Timeout = Timeout
    httpx_stub.AsyncClient = AsyncClient
    sys.modules["httpx"] = httpx_stub

SERVER_PATH = Path(__file__).resolve().parents[1] / "mcp-server" / "server.py"
spec = importlib.util.spec_from_file_location("outrider_mcp_server_test", SERVER_PATH)
server = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = server
spec.loader.exec_module(server)  # type: ignore[union-attr]


def run_async(coro):
    return asyncio.run(coro)


def make_run(root, target="example.com", scopes=("example.com",), exclusions=()):
    run = Path(root) / target.replace(".", "_")
    run.mkdir()
    in_scope = "".join(f"  - {json.dumps(item)}\n" for item in scopes)
    out_scope = "".join(f"  - {json.dumps(item)}\n" for item in exclusions) or " []\n"
    (run / "scope.yaml").write_text(
        f"in_scope:\n{in_scope}out_of_scope:\n{out_scope}", encoding="utf-8"
    )
    initialize_state(
        run,
        target,
        actor="authorized-operator",
        authorization_reference="EXAMPLE-ROE-001",
    )
    return run


def snapshot(run):
    data = {}
    for name in [
        "manifest.json",
        "scope.yaml",
        "run.jsonl",
        "evidence.jsonl",
        "approvals.jsonl",
    ]:
        p = run / name
        data[name] = p.read_text(encoding="utf-8") if p.exists() else None
    artifacts = run / "artifacts"
    data["artifacts"] = (
        sorted(str(p.relative_to(run)) for p in artifacts.rglob("*") if p.is_file())
        if artifacts.exists()
        else []
    )
    return data


class MCPServerTests(unittest.TestCase):
    def scoped_run(self, tmp, **kwargs):
        run = make_run(tmp, **kwargs)
        transition_state(run, "scoped", actor="authorized-operator")
        return run

    def assert_envelope(self, resp, tool):
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp["tool"], tool)
        for key in ["ok", "policy", "result", "error", "scope_note"]:
            self.assertIn(key, resp)
        self.assertIn("do not expand", resp["scope_note"])

    def test_tool_registration_signatures(self):
        tools = {
            name: getattr(server, name)
            for name in [
                "crtsh_lookup",
                "hudsonrock_lookup",
                "epss_score",
                "wayback_urls",
                "dns_records",
            ]
        }
        self.assertEqual(
            set(tools),
            {
                "crtsh_lookup",
                "hudsonrock_lookup",
                "epss_score",
                "wayback_urls",
                "dns_records",
            },
        )
        for name, func in tools.items():
            params = inspect.signature(func).parameters
            self.assertIn("run_dir", params)
            self.assertEqual(params["run_dir"].default, inspect._empty)
            self.assertNotIn("action_type", params)
            self.assertNotIn("skip_policy", params)
            self.assertNotIn("unsafe", params)

    def test_passive_tools_guard_before_upstream_and_success(self):
        helpers = {
            "crtsh_lookup": (
                server.crtsh_lookup,
                "_crtsh_raw",
                [{"common_name": "example.com"}],
            ),
            "hudsonrock_lookup": (
                server.hudsonrock_lookup,
                "_hudsonrock_raw",
                {"domain": "example.com"},
            ),
            "wayback_urls": (
                server.wayback_urls,
                "_wayback_raw",
                [{"url": "https://example.com/"}],
            ),
        }
        for tool, (func, helper, result) in helpers.items():
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as tmp:
                run = self.scoped_run(tmp)
                calls = []

                async def fake(*args):
                    calls.append(args)
                    return result

                with mock.patch.object(server, helper, side_effect=fake):
                    resp = run_async(func(str(run), " EXAMPLE.com. "))
                self.assert_envelope(resp, tool)
                self.assertTrue(resp["ok"])
                self.assertEqual(resp["policy"]["decision"], "allow")
                self.assertEqual(resp["result"], result)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][0], "example.com")

    def test_denied_and_policy_error_zero_upstream_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp)  # initialized denies passive
            with mock.patch.object(server, "_crtsh_raw") as fake:
                resp = run_async(server.crtsh_lookup(str(run), "example.com"))
            self.assertEqual(resp["error"]["code"], "policy_denied")
            fake.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(server, "_crtsh_raw") as fake:
                resp = run_async(
                    server.crtsh_lookup(str(Path(tmp) / "missing"), "example.com")
                )
            self.assertEqual(resp["error"]["code"], "policy_error")
            self.assertNotIn(str(tmp), json.dumps(resp))
            fake.assert_not_called()

    def test_http_upstream_error_codes_and_no_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.scoped_run(tmp)

            async def timeout(_domain):
                raise server.httpx.TimeoutException("t")

            with mock.patch.object(server, "_crtsh_raw", side_effect=timeout):
                resp = run_async(server.crtsh_lookup(str(run), "example.com"))
            self.assertEqual(resp["error"]["code"], "upstream_timeout")

            async def bad(_domain):
                raise ValueError("Unexpected response format from crt.sh")

            with mock.patch.object(server, "_crtsh_raw", side_effect=bad):
                resp = run_async(server.crtsh_lookup(str(run), "example.com"))
            self.assertEqual(resp["error"]["code"], "unexpected_response")
            self.assertNotIn("Traceback", json.dumps(resp))

    def test_epss_cve_validation_and_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.scoped_run(tmp)
            calls = []

            async def fake(cve):
                calls.append(cve)
                return {"cve": cve, "epss": 0.1, "percentile": 0.2}

            with mock.patch.object(server, "_epss_raw", side_effect=fake):
                resp = run_async(server.epss_score(str(run), "cve-2024-1234"))
            self.assertTrue(resp["ok"])
            self.assertEqual(resp["result"]["cve"], "CVE-2024-1234")
            self.assertEqual(calls, ["CVE-2024-1234"])
            with mock.patch.object(server, "_epss_raw") as fake2:
                bad = run_async(server.epss_score(str(run), "bad/CVE-2024-1234"))
            self.assertEqual(bad["error"]["code"], "invalid_input")
            fake2.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp)
            with mock.patch.object(server, "_epss_raw") as fake:
                denied = run_async(server.epss_score(str(run), "CVE-2024-1234"))
            self.assertEqual(denied["error"]["code"], "policy_denied")
            fake.assert_not_called()

    def test_wayback_limit_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.scoped_run(tmp)

            async def fake(domain, limit):
                return [{"limit": str(limit), "domain": domain}]

            for limit in [1, 100, 10000]:
                with mock.patch.object(server, "_wayback_raw", side_effect=fake) as m:
                    resp = run_async(
                        server.wayback_urls(str(run), "example.com", limit=limit)
                    )
                self.assertTrue(resp["ok"])
                self.assertEqual(m.call_args.args[1], limit)
            for limit in [0, -1, 10001, "5", 1.5, True]:
                with mock.patch.object(server, "_wayback_raw") as m:
                    resp = run_async(
                        server.wayback_urls(str(run), "example.com", limit=limit)
                    )
                self.assertEqual(resp["error"]["code"], "invalid_input")
                m.assert_not_called()

    def test_dns_policy_and_guarded_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.scoped_run(tmp, scopes=("example.com", "*.example.com"))
            with mock.patch.object(server, "_dns_records_raw") as resolver:
                denied = server.dns_records(str(run), "api.example.com")
            self.assertEqual(denied["error"]["code"], "policy_denied")
            resolver.assert_not_called()
            approval = grant_approval(
                run,
                "target_enumeration",
                "api.example.com",
                "authorized-operator",
                "Approved bounded DNS enumeration",
                duration_minutes=60,
            )
            order = []

            def fake(domain):
                order.append(("resolver", domain))
                return {"domain": domain, "records": {"A": ["192.0.2.10"]}}

            with mock.patch.object(server, "_dns_records_raw", side_effect=fake):
                allowed = server.dns_records(str(run), " API.example.com. ")
            self.assertTrue(allowed["ok"])
            self.assertEqual(order, [("resolver", "api.example.com")])
            revoke_approval(run, approval.approval_id, "authorized-operator", "done")
            with mock.patch.object(server, "_dns_records_raw") as resolver2:
                revoked = server.dns_records(str(run), "api.example.com")
            self.assertEqual(revoked["error"]["code"], "policy_denied")
            resolver2.assert_not_called()

    def test_input_errors_zero_upstream_or_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.scoped_run(tmp)
            with mock.patch.object(server, "_crtsh_raw") as http:
                resp = run_async(server.crtsh_lookup(str(run), "https://example.com"))
            self.assertEqual(resp["error"]["code"], "policy_error")
            http.assert_not_called()
            with mock.patch.object(server, "_dns_records_raw") as dns:
                resp = server.dns_records(str(run), "127.0.0.1")
            self.assertEqual(resp["error"]["code"], "policy_error")
            dns.assert_not_called()

    def test_no_control_file_side_effects_for_allowed_denied_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.scoped_run(tmp)
            before = snapshot(run)

            async def fake(_domain):
                return []

            with mock.patch.object(server, "_crtsh_raw", side_effect=fake):
                run_async(server.crtsh_lookup(str(run), "example.com"))
            with mock.patch.object(server, "_crtsh_raw") as m:
                run_async(server.crtsh_lookup(str(run), "other.example"))
            after = snapshot(run)
            self.assertEqual(before, after)
            m.assert_not_called()

    def test_demonstration_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, scopes=("example.com", "api.example.com"))
            transition_state(run, "scoped", actor="authorized-operator")
            base = snapshot(run)
            http_calls = []

            async def crt(domain):
                http_calls.append(domain)
                return [{"name_value": domain}]

            with mock.patch.object(server, "_crtsh_raw", side_effect=crt):
                allow = run_async(server.crtsh_lookup(str(run), "example.com"))
            self.assertTrue(allow["ok"])
            self.assertEqual(http_calls, ["example.com"])
            http_calls.clear()
            with mock.patch.object(server, "_crtsh_raw", side_effect=crt):
                deny = run_async(server.crtsh_lookup(str(run), "out.example"))
            self.assertFalse(deny["ok"])
            self.assertEqual(http_calls, [])
            init = make_run(
                tmp, target="initialized.example.com", scopes=("example.com",)
            )
            with mock.patch.object(server, "_crtsh_raw", side_effect=crt):
                init_deny = run_async(server.crtsh_lookup(str(init), "example.com"))
            self.assertEqual(init_deny["policy"]["decision"], "deny")
            self.assertEqual(http_calls, [])
            dns_calls = []

            def dns(domain):
                dns_calls.append(domain)
                return {"domain": domain, "records": {"A": ["192.0.2.10"]}}

            with mock.patch.object(server, "_dns_records_raw", side_effect=dns):
                dns_deny = server.dns_records(str(run), "api.example.com")
            self.assertFalse(dns_deny["ok"])
            self.assertEqual(dns_calls, [])
            approval = grant_approval(
                run,
                "target_enumeration",
                "api.example.com",
                "authorized-operator",
                "Approved bounded DNS enumeration",
                duration_minutes=60,
            )
            with mock.patch.object(server, "_dns_records_raw", side_effect=dns):
                dns_allow = server.dns_records(str(run), "api.example.com")
            self.assertTrue(dns_allow["ok"])
            self.assertEqual(dns_calls, ["api.example.com"])
            dns_calls.clear()
            revoke_approval(run, approval.approval_id, "authorized-operator", "done")
            with mock.patch.object(server, "_dns_records_raw", side_effect=dns):
                self.assertFalse(server.dns_records(str(run), "api.example.com")["ok"])
            self.assertEqual(dns_calls, [])
            (run / "scope.yaml").write_text(
                "in_scope:\n  - example.com\nout_of_scope:\n  - api.example.com\n",
                encoding="utf-8",
            )
            with mock.patch.object(server, "_dns_records_raw", side_effect=dns):
                self.assertFalse(server.dns_records(str(run), "api.example.com")["ok"])
            self.assertEqual(dns_calls, [])
            (run / "scope.yaml").write_text(base["scope.yaml"], encoding="utf-8")
            epss_calls = []

            async def epss(cve):
                epss_calls.append(cve)
                return {"cve": cve, "epss": 0.1, "percentile": 0.2}

            with mock.patch.object(server, "_epss_raw", side_effect=epss):
                self.assertTrue(
                    run_async(server.epss_score(str(run), "CVE-2024-1234"))["ok"]
                )
                bad = run_async(server.epss_score(str(run), "EXAMPLE-ROE-001"))
            self.assertEqual(bad["error"]["code"], "invalid_input")
            self.assertEqual(epss_calls, ["CVE-2024-1234"])


if __name__ == "__main__":
    unittest.main()
