import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from outrider.scope import (
    ScopeValidationError,
    evaluate_scope,
    load_scope,
    normalize_rule_key,
    normalize_target_host,
)


def write_scope(base, text):
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    (path / "scope.yaml").write_text(text, encoding="utf-8")
    return path


class ScopeLoadingTests(unittest.TestCase):
    def test_valid_generated_scope_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = write_scope(
                tmp,
                "target: example.com\nin_scope:\n  - example.com\nout_of_scope: []\nnotes:\n  - ignored\n",
            )
            config = load_scope(run)
            self.assertEqual(len(config.in_scope), 1)
            self.assertEqual(config.out_of_scope, ())

    def test_valid_manual_scope_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = write_scope(
                tmp,
                "in_scope: ['*.example.com', '192.0.2.0/24', '2001:db8::/32']\n"
                "out_of_scope: ['admin.example.com']\nboundary: ignored\n",
            )
            config = load_scope(run)
            self.assertEqual(len(config.in_scope), 3)
            self.assertEqual(len(config.out_of_scope), 1)

    def test_missing_scope_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ScopeValidationError, "not found"):
                load_scope(tmp)

    def test_malformed_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = write_scope(tmp, "in_scope: [example.com\n")
            with self.assertRaisesRegex(ScopeValidationError, "malformed YAML"):
                load_scope(run)

    def test_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = write_scope(tmp, "in_scope:\n  - example.com\nin_scope:\n  - other.example\n")
            with self.assertRaisesRegex(ScopeValidationError, "duplicate YAML key"):
                load_scope(run)

    def test_missing_and_empty_in_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = write_scope(tmp, "out_of_scope: []\n")
            with self.assertRaisesRegex(ScopeValidationError, "define in_scope"):
                load_scope(run)
        with tempfile.TemporaryDirectory() as tmp:
            run = write_scope(tmp, "in_scope: []\n")
            with self.assertRaisesRegex(ScopeValidationError, "must not be empty"):
                load_scope(run)

    def test_wrong_field_types_and_empty_rule(self):
        cases = [
            ("in_scope: example.com\n", "in_scope must be a list"),
            ("in_scope: [example.com]\nout_of_scope: none\n", "out_of_scope must be a list"),
            ("in_scope: [123]\n", "rules must be strings"),
            ("in_scope: ['']\n", "empty rule"),
        ]
        for text, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmp:
                run = write_scope(tmp, text)
                with self.assertRaisesRegex(ScopeValidationError, message):
                    load_scope(run)

    def test_invalid_rules(self):
        bad_rules = [
            "*",
            "api.*.example.com",
            "exa_mple.com",
            "192.0.2.999",
            "192.0.2.1/24",
            # URL/path rules are supported now, but these variants stay invalid:
            "ftp://example.com/x",              # unsupported scheme
            "https://example.com/x?a=b",        # query string
            "https://example.com/x#frag",       # fragment
            "https://user@example.com/x",       # embedded credentials
            "https://*.example.com/x",          # wildcard in host
            "example.com:99999/x",              # port out of range
            "example.com:abc/x",                # malformed port
        ]
        for rule in bad_rules:
            with self.subTest(rule=rule), tempfile.TemporaryDirectory() as tmp:
                run = write_scope(tmp, f"in_scope:\n  - {rule!r}\n")
                with self.assertRaises(ScopeValidationError):
                    load_scope(run)

    def test_valid_url_path_rules_load(self):
        for rule in [
            "www.example.com/book/",
            "https://www.example.com/account/cashback",
            "www.example.com/api/*/admin",
            "api.example.com:8443/v1",
            "api.example.com:8443",
            "https://www.example.com",
        ]:
            with self.subTest(rule=rule), tempfile.TemporaryDirectory() as tmp:
                run = write_scope(tmp, f"in_scope:\n  - {rule!r}\n")
                cfg = load_scope(run)
                self.assertEqual(cfg.in_scope[0].kind, "url")

    def test_legacy_none_and_new_empty_out_of_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = write_scope(tmp, "in_scope:\n  - example.com\nout_of_scope:\n  - none\n")
            self.assertEqual(load_scope(run).out_of_scope, ())
        with tempfile.TemporaryDirectory() as tmp:
            run = write_scope(tmp, "in_scope:\n  - example.com\nout_of_scope: []\n")
            self.assertEqual(load_scope(run).out_of_scope, ())


class ScopeDecisionTests(unittest.TestCase):
    def config(self, text):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run = write_scope(tmp.name, text)
        return load_scope(run)

    def test_domain_behavior(self):
        cfg = self.config("in_scope:\n  - example.com\n  - '*.example.com'\nout_of_scope: []\n")
        self.assertEqual(evaluate_scope(cfg, "example.com").decision, "allow")
        self.assertEqual(evaluate_scope(cfg, "api.example.com").decision, "allow")
        self.assertEqual(evaluate_scope(cfg, "EXAMPLE.COM.").normalized_candidate, "example.com")
        apex_only = self.config("in_scope:\n  - example.com\n")
        self.assertEqual(evaluate_scope(apex_only, "api.example.com").decision, "deny")
        wildcard_only = self.config("in_scope:\n  - '*.example.com'\n")
        self.assertEqual(evaluate_scope(wildcard_only, "api.example.com").decision, "allow")
        self.assertEqual(evaluate_scope(wildcard_only, "deeper.example.api.example.com").decision, "allow")
        self.assertEqual(evaluate_scope(wildcard_only, "example.com").decision, "deny")
        self.assertEqual(evaluate_scope(wildcard_only, "unrelated.example.net").decision, "deny")

    def test_exclusion_behavior(self):
        cfg = self.config(
            "in_scope:\n  - example.com\n  - '*.example.com'\n"
            "out_of_scope:\n  - example.com\n  - api.example.com\n  - '*.blocked.example.com'\n"
        )
        self.assertEqual(evaluate_scope(cfg, "example.com").decision, "deny")
        self.assertEqual(evaluate_scope(cfg, "api.example.com").matched_rule_source, "out_of_scope")
        self.assertEqual(evaluate_scope(cfg, "x.blocked.example.com").decision, "deny")
        self.assertEqual(evaluate_scope(cfg, "other.net").decision, "deny")

    def test_ip_behavior(self):
        cfg = self.config(
            "in_scope:\n  - 192.0.2.10\n  - 198.51.100.0/24\n"
            "  - 2001:db8::1\n  - 2001:db8:abcd::/48\n"
            "out_of_scope:\n  - 198.51.100.7\n"
        )
        self.assertEqual(evaluate_scope(cfg, "192.0.2.10").decision, "allow")
        self.assertEqual(evaluate_scope(cfg, "192.0.2.11").decision, "deny")
        self.assertEqual(evaluate_scope(cfg, "198.51.100.8").decision, "allow")
        self.assertEqual(evaluate_scope(cfg, "198.51.101.8").decision, "deny")
        self.assertEqual(evaluate_scope(cfg, "2001:db8::1").decision, "allow")
        self.assertEqual(evaluate_scope(cfg, "2001:db8:abcd::5").decision, "allow")
        self.assertEqual(evaluate_scope(cfg, "2001:db8:ffff::5").decision, "deny")
        self.assertEqual(evaluate_scope(cfg, "198.51.100.7").matched_rule_source, "out_of_scope")

    def test_url_behavior_and_no_network_request(self):
        cfg = self.config("in_scope:\n  - api.example.com\n  - 192.0.2.0/24\n")
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("network")):
            self.assertEqual(
                evaluate_scope(cfg, "https://api.example.com/path?q=1#frag").decision,
                "allow",
            )
            self.assertEqual(evaluate_scope(cfg, "https://192.0.2.3/path").decision, "allow")
        self.assertEqual(evaluate_scope(cfg, "https://user:pass@api.example.com/").decision, "error")
        self.assertEqual(evaluate_scope(cfg, "https:///missing-host").decision, "error")
        self.assertEqual(evaluate_scope(cfg, "api.example.com/path").decision, "error")
        self.assertEqual(evaluate_scope(cfg, "api.example.com:443").decision, "error")

    def test_url_path_scope_rules_matrix(self):
        cfg = self.config(
            "in_scope:\n"
            "  - www.example.com/book/\n"
            "  - www.example.com/account/cashback\n"
            "  - www.example.com/api/*/admin\n"
            "  - api.example.com:8443/v1\n"
            "  - example.net\n"
            "out_of_scope:\n"
            "  - www.example.com/admin\n"
        )
        allow = lambda c: self.assertEqual(evaluate_scope(cfg, c).decision, "allow", c)
        deny = lambda c: self.assertEqual(evaluate_scope(cfg, c).decision, "deny", c)
        # Reachability: a bare host that a URL rule references is in scope.
        allow("www.example.com")
        # Path prefix: /book covers /book/ and children; unlisted path denies.
        allow("https://www.example.com/book/x")
        allow("https://www.example.com/book")
        allow("https://www.example.com/account/cashback/2024")
        deny("https://www.example.com/private")
        # out_of_scope path wins over in-scope host reachability.
        deny("https://www.example.com/admin")
        deny("https://www.example.com/admin/panel")
        # Single-segment wildcard.
        allow("https://www.example.com/api/v2/admin")
        deny("https://www.example.com/api/v2/v3/admin")
        # host:port rule: matching port allows, default/other port denies.
        allow("https://api.example.com:8443/v1/thing")
        deny("https://api.example.com/v1/thing")
        # A plain domain rule covers every path/scheme on that host.
        allow("example.net")
        allow("https://example.net/anything")

    def test_url_rule_scheme_and_port_constraints(self):
        cfg = self.config("in_scope:\n  - https://secure.example.com/app\n")
        self.assertEqual(evaluate_scope(cfg, "https://secure.example.com/app/x").decision, "allow")
        self.assertEqual(evaluate_scope(cfg, "http://secure.example.com/app/x").decision, "deny")
        # A scheme-qualified rule still lets the bare host be reachable.
        self.assertEqual(evaluate_scope(cfg, "secure.example.com").decision, "allow")

    def test_url_rule_ip_candidate_never_matches(self):
        cfg = self.config("in_scope:\n  - www.example.com/book/\n")
        self.assertEqual(evaluate_scope(cfg, "https://203.0.113.5/book/").decision, "deny")

    def test_normalize_rule_key_url_dedup_and_target(self):
        # Scheme-agnostic and scheme-qualified same host+path collapse by host+path.
        self.assertEqual(
            normalize_rule_key("www.example.com/book/", "in_scope"),
            "url:*|www.example.com|*|/book/",
        )
        self.assertEqual(
            normalize_rule_key("https://api.example.com:8443/v1", "in_scope"),
            "url:https|api.example.com|8443|/v1",
        )
        self.assertNotEqual(
            normalize_rule_key("www.example.com/book/", "in_scope"),
            normalize_rule_key("www.example.com/admin", "in_scope"),
        )
        # A URL target reduces to its bare host; CIDR/port/path targets are rejected.
        self.assertEqual(normalize_target_host("https://www.example.com/book/"), "www.example.com")
        for bad in ["192.0.2.0/24", "*.example.com", "example.com:443", "example.com/path"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ScopeValidationError):
                    normalize_target_host(bad)


if __name__ == "__main__":
    unittest.main()
