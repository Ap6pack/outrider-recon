"""Regression tests for the standalone secret_scan.py pattern catalog.

The scanner ships beside the offensive-osint skill rather than inside the
outrider package, so it is loaded by path instead of imported normally.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "skills"
    / "offensive-osint"
    / "scripts"
    / "secret_scan.py"
)


def _load_scanner():
    # Loading by path can otherwise reuse stale bytecode when an edit lands in
    # the same second and leaves the file the same size.
    importlib.invalidate_caches()
    spec = importlib.util.spec_from_file_location("secret_scan", SCRIPT)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


secret_scan = _load_scanner()


def patterns_for(text: str) -> set[str]:
    """Return the set of pattern names that fire on `text`."""
    return {hit["pattern"] for hit in secret_scan.scan_text(text)}


class SecretScanCatalogTest(unittest.TestCase):
    def test_script_exists(self):
        self.assertTrue(SCRIPT.is_file(), f"missing scanner at {SCRIPT}")

    def test_catalog_is_compiled(self):
        self.assertTrue(secret_scan.COMPILED, "pattern catalog is empty")
        self.assertEqual(len(secret_scan.COMPILED), len(secret_scan.PATTERNS))

    def test_aws_access_key(self):
        self.assertIn("AWS_ACCESS_KEY", patterns_for("AKIAIOSFODNN7EXAMPLE"))

    def test_jwt(self):
        token = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.assertIn("JWT", patterns_for(token))

    def test_github_classic_pat_exact_length_matches(self):
        # A GitHub classic PAT is ghp_ followed by exactly 36 characters.
        self.assertIn("GH_PAT_CLASSIC", patterns_for("ghp_" + "a" * 36))

    def test_github_oauth_token_exact_length_matches(self):
        self.assertIn("GH_OAUTH", patterns_for("gho_" + "a" * 36))

    def test_github_classic_pat_wrong_length_does_not_match(self):
        # Guards the CI fixture bug: the smoke-test fixture carried a 37-char
        # body, so GH_PAT_CLASSIC silently never fired and the test proved
        # nothing. Neither a short nor a long body may match.
        for body_length in (35, 37):
            with self.subTest(body_length=body_length):
                self.assertNotIn(
                    "GH_PAT_CLASSIC", patterns_for("ghp_" + "a" * body_length)
                )

    def test_hit_shape(self):
        hits = list(
            secret_scan.scan_text("AKIAIOSFODNN7EXAMPLE", source="fixture.txt")
        )
        self.assertTrue(hits)
        hit = hits[0]
        self.assertEqual(hit["pattern"], "AWS_ACCESS_KEY")
        self.assertEqual(hit["severity"], "critical")
        self.assertEqual(hit["category"], "aws")
        self.assertEqual(hit["source"], "fixture.txt")
        self.assertEqual(hit["line"], 1)

    def test_line_numbers_are_one_based(self):
        text = "nothing here\nAKIAIOSFODNN7EXAMPLE\n"
        hits = [h for h in secret_scan.scan_text(text) if h["pattern"] == "AWS_ACCESS_KEY"]
        self.assertEqual([h["line"] for h in hits], [2])

    def test_clean_text_yields_nothing(self):
        self.assertEqual(
            patterns_for("just some ordinary prose with no credentials in it"), set()
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
