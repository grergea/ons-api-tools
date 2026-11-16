"""Tests for pre-flight certificate identity checks and staged-cert gating."""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_workflow as wf

LIST_RAW = (
    "\n\033[92m[ACTIVE]\033[0m wildcard.example.com\n"
    "  Domains: live.example.com, cdn.example.com\n"
    "  Expires: 2026-11-30 08:59:59\n"
    "  Updated: 2026-05-15 21:01:50\n"
    "  Memo: old memo\n"
    "\n\033[90m[INACTIVE]\033[0m other.example.org\n"
    "  Domains: www.example.org\n"
    "  Expires: 2026-01-01 00:00:00\n"
)

INFO = {
    "subject_cn": "*.example.com",
    "san": ["*.example.com", "example.com"],
    "issuer_cn": "Test CA",
    "serial": "0A0B",
    "not_after": "May 27 23:59:59 2027 GMT",
    "fingerprint": "AA:BB",
}


class ParseListTests(unittest.TestCase):
    def test_extracts_domains_and_expiry_for_the_named_cert(self):
        entry = wf.parse_list_entry(LIST_RAW, "wildcard.example.com")

        self.assertEqual(entry["domains"], ["live.example.com", "cdn.example.com"])
        self.assertEqual(entry["expires"], "2026-11-30 08:59:59")

    def test_does_not_bleed_into_the_next_entry(self):
        entry = wf.parse_list_entry(LIST_RAW, "wildcard.example.com")

        self.assertNotIn("www.example.org", entry["domains"])

    def test_unknown_name_returns_none(self):
        self.assertIsNone(wf.parse_list_entry(LIST_RAW, "missing"))


class DomainCoverageTests(unittest.TestCase):
    def test_reports_domains_the_certificate_does_not_cover(self):
        uncovered = wf.uncovered_domains(INFO, ["live.example.com", "www.example.org"])

        self.assertEqual(uncovered, ["www.example.org"])

    def test_all_covered_returns_empty(self):
        self.assertEqual(wf.uncovered_domains(INFO, ["live.example.com"]), [])


class PreflightEmptyTargetTests(unittest.TestCase):
    def test_target_with_no_mapped_domains_is_not_reported_as_verified(self):
        info = {**INFO}
        with (
            mock.patch.object(wf, "describe_certificate", return_value=info),
            mock.patch.object(
                wf,
                "fetch_registered_entry",
                return_value={"domains": [], "expires": "x"},
            ),
            mock.patch.object(wf, "print_success") as ok,
            mock.patch.object(wf, "print_warning") as warn,
        ):
            result = wf.preflight_certificate("/c.pem", "t", {})

        self.assertTrue(result["success"])
        ok.assert_not_called()
        self.assertIn("could not be verified", warn.call_args.args[0])


class DefaultMemoTests(unittest.TestCase):
    def test_memo_comes_from_certificate_content(self):
        memo = wf.default_memo(INFO)

        self.assertIn("Test CA", memo)
        self.assertIn("0A0B", memo)
        self.assertIn("2027", memo)


class VerifyStagedGateTests(unittest.TestCase):
    def _run(self, **wait):
        base = {"found": True, "staging_ip": "192.0.2.1", "raw": "", "verifiable": True}
        with mock.patch.object(
            wf, "wait_for_staged_cert", return_value={**base, **wait}
        ):
            return wf.verify_staged_cert("x", {}, "/c.pem")

    def test_fingerprint_mismatch_stops_the_workflow(self):
        self.assertFalse(self._run(matched=False)["success"])

    def test_match_passes_and_is_reported(self):
        self.assertTrue(self._run(matched=True)["success"])

    def test_no_staging_node_is_not_a_failure(self):
        self.assertTrue(self._run(matched=False, verifiable=False)["success"])


if __name__ == "__main__":
    unittest.main()
