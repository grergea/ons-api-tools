"""Tests for waiting until the staging node serves the certificate just uploaded."""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_workflow as wf

MATCH_RAW = "  Fingerprint Comparison: \033[92mMATCH\033[0m\n  [VALID - 194 days]"
MISMATCH_RAW = "  Fingerprint Comparison: \033[91mMISMATCH\033[0m\n  [EXPIRED]"


def _lookup(raw):
    return {"found": True, "staging_ip": "192.0.2.1", "raw": raw}


class WaitForStagedCertTests(unittest.TestCase):
    def test_returns_immediately_when_fingerprint_matches(self):
        with (
            mock.patch.object(
                wf, "lookup_cert", return_value=_lookup(MATCH_RAW)
            ) as lookup,
            mock.patch.object(wf.time, "sleep") as sleep,
        ):
            result = wf.wait_for_staged_cert("x", {}, "/local.pem")

        self.assertTrue(result["matched"])
        self.assertEqual(lookup.call_count, 1)
        sleep.assert_not_called()

    def test_retries_while_stale_cert_is_served_then_matches(self):
        replies = [_lookup(MISMATCH_RAW), _lookup(MISMATCH_RAW), _lookup(MATCH_RAW)]
        with (
            mock.patch.object(wf, "lookup_cert", side_effect=replies) as lookup,
            mock.patch.object(wf.time, "sleep") as sleep,
        ):
            result = wf.wait_for_staged_cert("x", {}, "/local.pem")

        self.assertTrue(result["matched"])
        self.assertEqual(lookup.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_gives_up_after_max_attempts_and_reports_last_raw(self):
        with (
            mock.patch.object(
                wf, "lookup_cert", return_value=_lookup(MISMATCH_RAW)
            ) as lookup,
            mock.patch.object(wf.time, "sleep"),
        ):
            result = wf.wait_for_staged_cert("x", {}, "/local.pem")

        self.assertFalse(result["matched"])
        self.assertEqual(lookup.call_count, wf._STAGED_CERT_MAX_ATTEMPTS)
        self.assertEqual(result["raw"], MISMATCH_RAW)

    def test_lookup_failure_is_not_a_match(self):
        with (
            mock.patch.object(
                wf, "lookup_cert", return_value={"found": False, "staging_ip": None}
            ),
            mock.patch.object(wf.time, "sleep"),
        ):
            result = wf.wait_for_staged_cert("x", {}, "/local.pem")

        self.assertFalse(result["matched"])
        self.assertFalse(result["found"])

    def test_no_staging_node_is_unverifiable_and_not_retried(self):
        raw = "Staging Server IP: N/A\nDeploy Status: Deployed"
        reply = {"found": True, "staging_ip": "N/A", "raw": raw}
        with (
            mock.patch.object(wf, "lookup_cert", return_value=reply) as lookup,
            mock.patch.object(wf.time, "sleep") as sleep,
        ):
            result = wf.wait_for_staged_cert("x", {}, "/local.pem")

        self.assertFalse(result["matched"])
        self.assertFalse(result["verifiable"])
        self.assertEqual(lookup.call_count, 1)
        sleep.assert_not_called()

    def test_passes_local_cert_to_lookup(self):
        with mock.patch.object(
            wf, "lookup_cert", return_value=_lookup(MATCH_RAW)
        ) as lookup:
            wf.wait_for_staged_cert("x", {"id": "a"}, "/local.pem")

        self.assertEqual(lookup.call_args.kwargs.get("local_cert"), "/local.pem")


if __name__ == "__main__":
    unittest.main()
