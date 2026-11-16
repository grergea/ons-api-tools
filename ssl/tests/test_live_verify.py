"""Tests for live_verify: which certificate do the edge IPs actually serve."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import live_verify as lv

FP_NEW = "AA:BB"
FP_OLD = "CC:DD"


class ParseDigTests(unittest.TestCase):
    def test_keeps_only_ip_literals_and_drops_cnames(self):
        out = "kr-live.example.com.\nlive.example.com.cdn.net.\n192.0.2.1\n192.0.2.2\n"

        self.assertEqual(lv.parse_dig(out), ["192.0.2.1", "192.0.2.2"])

    def test_accepts_ipv6_and_drops_error_text(self):
        out = "2001:db8::1\n;; connection timed out; no servers could be reached\n"

        self.assertEqual(lv.parse_dig(out), ["2001:db8::1"])


class VerifyHostTests(unittest.TestCase):
    def _verify(self, served, **kw):
        return lv.verify_host(
            "live.example.com",
            FP_NEW,
            ips=sorted(served),
            fetch=lambda ip, host: served[ip],
            **kw,
        )

    def test_all_ips_serving_the_new_cert_pass(self):
        result = self._verify({"192.0.2.1": FP_NEW, "192.0.2.2": FP_NEW})

        self.assertTrue(result["ok"])
        self.assertEqual((result["matched"], result["total"]), (2, 2))

    def test_one_stale_ip_fails_and_is_named(self):
        result = self._verify({"192.0.2.1": FP_NEW, "192.0.2.2": FP_OLD})

        self.assertFalse(result["ok"])
        self.assertEqual(result["mismatched"], {"192.0.2.2": FP_OLD})

    def test_unreachable_ip_is_reported_separately_from_mismatch(self):
        result = self._verify({"192.0.2.1": FP_NEW, "192.0.2.2": None})

        self.assertFalse(result["ok"])
        self.assertEqual(result["unreachable"], ["192.0.2.2"])
        self.assertEqual(result["mismatched"], {})

    def test_no_resolved_ips_is_a_failure_not_a_vacuous_pass(self):
        result = lv.verify_host(
            "x.example.com", FP_NEW, ips=[], fetch=lambda *a: FP_NEW
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["total"], 0)


if __name__ == "__main__":
    unittest.main()
