"""End-to-end wiring of renew/new with the ONS API mocked.

Checks the order of API calls and, above all, which paths must stop before
anything is uploaded or deployed.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_workflow as wf

OK = {"success": True, "data": {"api_response": {"result_code": "200", "data": {}}}}


def _make_cert(cn_san: str) -> Path:
    d = Path(tempfile.mkdtemp())
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"),
         "-subj", "/CN=*.example.com", "-days", "30",
         "-addext", f"subjectAltName={cn_san}"],
        check=True, capture_output=True,
    )  # fmt: skip
    return d / "c.pem"


def _staged(matched=True, verifiable=True):
    return {
        "found": True, "staging_ip": "192.0.2.9", "raw": "",
        "matched": matched, "verifiable": verifiable,
    }  # fmt: skip


class RenewWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.cert = _make_cert("DNS:*.example.com,DNS:example.com")
        self.calls = []

        def manager(cmd):
            self.calls.append(cmd[0])
            return OK

        patches = [
            mock.patch.object(wf, "run_manager_command", side_effect=manager),
            mock.patch.object(
                wf, "fetch_registered_entry",
                return_value={"domains": ["live.example.com"], "expires": "2026-12-01"},
            ),
            mock.patch.object(wf, "wait_for_staged_cert", return_value=_staged()),
            mock.patch.object(wf.time, "sleep"),
        ]  # fmt: skip
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _live(self, ok=True):
        result = {
            "host": "live.example.com", "ok": ok, "total": 2,
            "matched": 2 if ok else 1, "mismatched": {} if ok else {"192.0.2.2": "FP"},
            "unreachable": [], "ips": ["192.0.2.1", "192.0.2.2"],
        }  # fmt: skip
        return mock.patch.object(wf.live_verify, "verify_host", return_value=result)

    def _renew(self, **kw):
        return wf.workflow_renew_cert(
            "t", str(self.cert), "/k.pem", auth={"id": "a", "api_key": "k"}, **kw
        )

    def test_happy_path_runs_stage_then_deploy_then_live_check(self):
        with self._live() as live:
            result = self._renew()

        self.assertTrue(result["success"])
        self.assertEqual(self.calls, ["staging-update", "deploy"])
        live.assert_called_once()

    def test_memo_defaults_from_certificate_content(self):
        sent = []
        wf.run_manager_command.side_effect = lambda cmd: (sent.append(cmd), OK)[1]

        with self._live():
            self._renew()

        memo = sent[0][sent[0].index("--memo") + 1]
        self.assertIn("Serial=", memo)
        self.assertNotIn("Let's Encrypt", memo)

    def test_san_mismatch_stops_before_any_api_call(self):
        wf.fetch_registered_entry.return_value = {
            "domains": ["www.other.org"],
            "expires": "x",
        }

        result = self._renew()

        self.assertFalse(result["success"])
        self.assertEqual(self.calls, [])

    def test_fingerprint_mismatch_stages_but_never_deploys(self):
        wf.wait_for_staged_cert.return_value = _staged(matched=False)

        result = self._renew()

        self.assertFalse(result["success"])
        self.assertEqual(self.calls, ["staging-update"])

    def test_stale_edge_ip_fails_the_workflow_after_deploy(self):
        with self._live(ok=False):
            result = self._renew()

        self.assertFalse(result["success"])
        self.assertEqual(result["step"], 4)
        self.assertEqual(self.calls, ["staging-update", "deploy"])

    def test_no_auto_deploy_skips_deploy_and_live_check(self):
        with self._live() as live:
            result = self._renew(auto_deploy=False)

        self.assertTrue(result["success"])
        self.assertEqual(self.calls, ["staging-update"])
        live.assert_not_called()

    def test_skip_live_verify_deploys_without_edge_check(self):
        with self._live() as live:
            result = self._renew(skip_live_verify=True)

        self.assertTrue(result["success"])
        live.assert_not_called()


class NewWorkflowTests(unittest.TestCase):
    def test_happy_path_stages_deploys_then_checks_every_edge(self):
        cert = _make_cert("DNS:*.example.com")
        calls = []
        live = {
            "host": "a.example.com", "ok": True, "total": 1, "matched": 1,
            "mismatched": {}, "unreachable": [], "ips": ["192.0.2.1"],
        }  # fmt: skip
        with (
            mock.patch.object(
                wf, "run_manager_command",
                side_effect=lambda c: (calls.append(c[0]), OK)[1],
            ),
            mock.patch.object(wf, "wait_for_staged_cert", return_value=_staged()),
            mock.patch.object(wf.live_verify, "verify_host", return_value=live) as v,
        ):  # fmt: skip
            result = wf.workflow_new_cert(
                "t",
                str(cert),
                "/k.pem",
                domain_list="a.example.com",
                auth={"id": "a", "api_key": "k"},
            )

        self.assertTrue(result["success"])
        self.assertEqual(calls, ["staging-deploy", "deploy"])
        v.assert_called_once()

    def test_uncovered_domain_list_stops_before_staging(self):
        cert = _make_cert("DNS:*.example.com")
        calls = []
        with mock.patch.object(
            wf, "run_manager_command", side_effect=lambda c: (calls.append(c[0]), OK)[1]
        ):
            result = wf.workflow_new_cert(
                "t",
                str(cert),
                "/k.pem",
                domain_list="a.example.com,x.other.org",
                auth={"id": "a", "api_key": "k"},
            )

        self.assertFalse(result["success"])
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
