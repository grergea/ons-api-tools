"""Tests for the domain HTTPS/HTTP2 ON/OFF API commands in ssl_api_manager."""

import argparse
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_api_manager as mgr

BASE = "https://openapi.onscdn.com/cdnservice/domain"


def _ns(**kwargs):
    defaults = {"id": "admin", "password": None, "api_key": "KEY"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _fields(call):
    """Flatten the multipart `files` argument into {name: value}."""
    return {k: v[1] for k, v in call.kwargs["files"].items()}


class HttpsSettingsTests(unittest.TestCase):
    def test_api_urls_registered(self):
        self.assertEqual(
            mgr.API_URLS["https_staging"], f"{BASE}/staging/https/settings"
        )
        self.assertEqual(mgr.API_URLS["https_deploy"], f"{BASE}/https/settings")
        self.assertEqual(mgr.API_URLS["https_cancel"], f"{BASE}/staging/https/cancel")

    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    def test_https_staging_sends_domain_https_http2(self, post, _handle):
        mgr.https_staging(_ns(domain="a.example.com", https="off", http2="off"))

        self.assertEqual(post.call_args.args[0], f"{BASE}/staging/https/settings")
        fields = _fields(post.call_args)
        self.assertEqual(fields["domain"], "a.example.com")
        self.assertEqual(fields["https"], "off")
        self.assertEqual(fields["http2"], "off")
        self.assertEqual(fields["id"], "admin")
        self.assertEqual(fields["cloud_key_value"], "KEY")

    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    def test_https_deploy_sends_only_domain(self, post, _handle):
        mgr.https_deploy(_ns(domain="a.example.com"))

        self.assertEqual(post.call_args.args[0], f"{BASE}/https/settings")
        fields = _fields(post.call_args)
        self.assertEqual(fields["domain"], "a.example.com")
        self.assertNotIn("https", fields)
        self.assertNotIn("http2", fields)

    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    def test_https_cancel_sends_only_domain(self, post, _handle):
        mgr.https_cancel(_ns(domain="a.example.com"))

        self.assertEqual(post.call_args.args[0], f"{BASE}/staging/https/cancel")
        self.assertEqual(_fields(post.call_args)["domain"], "a.example.com")


class HttpsParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = mgr.create_parser()

    def test_https_staging_requires_https_and_http2(self):
        argv = ["https-staging", "--id", "a", "--api-key", "k", "--domain", "d.com"]
        with self.assertRaises(SystemExit):
            with mock.patch("sys.stderr"):
                self.parser.parse_args(argv)

    def test_https_staging_rejects_invalid_value(self):
        argv = [
            "https-staging",
            "--id",
            "a",
            "--api-key",
            "k",
            "--domain",
            "d.com",
            "--https",
            "yes",
            "--http2",
            "off",
        ]
        with self.assertRaises(SystemExit):
            with mock.patch("sys.stderr"):
                self.parser.parse_args(argv)

    def test_https_staging_parses(self):
        args = self.parser.parse_args(
            [
                "https-staging",
                "--id",
                "a",
                "--api-key",
                "k",
                "--domain",
                "d.com",
                "--https",
                "on",
                "--http2",
                "off",
            ]
        )
        self.assertIs(args.func, mgr.https_staging)
        self.assertEqual((args.https, args.http2), ("on", "off"))

    def test_deploy_and_cancel_parse(self):
        for cmd, func in (
            ("https-deploy", mgr.https_deploy),
            ("https-cancel", mgr.https_cancel),
        ):
            args = self.parser.parse_args(
                [cmd, "--id", "a", "--api-key", "k", "--domain", "d.com"]
            )
            self.assertIs(args.func, func)


if __name__ == "__main__":
    unittest.main()
