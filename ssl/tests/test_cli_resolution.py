"""Tests for the --domain auto-detection resolution helpers used by the CLI."""

import argparse
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_workflow as wf
from cert_discovery import CertDiscoveryError


def _ns(**kwargs):
    defaults = {"cert_dir": None, "domain": None, "ssl_cert": None, "ssl_key": None,
                "ssl_key_password": None}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class ResolveValidateCertDirTests(unittest.TestCase):
    def test_returns_explicit_cert_dir_unchanged(self):
        args = _ns(cert_dir="/some/explicit/path")
        self.assertEqual(wf._resolve_validate_cert_dir(args), "/some/explicit/path")

    @patch("ssl_workflow.resolve_cert_dir")
    def test_falls_back_to_domain_auto_detection(self, mock_resolve):
        mock_resolve.return_value = Path("/found/20260101_example.com")
        args = _ns(domain="example.com")

        result = wf._resolve_validate_cert_dir(args)

        self.assertEqual(result, "/found/20260101_example.com")
        mock_resolve.assert_called_once_with("example.com")

    def test_exits_when_neither_provided(self):
        args = _ns()
        with self.assertRaises(SystemExit):
            wf._resolve_validate_cert_dir(args)

    @patch("ssl_workflow.resolve_cert_dir")
    def test_exits_when_domain_not_found(self, mock_resolve):
        mock_resolve.side_effect = CertDiscoveryError("not found")
        args = _ns(domain="missing.com")

        with self.assertRaises(SystemExit):
            wf._resolve_validate_cert_dir(args)


class ResolveCertKeyArgsTests(unittest.TestCase):
    def test_returns_explicit_paths_unchanged(self):
        args = _ns(ssl_cert="/a/cert.pem", ssl_key="/a/key.pem")
        cert, key = wf._resolve_cert_key_args(args)
        self.assertEqual((cert, key), ("/a/cert.pem", "/a/key.pem"))

    def test_exits_when_only_one_explicit_path_given(self):
        args = _ns(ssl_cert="/a/cert.pem")
        with self.assertRaises(SystemExit):
            wf._resolve_cert_key_args(args)

    @patch("ssl_workflow.get_cert_bundle")
    @patch("ssl_workflow.resolve_cert_dir")
    def test_falls_back_to_domain_auto_detection(self, mock_resolve, mock_bundle):
        mock_resolve.return_value = Path("/found/20260101_example.com")
        mock_bundle.return_value = {"fullchain": Path("/found/fullchain.pem"), "key": Path("/found/nopass_key.pem")}
        args = _ns(domain="example.com")

        cert, key = wf._resolve_cert_key_args(args)

        self.assertEqual(cert, "/found/fullchain.pem")
        self.assertEqual(key, "/found/nopass_key.pem")

    def test_returns_none_none_when_not_required_and_nothing_given(self):
        args = _ns()
        cert, key = wf._resolve_cert_key_args(args, required=False)
        self.assertEqual((cert, key), (None, None))

    def test_exits_when_required_and_nothing_given(self):
        args = _ns()
        with self.assertRaises(SystemExit):
            wf._resolve_cert_key_args(args, required=True)


if __name__ == "__main__":
    unittest.main()
