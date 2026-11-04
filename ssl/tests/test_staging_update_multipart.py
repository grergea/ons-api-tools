"""Tests for multipart handling in staging_update and secret masking in ssl_workflow."""

import argparse
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_api_manager as mgr
import ssl_workflow as wf


def _ns(**kwargs):
    defaults = {
        "id": "admin",
        "password": None,
        "api_key": "KEY",
        "ssl_file_name": "example.com",
        "add_domain_list": None,
        "del_domain_list": None,
        "memo": None,
        "ssl_key_password": None,
        "ssl_cert": None,
        "ssl_key": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class StagingUpdateMultipartTests(unittest.TestCase):
    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    def test_domain_only_change_is_sent_as_multipart(self, post, _handle):
        """Without cert files the API rejects urlencoded bodies with 415."""
        mgr.staging_update(_ns(add_domain_list="a.example.com"))

        kwargs = post.call_args.kwargs
        self.assertNotIn("data", kwargs)
        fields = {k: v[1] for k, v in kwargs["files"].items()}
        self.assertEqual(fields["ssl_file_name"], "example.com")
        self.assertEqual(fields["add_domain_list"], "a.example.com")
        self.assertEqual(fields["cloud_key_value"], "KEY")


class MaskSecretsTests(unittest.TestCase):
    def test_api_key_and_password_values_are_masked(self):
        command = [
            "lookup",
            "--id",
            "admin",
            "--api-key",
            "SECRET",
            "--ssl-key-password",
            "PW",
            "--ssl-file-name",
            "example.com",
        ]
        masked = wf._mask_secrets(command)

        self.assertNotIn("SECRET", masked)
        self.assertNotIn("PW", masked)
        self.assertEqual(masked.count("****"), 2)
        self.assertIn("example.com", masked)
        self.assertEqual(command[4], "SECRET")


if __name__ == "__main__":
    unittest.main()
