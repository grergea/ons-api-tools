"""Tests for validate_certificate_files using cert_discovery auto-detection."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_workflow as wf


def _run(cmd):
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def _make_self_signed(tmp: Path, cn: str, days: int = 365):
    key = tmp / "key.pem"
    crt = tmp / "cert.pem"
    _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
          "-keyout", str(key), "-out", str(crt), "-days", str(days),
          "-subj", f"/CN={cn}"])
    return key, crt


class ValidateCertificateFilesTests(unittest.TestCase):
    def test_vendor_named_files_are_discovered_and_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            key, crt = _make_self_signed(tmp, "example.com")
            (tmp / "star_example_com_cert.pem").write_text(crt.read_text())
            (tmp / "star_example_com_key.pem").write_text(key.read_text())
            key.unlink()
            crt.unlink()

            with patch("ssl_workflow.verify_certificate_chain", return_value={"valid": True, "chain": []}):
                result = wf.validate_certificate_files(str(tmp), domain="example.com")

            self.assertEqual(result["cert_info"]["status"], "valid")
            self.assertEqual(result["errors"], [])

    def test_missing_key_reports_discovery_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "cert_only.pem").write_text("dummy cert content")

            result = wf.validate_certificate_files(str(tmp))

            self.assertFalse(result["valid"])
            self.assertIn("private key", result["errors"][0].lower())


if __name__ == "__main__":
    unittest.main()
