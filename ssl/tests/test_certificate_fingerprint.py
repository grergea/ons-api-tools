"""Tests for SHA-256 fingerprint comparison between a local cert and a served cert."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_workflow as wf


def _make_cert(directory: Path, name: str) -> Path:
    """Generate a throwaway self-signed certificate."""
    key = directory / f"{name}.key"
    crt = directory / f"{name}.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(crt),
            "-days",
            "1",
            "-subj",
            f"/CN={name}.example.test",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return crt


class CertificateFingerprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.cert_a = _make_cert(cls.tmp, "alpha")
        cls.cert_b = _make_cert(cls.tmp, "bravo")
        # Same certificate content under a different filename
        cls.cert_a_copy = cls.tmp / "alpha_copy.crt"
        cls.cert_a_copy.write_bytes(cls.cert_a.read_bytes())

    def test_fingerprint_format(self):
        result = wf.certificate_fingerprint(str(self.cert_a))
        self.assertTrue(result["valid"], result.get("error"))
        self.assertRegex(result["fingerprint"], r"^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$")

    def test_fingerprint_is_stable(self):
        first = wf.certificate_fingerprint(str(self.cert_a))
        second = wf.certificate_fingerprint(str(self.cert_a))
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    def test_missing_file_is_reported(self):
        result = wf.certificate_fingerprint(str(self.tmp / "does_not_exist.crt"))
        self.assertFalse(result["valid"])
        self.assertIn("error", result)

    def test_identical_certificates_match(self):
        result = wf.compare_certificate_fingerprints(
            str(self.cert_a), str(self.cert_a_copy)
        )
        self.assertTrue(result["match"])
        self.assertEqual(result["fingerprint_a"], result["fingerprint_b"])

    def test_different_certificates_do_not_match(self):
        result = wf.compare_certificate_fingerprints(str(self.cert_a), str(self.cert_b))
        self.assertFalse(result["match"])
        self.assertNotEqual(result["fingerprint_a"], result["fingerprint_b"])

    def test_compare_reports_unreadable_input(self):
        result = wf.compare_certificate_fingerprints(
            str(self.cert_a), str(self.tmp / "missing.crt")
        )
        self.assertFalse(result["match"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
