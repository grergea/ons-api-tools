"""Tests for CA bundle layouts that ship several key/chain files side by side.

Reproduces the star_*_ALL_lets layout: an encrypted key next to a decrypted
`Nopasskey.pem`, a `fullchain_cert.pem`, and a `.pfx` whose name contains "chain".
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cert_discovery as cd


def _run(cmd):
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def _make_cert(directory: Path, key_name: str, cert_name: str, cn: str) -> None:
    _run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(directory / key_name),
            "-out", str(directory / cert_name),
            "-subj", f"/CN={cn}", "-days", "30",
        ]
    )  # fmt: skip


class CaBundleLayoutTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        d = self.dir
        _make_cert(d, "site_Nopasskey.pem", "site_cert.pem", "*.example.com")
        _run(
            [
                "openssl", "rsa", "-aes256", "-passout", "pass:pw1234",
                "-in", str(d / "site_Nopasskey.pem"),
                "-out", str(d / "site_key.pem"),
            ]
        )  # fmt: skip
        cert = (d / "site_cert.pem").read_text()
        (d / "site_fullchain_cert.pem").write_text(cert + cert)
        (d / "site_chain.pfx").write_bytes(b"\x30\x82binary")
        (d / "site_JKS(Tomcat).zip").write_bytes(b"zip")

    def test_picks_key_that_matches_the_cert_regardless_of_filename(self):
        bundle = cd.discover_cert_bundle(self.dir)

        self.assertEqual(bundle["cert"].name, "site_cert.pem")
        self.assertEqual(bundle["key"].name, "site_Nopasskey.pem")

    def test_pfx_is_not_a_chain_candidate_and_fullchain_is_the_bundle(self):
        bundle = cd.discover_cert_bundle(self.dir)

        self.assertIsNone(bundle["chain"])
        self.assertEqual(bundle["bundle"].name, "site_fullchain_cert.pem")

    def test_content_beats_a_misleading_filename(self):
        # A decoy key named like the preferred one must lose to the matching key.
        decoy = Path(tempfile.mkdtemp())
        _make_cert(decoy, "decoy.pem", "decoy_cert.pem", "decoy.example.org")
        (self.dir / "site_Nopasskey.pem").rename(self.dir / "site_real_key.pem")
        (self.dir / "nopass_decoy_key.pem").write_text(
            (decoy / "decoy.pem").read_text()
        )

        bundle = cd.discover_cert_bundle(self.dir)

        self.assertEqual(bundle["key"].name, "site_real_key.pem")

    def test_key_of_a_different_certificate_is_rejected(self):
        other = Path(tempfile.mkdtemp())
        _make_cert(other, "other_key.pem", "other_cert.pem", "other.example.org")
        (self.dir / "site_Nopasskey.pem").unlink()
        (self.dir / "site_key.pem").unlink()
        (self.dir / "other_key.pem").write_text((other / "other_key.pem").read_text())

        with self.assertRaises(cd.CertDiscoveryError) as ctx:
            cd.discover_cert_bundle(self.dir)

        self.assertIn("matches", str(ctx.exception))


class CertificateIdentityTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        _run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(self.dir / "k.pem"), "-out", str(self.dir / "c.pem"),
                "-subj", "/CN=*.example.com", "-days", "30",
                "-addext", "subjectAltName=DNS:*.example.com,DNS:example.com",
            ]
        )  # fmt: skip

    def test_describe_reads_subject_san_serial_issuer_and_expiry(self):
        info = cd.describe_certificate(self.dir / "c.pem")

        self.assertEqual(info["subject_cn"], "*.example.com")
        self.assertEqual(info["san"], ["*.example.com", "example.com"])
        self.assertRegex(info["serial"], r"^[0-9A-F]+$")
        self.assertIn("issuer_cn", info)
        self.assertIn("not_after", info)

    def test_fingerprint_equals_the_plain_openssl_sha256_fingerprint(self):
        expected = subprocess.run(
            ["openssl", "x509", "-in", str(self.dir / "c.pem"), "-noout",
             "-fingerprint", "-sha256"],
            capture_output=True, text=True, check=True,
        ).stdout.strip().split("=", 1)[1]  # fmt: skip

        self.assertEqual(
            cd.describe_certificate(self.dir / "c.pem")["fingerprint"], expected
        )

    def test_covers_domain_handles_wildcard_exact_and_non_matches(self):
        san = ["*.example.com", "example.com"]

        self.assertTrue(cd.san_covers_domain(san, "live.example.com"))
        self.assertTrue(cd.san_covers_domain(san, "example.com"))
        self.assertFalse(cd.san_covers_domain(san, "a.b.example.com"))
        self.assertFalse(cd.san_covers_domain(san, "example.org"))
        self.assertFalse(cd.san_covers_domain(san, "notexample.com"))


if __name__ == "__main__":
    unittest.main()
