"""Tests for the generalized verify_certificate_chain (no hardcoded customer paths)."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_workflow as wf


def _run(cmd):
    subprocess.run(cmd, check=True, capture_output=True, text=True)


class VerifyCertificateChainTests(unittest.TestCase):
    """Builds a throwaway root -> intermediate -> leaf PKI to test chain
    verification without touching any real certificate data."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

        root_key = cls.tmp / "root.key"
        root_crt = cls.tmp / "root.crt"
        _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
              "-keyout", str(root_key), "-out", str(root_crt),
              "-days", "1", "-subj", "/CN=Test Root CA"])

        inter_key = cls.tmp / "inter.key"
        inter_csr = cls.tmp / "inter.csr"
        inter_crt = cls.tmp / "inter.crt"
        ext_file = cls.tmp / "inter_ext.cnf"
        ext_file.write_text("basicConstraints=critical,CA:TRUE\n")
        _run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
              "-keyout", str(inter_key), "-out", str(inter_csr),
              "-subj", "/CN=Test Intermediate CA"])
        _run(["openssl", "x509", "-req", "-in", str(inter_csr),
              "-CA", str(root_crt), "-CAkey", str(root_key), "-CAcreateserial",
              "-out", str(inter_crt), "-days", "1", "-extfile", str(ext_file)])

        leaf_key = cls.tmp / "leaf.key"
        leaf_csr = cls.tmp / "leaf.csr"
        leaf_crt = cls.tmp / "leaf.crt"
        _run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
              "-keyout", str(leaf_key), "-out", str(leaf_csr),
              "-subj", "/CN=leaf.example.com"])
        _run(["openssl", "x509", "-req", "-in", str(leaf_csr),
              "-CA", str(inter_crt), "-CAkey", str(inter_key), "-CAcreateserial",
              "-out", str(leaf_crt), "-days", "1"])

        cls.root_crt = root_crt
        cls.other_root_crt = cls.tmp / "other_root.crt"
        other_root_key = cls.tmp / "other_root.key"
        _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
              "-keyout", str(other_root_key), "-out", str(cls.other_root_crt),
              "-days", "1", "-subj", "/CN=Unrelated Root CA"])

        cls.fullchain = cls.tmp / "fullchain.pem"
        cls.fullchain.write_text(
            leaf_crt.read_text().rstrip("\n") + "\n" + inter_crt.read_text().rstrip("\n") + "\n"
        )

    def test_valid_chain_with_matching_trusted_root(self):
        result = wf.verify_certificate_chain(str(self.fullchain), trusted_ca_file=str(self.root_crt))

        self.assertTrue(result["valid"], result.get("error"))
        self.assertEqual(len(result["chain"]), 2)

    def test_invalid_chain_with_unrelated_trusted_root(self):
        result = wf.verify_certificate_chain(str(self.fullchain), trusted_ca_file=str(self.other_root_crt))

        self.assertFalse(result["valid"])

    def test_no_longer_depends_on_customer_specific_sibling_directory(self):
        # Regression guard: this must not raise or require a
        # "{cert_dir}_XXXX/RootChain/..." sibling directory to exist.
        result = wf.verify_certificate_chain(str(self.fullchain), trusted_ca_file=str(self.root_crt))
        self.assertTrue(result["valid"])


if __name__ == "__main__":
    unittest.main()
