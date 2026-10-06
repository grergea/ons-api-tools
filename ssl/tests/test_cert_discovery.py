"""Tests for cert_discovery.py — path resolution and filename auto-detection."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cert_discovery as cd


def _run(cmd):
    subprocess.run(cmd, check=True, capture_output=True, text=True)


class ResolveCertDirTests(unittest.TestCase):
    def test_picks_most_recent_dated_folder(self):
        with tempfile.TemporaryDirectory() as base:
            base = Path(base)
            (base / "20260101_example.com").mkdir()
            (base / "20260615_example.com").mkdir()
            (base / "20260301_other.com").mkdir()

            result = cd.resolve_cert_dir("example.com", base_dir=base)

            self.assertEqual(result.name, "20260615_example.com")

    def test_raises_when_no_match(self):
        with tempfile.TemporaryDirectory() as base:
            with self.assertRaises(cd.CertDiscoveryError):
                cd.resolve_cert_dir("missing.com", base_dir=Path(base))


class DiscoverCertBundleTests(unittest.TestCase):
    def _make_dir(self, files: dict) -> Path:
        tmpdir = tempfile.mkdtemp()
        tmpdir = Path(tmpdir)
        for name, content in files.items():
            (tmpdir / name).write_text(content)
        return tmpdir

    def test_vendor_style_filenames(self):
        cert_dir = self._make_dir(
            {
                "star_example_com_cert.pem": "CERT",
                "star_example_com_key.pem": "KEY",
                "nopass_star_example_com_key.pem": "NOPASS-KEY",
                "Chain_RootCA_Bundle.crt": "CHAIN",
                "star_example_com_PEM(Apache).zip": "ZIP",
                ".DS_Store": "junk",
            }
        )

        bundle = cd.discover_cert_bundle(cert_dir)

        self.assertEqual(bundle["cert"].name, "star_example_com_cert.pem")
        self.assertEqual(bundle["key"].name, "nopass_star_example_com_key.pem")
        self.assertEqual(bundle["chain"].name, "Chain_RootCA_Bundle.crt")

    def test_fixed_legacy_filenames(self):
        cert_dir = self._make_dir(
            {
                "ssl.crt": "CERT",
                "ssl.key": "KEY",
                "fullchain.pem": "CERT+CHAIN",
            }
        )

        bundle = cd.discover_cert_bundle(cert_dir)

        self.assertEqual(bundle["cert"].name, "ssl.crt")
        self.assertEqual(bundle["key"].name, "ssl.key")
        self.assertIsNone(bundle["chain"])

    def test_no_chain_file_is_optional(self):
        cert_dir = self._make_dir({"crt.crt": "CERT", "key.key": "KEY"})

        bundle = cd.discover_cert_bundle(cert_dir)

        self.assertEqual(bundle["cert"].name, "crt.crt")
        self.assertEqual(bundle["key"].name, "key.key")
        self.assertIsNone(bundle["chain"])

    def test_plain_key_is_not_a_cert_candidate_when_nopass_key_exists(self):
        cert_dir = self._make_dir(
            {
                "site_cert.pem": "CERT",
                "site_key.pem": "KEY",
                "nopass_site_key.pem": "NOPASS-KEY",
            }
        )

        bundle = cd.discover_cert_bundle(cert_dir)

        self.assertEqual(bundle["cert"].name, "site_cert.pem")
        self.assertEqual(bundle["key"].name, "nopass_site_key.pem")

    def test_gogetssl_layout_separates_leaf_from_all_bundle(self):
        cert_dir = self._make_dir(
            {
                "example.com_2026DBC.all.crt.pem": "LEAF+CHAIN",
                "example.com_2026DBC.crt.pem": "LEAF",
                "example.com_2026DBC.key.pem": "KEY",
                "발급내역서(필독)_2026DBC.pdf": "PDF",
                ".DS_Store": "junk",
            }
        )

        bundle = cd.discover_cert_bundle(cert_dir)

        self.assertEqual(bundle["cert"].name, "example.com_2026DBC.crt.pem")
        self.assertEqual(bundle["key"].name, "example.com_2026DBC.key.pem")
        self.assertEqual(bundle["bundle"].name, "example.com_2026DBC.all.crt.pem")
        self.assertIsNone(bundle["chain"])

    def test_all_bundle_alone_is_used_as_the_cert(self):
        cert_dir = self._make_dir(
            {
                "example.com.all.crt.pem": "LEAF+CHAIN",
                "example.com.key.pem": "KEY",
            }
        )

        bundle = cd.discover_cert_bundle(cert_dir)

        self.assertEqual(bundle["cert"].name, "example.com.all.crt.pem")
        self.assertIsNone(bundle["bundle"])

    def test_two_all_bundles_raise(self):
        cert_dir = self._make_dir(
            {
                "a.all.crt.pem": "A",
                "b.all.crt.pem": "B",
                "a.crt.pem": "LEAF",
                "a.key.pem": "KEY",
            }
        )

        with self.assertRaises(cd.CertDiscoveryError):
            cd.discover_cert_bundle(cert_dir)

    def test_get_cert_bundle_uses_all_bundle_as_fullchain(self):
        cert_dir = self._make_dir(
            {
                "example.com.all.crt.pem": "LEAF\nCHAIN-1\nCHAIN-2\n",
                "example.com.crt.pem": "LEAF",
            }
        )
        _run(
            ["openssl", "genrsa", "-out", str(cert_dir / "example.com.key.pem"), "2048"]
        )

        result = cd.get_cert_bundle(cert_dir)

        self.assertEqual(result["fullchain"].read_text(), "LEAF\nCHAIN-1\nCHAIN-2\n")

    def _make_nested(self, layout: dict) -> Path:
        """layout: {relative/path: content}; parent dirs are created."""
        root = Path(tempfile.mkdtemp())
        for rel, content in layout.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return root

    def test_descends_into_the_only_subfolder_with_cert_files(self):
        root = self._make_nested(
            {
                "site_2026DBC/site.crt.pem": "LEAF",
                "site_2026DBC/site.all.crt.pem": "LEAF+CHAIN",
                "site_2026DBC/site.key.pem": "KEY",
                "Convert/site.pfx": "PFX",
                "Convert/site.jks": "JKS",
                "RootChain/Root_CA.crt": "ROOT",
                "RootChain/Intermediate_CA.crt": "INTER",
                "site_2026DBC.zip": "ZIP",
            }
        )

        bundle = cd.discover_cert_bundle(root)

        self.assertEqual(bundle["cert"].parent.name, "site_2026DBC")
        self.assertEqual(bundle["cert"].name, "site.crt.pem")
        self.assertEqual(bundle["key"].name, "site.key.pem")
        self.assertEqual(bundle["bundle"].name, "site.all.crt.pem")

    def test_multiple_subfolders_with_cert_files_raise(self):
        root = self._make_nested(
            {
                "a/a.crt.pem": "A",
                "a/a.key.pem": "KEY",
                "b/b.crt.pem": "B",
                "b/b.key.pem": "KEY",
            }
        )

        with self.assertRaises(cd.CertDiscoveryError) as ctx:
            cd.discover_cert_bundle(root)

        self.assertIn("multiple subfolders", str(ctx.exception))

    def test_does_not_descend_when_top_level_has_cert_files(self):
        root = self._make_nested(
            {
                "site.crt.pem": "LEAF",
                "nested/other.crt.pem": "OTHER",
                "nested/other.key.pem": "KEY",
            }
        )

        with self.assertRaises(cd.CertDiscoveryError) as ctx:
            cd.discover_cert_bundle(root)

        self.assertIn("private key", str(ctx.exception))

    def test_skips_hidden_and_macosx_subfolders(self):
        root = self._make_nested(
            {
                "real/real.crt.pem": "LEAF",
                "real/real.key.pem": "KEY",
                "__MACOSX/real/._real.crt.pem": "JUNK",
                "__MACOSX/real/._real.key.pem": "JUNK",
                ".hidden/h.crt.pem": "H",
                ".hidden/h.key.pem": "KEY",
            }
        )

        bundle = cd.discover_cert_bundle(root)

        self.assertEqual(bundle["cert"].parent.name, "real")

    def test_empty_tree_reports_the_top_level_error(self):
        root = self._make_nested({"Convert/site.pfx": "PFX"})

        with self.assertRaises(cd.CertDiscoveryError) as ctx:
            cd.discover_cert_bundle(root)

        self.assertIn("certificate file", str(ctx.exception))

    def test_get_cert_bundle_writes_fullchain_next_to_the_files(self):
        root = self._make_nested(
            {
                "site/site.crt.pem": "LEAF",
                "site/site.all.crt.pem": "LEAF\nCHAIN\n",
            }
        )
        _run(["openssl", "genrsa", "-out", str(root / "site" / "site.key.pem"), "2048"])

        result = cd.get_cert_bundle(root)

        self.assertEqual(result["fullchain"], root / "site" / "fullchain.pem")
        self.assertFalse((root / "fullchain.pem").exists())

    def test_ambiguous_cert_candidates_raise(self):
        cert_dir = self._make_dir(
            {
                "a_cert.pem": "CERT-A",
                "b_cert.pem": "CERT-B",
                "key.key": "KEY",
            }
        )

        with self.assertRaises(cd.CertDiscoveryError):
            cd.discover_cert_bundle(cert_dir)

    def test_missing_key_raises(self):
        cert_dir = self._make_dir({"cert.pem": "CERT"})

        with self.assertRaises(cd.CertDiscoveryError):
            cd.discover_cert_bundle(cert_dir)


class BuildFullchainTests(unittest.TestCase):
    def test_joins_with_single_newline_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            cert = tmp / "cert.pem"
            chain = tmp / "chain.pem"
            cert.write_text(
                "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
            )
            chain.write_text(
                "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n"
            )
            out = tmp / "fullchain.pem"

            cd.build_fullchain(cert, chain, out)
            content = out.read_text()

            self.assertEqual(
                content,
                "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
                "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n",
            )

    def test_no_chain_writes_cert_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            cert = tmp / "cert.pem"
            cert.write_text(
                "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
            )
            out = tmp / "fullchain.pem"

            cd.build_fullchain(cert, None, out)

            self.assertEqual(
                out.read_text(),
                "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
            )


class EncryptedKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.encrypted_key = self.tmp / "enc.key"
        self.plain_key = self.tmp / "plain.key"
        _run(
            [
                "openssl",
                "genrsa",
                "-aes256",
                "-passout",
                "pass:test1234",
                "-out",
                str(self.encrypted_key),
                "2048",
            ]
        )
        _run(["openssl", "genrsa", "-out", str(self.plain_key), "2048"])

    def test_is_key_encrypted_detects_both_cases(self):
        self.assertTrue(cd.is_key_encrypted(self.encrypted_key))
        self.assertFalse(cd.is_key_encrypted(self.plain_key))

    def test_ensure_decrypted_key_returns_unchanged_plain_key(self):
        result = cd.ensure_decrypted_key(self.plain_key, password=None)
        self.assertEqual(result, self.plain_key)

    def test_ensure_decrypted_key_raises_without_password(self):
        with self.assertRaises(cd.CertDiscoveryError):
            cd.ensure_decrypted_key(self.encrypted_key, password=None)

    def test_ensure_decrypted_key_decrypts_and_caches(self):
        result = cd.ensure_decrypted_key(self.encrypted_key, password="test1234")

        self.assertEqual(result.name, "nopass_enc.key")
        self.assertFalse(cd.is_key_encrypted(result))

        # Second call reuses the cached file without needing the password again.
        cached = cd.ensure_decrypted_key(self.encrypted_key, password=None)
        self.assertEqual(cached, result)


if __name__ == "__main__":
    unittest.main()
