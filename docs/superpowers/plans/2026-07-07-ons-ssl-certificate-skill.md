# ONS SSL Certificate Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install a working Claude Code skill for ONS CDN SSL certificate lookup/registration/renewal, fix the hardcoded customer-specific chain-verification bug, and make the tooling understand the real `~/Certificate/{YYYYMMDD_domain}/` layout with vendor-arbitrary filenames.

**Architecture:** A new pure-logic module `cert_discovery.py` handles locating a domain's certificate directory and auto-detecting cert/key/chain files inside it (including decrypting a password-protected key). `ssl_workflow.py` is patched to use this module instead of assuming fixed filenames, and its chain-verification function is rewritten to rely only on the certificates present in `fullchain.pem` plus the system's default CA trust store — no more per-customer `RootChain` directory dependency. A new skill directory under `.claude/skills/ons-ssl-certificate/` wraps the CLI for Claude Code; the old draft `SKILL.md` inside the script repo is retired. Two vault housekeeping tasks (duplicate note removal, script-note sync) close out the work.

**Tech Stack:** Python 3.13 (stdlib only — `argparse`, `subprocess`, `pathlib`, `re`, `tempfile`, `unittest`), OpenSSL 3.6 CLI (already a hard dependency), no new third-party packages.

## Global Constraints

- `ons-api-tools` is a **public GitHub repo** — never commit real customer domain names, API keys, or private keys. Test fixtures used in automated tests must be synthetic (generated on the fly) or already-gitignored (`ssl/certs/`).
- No new pip dependencies. Use stdlib `unittest`, not `pytest` (not installed, and this repo has no existing test infra).
- Certificate directory convention: `~/Certificate/{YYYYMMDD}_{domain}/` (already in real use — do not invent a different layout).
- Backward compatibility: existing explicit `--cert-dir` / `--ssl-cert` / `--ssl-key` flags must keep working unchanged; `--domain` auto-detection is additive.
- Password handling: never pass a private-key passphrase as a literal CLI argument to `openssl`; use a transient environment variable (`_ONS_KEY_PASSIN`) so it never appears in `ps` output.

---

## Task 1: `cert_discovery.py` — path resolution and vendor-filename auto-detection

**Files:**
- Create: `ssl/cert_discovery.py`
- Create: `ssl/tests/__init__.py` (empty file, makes the tests dir a package)
- Test: `ssl/tests/test_cert_discovery.py`

**Interfaces:**
- Produces: `CertDiscoveryError(Exception)`, `DEFAULT_CERT_BASE: Path`, `resolve_cert_dir(domain: str, base_dir: Path = DEFAULT_CERT_BASE) -> Path`, `discover_cert_bundle(cert_dir: Path) -> dict` (keys: `cert`, `key`, `chain` — all `Path`, `chain` may be `None`), `is_key_encrypted(key_path: Path) -> bool`, `ensure_decrypted_key(key_path: Path, password: Optional[str]) -> Path`, `build_fullchain(cert_path: Path, chain_path: Optional[Path], output_path: Path) -> Path`, `get_cert_bundle(cert_dir: Path, key_password: Optional[str] = None) -> dict` (keys: `cert`, `key`, `chain`, `fullchain`).

- [ ] **Step 1: Write the failing tests**

Create `ssl/tests/__init__.py` with empty content.

Create `ssl/tests/test_cert_discovery.py`:

```python
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
        cert_dir = self._make_dir({
            "star_example_com_cert.pem": "CERT",
            "star_example_com_key.pem": "KEY",
            "nopass_star_example_com_key.pem": "NOPASS-KEY",
            "Chain_RootCA_Bundle.crt": "CHAIN",
            "star_example_com_PEM(Apache).zip": "ZIP",
            ".DS_Store": "junk",
        })

        bundle = cd.discover_cert_bundle(cert_dir)

        self.assertEqual(bundle["cert"].name, "star_example_com_cert.pem")
        self.assertEqual(bundle["key"].name, "nopass_star_example_com_key.pem")
        self.assertEqual(bundle["chain"].name, "Chain_RootCA_Bundle.crt")

    def test_fixed_legacy_filenames(self):
        cert_dir = self._make_dir({
            "ssl.crt": "CERT",
            "ssl.key": "KEY",
            "fullchain.pem": "CERT+CHAIN",
        })

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

    def test_ambiguous_cert_candidates_raise(self):
        cert_dir = self._make_dir({
            "a_cert.pem": "CERT-A",
            "b_cert.pem": "CERT-B",
            "key.key": "KEY",
        })

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
            cert.write_text("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----")
            chain.write_text("-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n")
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
            cert.write_text("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----")
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
        _run(["openssl", "genrsa", "-aes256", "-passout", "pass:test1234",
              "-out", str(self.encrypted_key), "2048"])
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ssl && python3 -m unittest tests.test_cert_discovery -v`
Expected: `ModuleNotFoundError: No module named 'cert_discovery'`

- [ ] **Step 3: Implement `cert_discovery.py`**

Create `ssl/cert_discovery.py`:

```python
#!/usr/bin/env python3
"""Certificate bundle auto-discovery for the ~/Certificate/ convention.

Vendors deliver certificate/key/chain files under arbitrary names inside
~/Certificate/{YYYYMMDD}_{domain}/. These helpers locate the right files
by pattern and normalize them into a single fullchain.pem, so callers
never need to hardcode the vendor's naming scheme or a specific
customer's directory layout.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Optional

DEFAULT_CERT_BASE = Path.home() / "Certificate"

_IGNORED_SUFFIXES = {".zip"}
_IGNORED_NAMES = {".ds_store", "fullchain.pem"}

_CHAIN_PATTERN = re.compile(r"chain", re.IGNORECASE)
_KEY_PATTERN = re.compile(r"key", re.IGNORECASE)
_NOPASS_KEY_PATTERN = re.compile(r"^nopass.*key", re.IGNORECASE)
_CERT_PATTERN = re.compile(r"cert|\.crt$", re.IGNORECASE)


class CertDiscoveryError(Exception):
    """Raised when certificate files cannot be unambiguously located."""


def resolve_cert_dir(domain: str, base_dir: Path = DEFAULT_CERT_BASE) -> Path:
    """Find the most recently dated certificate directory for a domain.

    Looks for base_dir/*_{domain} and returns the match with the highest
    YYYYMMDD prefix (lexicographic sort works since the prefix is
    zero-padded). Raises CertDiscoveryError if none is found.
    """
    matches = sorted(base_dir.glob(f"*_{domain}"), reverse=True)
    if not matches:
        raise CertDiscoveryError(
            f"No certificate directory found for domain '{domain}' under {base_dir}"
        )
    return matches[0]


def _relevant_files(cert_dir: Path) -> list:
    files = []
    for f in cert_dir.iterdir():
        if not f.is_file():
            continue
        if f.suffix.lower() in _IGNORED_SUFFIXES:
            continue
        if f.name.lower() in _IGNORED_NAMES:
            continue
        files.append(f)
    return files


def discover_cert_bundle(cert_dir: Path) -> dict:
    """Auto-detect cert/key/chain files with vendor-arbitrary names.

    Returns {"cert": Path, "key": Path, "chain": Path | None}. Raises
    CertDiscoveryError if the cert or key candidate is missing or
    ambiguous (zero or multiple matches). A chain file is optional.
    """
    files = _relevant_files(cert_dir)

    chain_candidates = [f for f in files if _CHAIN_PATTERN.search(f.name)]
    nopass_key_candidates = [f for f in files if _NOPASS_KEY_PATTERN.search(f.name)]
    key_candidates = nopass_key_candidates or [
        f for f in files if _KEY_PATTERN.search(f.name) and f not in chain_candidates
    ]
    cert_candidates = [
        f for f in files
        if _CERT_PATTERN.search(f.name)
        and f not in chain_candidates
        and f not in key_candidates
    ]

    if len(cert_candidates) != 1:
        raise CertDiscoveryError(
            f"Expected exactly 1 certificate file in {cert_dir}, found "
            f"{len(cert_candidates)}: {[f.name for f in cert_candidates]}"
        )
    if len(key_candidates) != 1:
        raise CertDiscoveryError(
            f"Expected exactly 1 private key file in {cert_dir}, found "
            f"{len(key_candidates)}: {[f.name for f in key_candidates]}"
        )
    if len(chain_candidates) > 1:
        raise CertDiscoveryError(
            f"Expected at most 1 chain file in {cert_dir}, found "
            f"{len(chain_candidates)}: {[f.name for f in chain_candidates]}"
        )

    return {
        "cert": cert_candidates[0],
        "key": key_candidates[0],
        "chain": chain_candidates[0] if chain_candidates else None,
    }


def is_key_encrypted(key_path: Path) -> bool:
    """Return True if the private key requires a password to load."""
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-noout", "-check"],
        capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
    )
    return result.returncode != 0


def ensure_decrypted_key(key_path: Path, password: Optional[str]) -> Path:
    """Return a path to an unencrypted version of key_path.

    If key_path is already unencrypted, returns it unchanged. If it is
    encrypted, decrypts it into nopass_<original name> next to it
    (cached for future calls) using the given password, and returns that
    path. Raises CertDiscoveryError if the key is encrypted and no
    password was given, or if decryption fails.
    """
    if not is_key_encrypted(key_path):
        return key_path

    decrypted_path = key_path.parent / f"nopass_{key_path.name}"
    if decrypted_path.exists():
        return decrypted_path

    if not password:
        raise CertDiscoveryError(
            f"{key_path.name} is password-protected. Provide --ssl-key-password "
            f"or set the ONS_SSL_KEY_PASSWORD environment variable."
        )

    env = os.environ.copy()
    env["_ONS_KEY_PASSIN"] = password
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-passin", "env:_ONS_KEY_PASSIN",
         "-out", str(decrypted_path)],
        capture_output=True, text=True, timeout=10, env=env, stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise CertDiscoveryError(f"Failed to decrypt {key_path.name}: {result.stderr.strip()}")

    return decrypted_path


def build_fullchain(cert_path: Path, chain_path: Optional[Path], output_path: Path) -> Path:
    """Concatenate cert (+ chain, if present) into output_path and return it.

    Normalizes newline boundaries between PEM blocks — naively `cat`-ing
    files that don't end in a newline produces a malformed PEM that
    OpenSSL rejects with "bad end line".
    """
    parts = [cert_path.read_text()]
    if chain_path:
        parts.append(chain_path.read_text())
    output_path.write_text("\n".join(p.rstrip("\n") for p in parts) + "\n")
    return output_path


def get_cert_bundle(cert_dir: Path, key_password: Optional[str] = None) -> dict:
    """Resolve a full usable certificate bundle for cert_dir.

    Returns {"cert": Path, "key": Path, "chain": Path | None,
    "fullchain": Path}. Uses an existing fullchain.pem if present;
    otherwise builds one from the discovered cert + chain. Decrypts the
    private key if needed.
    """
    bundle = discover_cert_bundle(cert_dir)
    key_path = ensure_decrypted_key(bundle["key"], key_password)

    fullchain_path = cert_dir / "fullchain.pem"
    if not fullchain_path.exists():
        build_fullchain(bundle["cert"], bundle["chain"], fullchain_path)

    return {
        "cert": bundle["cert"],
        "key": key_path,
        "chain": bundle["chain"],
        "fullchain": fullchain_path,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ssl && python3 -m unittest tests.test_cert_discovery -v`
Expected: `OK` (12 tests pass)

- [ ] **Step 5: Commit**

```bash
git add ssl/cert_discovery.py ssl/tests/__init__.py ssl/tests/test_cert_discovery.py
git commit -m "Add cert_discovery module for ~/Certificate/ auto-detection"
```

---

## Task 2: Fix hardcoded chain verification in `ssl_workflow.py`

**Files:**
- Modify: `ssl/ssl_workflow.py` (function `verify_certificate_chain`, originally lines 278-350)
- Test: `ssl/tests/test_verify_certificate_chain.py`

**Interfaces:**
- Consumes: nothing from Task 1 directly (self-contained fix).
- Produces: `verify_certificate_chain(fullchain_path: str, trusted_ca_file: Optional[str] = None) -> dict` (same return shape as before: `{"valid": bool, "chain": list, "message"|"error": str}`). The new optional `trusted_ca_file` parameter defaults to `None` (use the system's default CA store); tests pass a synthetic root to make the test hermetic.

- [ ] **Step 1: Write the failing test**

Create `ssl/tests/test_verify_certificate_chain.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ssl && python3 -m unittest tests.test_verify_certificate_chain -v`
Expected: `FAIL` — `verify_certificate_chain() got an unexpected keyword argument 'trusted_ca_file'`

- [ ] **Step 3: Replace `verify_certificate_chain` in `ssl_workflow.py`**

Add `import tempfile` to the top imports (after `import sys`, before `from datetime import datetime`):

```python
import subprocess
import sys
import tempfile
from datetime import datetime
```

Replace the entire existing `verify_certificate_chain` function (originally lines 278-350, the one that builds `original_dir = Path(cert_dir).parent / f"{Path(cert_dir).name}_2026032792EC5"`) with:

```python
def verify_certificate_chain(fullchain_path: str, trusted_ca_file: Optional[str] = None) -> dict:
    """
    Verify the full certificate chain using OpenSSL.

    fullchain_path must contain the leaf certificate followed by any
    intermediate certificates (as produced by cert_discovery.build_fullchain
    or an already-merged fullchain.pem). No customer-specific root chain
    directory is required — the system's default CA trust store is used
    unless trusted_ca_file overrides it (used by tests to stay hermetic).

    Returns dict with:
        - valid: bool
        - chain: list of {"subject": str, "issuer": str} certificate links
        - error: error message if failed
    """
    try:
        pem_blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(fullchain_path).read_text(), re.DOTALL,
        )
        if not pem_blocks:
            return {"valid": False, "chain": [], "error": "No certificates found in fullchain"}

        # Extract subject/issuer pairs for display purposes.
        chain_cmd = f"""
            openssl crl2pkcs7 -nocrl -certfile "{fullchain_path}" | \
            openssl pkcs7 -print_certs -noout 2>/dev/null
        """
        chain_result = subprocess.run(
            chain_cmd, shell=True, capture_output=True, text=True, timeout=15
        )

        chain = []
        if chain_result.returncode == 0 and chain_result.stdout:
            current_subject = None
            for line in chain_result.stdout.strip().split("\n"):
                line = line.strip()
                if line.startswith("subject="):
                    current_subject = line.split("=", 1)[1].strip()
                elif line.startswith("issuer=") and current_subject:
                    issuer = line.split("=", 1)[1].strip()
                    chain.append({"subject": current_subject, "issuer": issuer})
                    current_subject = None

        leaf, intermediates = pem_blocks[0], pem_blocks[1:]

        with tempfile.TemporaryDirectory() as tmpdir:
            leaf_path = Path(tmpdir) / "leaf.pem"
            leaf_path.write_text(leaf)

            cmd = ["openssl", "verify"]
            if trusted_ca_file:
                cmd += ["-CAfile", trusted_ca_file]
            if intermediates:
                untrusted_path = Path(tmpdir) / "untrusted.pem"
                untrusted_path.write_text("\n".join(intermediates))
                cmd += ["-untrusted", str(untrusted_path)]
            cmd.append(str(leaf_path))

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        if result.returncode == 0:
            return {"valid": True, "chain": chain, "message": result.stdout.strip()}
        else:
            return {
                "valid": False,
                "chain": chain,
                "error": result.stderr.strip() or result.stdout.strip(),
            }

    except subprocess.TimeoutExpired:
        return {"valid": False, "error": "Timeout while verifying certificate chain"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ssl && python3 -m unittest tests.test_verify_certificate_chain -v`
Expected: `OK` (3 tests pass)

- [ ] **Step 5: Commit**

```bash
git add ssl/ssl_workflow.py ssl/tests/test_verify_certificate_chain.py
git commit -m "Fix chain verification to stop depending on a hardcoded customer directory"
```

---

## Task 3: Wire `validate_certificate_files` to use `cert_discovery`

**Files:**
- Modify: `ssl/ssl_workflow.py` (function `validate_certificate_files`, originally lines 196-275; import block; `workflow_validate` at line ~722; `workflow_compare` at line ~948)
- Test: `ssl/tests/test_validate_certificate_files.py`

**Interfaces:**
- Consumes: `cert_discovery.get_cert_bundle`, `cert_discovery.CertDiscoveryError` (Task 1); `verify_certificate_chain(fullchain_path, trusted_ca_file=None)` (Task 2).
- Produces: `validate_certificate_files(cert_dir: str, domain: str = None, key_password: str = None) -> dict` (same return shape as before, plus errors now include `CertDiscoveryError` messages when files can't be located); `workflow_validate(cert_dir, domain=None, key_password=None)`; `workflow_compare(cert_dir, ssl_file_name, domain=None, auth=None, key_password=None)`.

- [ ] **Step 1: Write the failing test**

Create `ssl/tests/test_validate_certificate_files.py`:

```python
"""Tests for validate_certificate_files using cert_discovery auto-detection."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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

            result = wf.validate_certificate_files(str(tmp), domain="example.com")

            self.assertEqual(result["cert_info"]["status"], "valid")
            self.assertEqual(result["errors"], [])

    def test_missing_key_reports_discovery_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _, crt = _make_self_signed(tmp, "example.com")
            (tmp / "cert_only.pem").write_text(crt.read_text())

            result = wf.validate_certificate_files(str(tmp))

            self.assertFalse(result["valid"])
            self.assertIn("private key", result["errors"][0].lower())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ssl && python3 -m unittest tests.test_validate_certificate_files -v`
Expected: `FAIL` — old `validate_certificate_files` looks for a fixed `ssl.crt`/`ssl.key` and reports "Certificate file not found"

- [ ] **Step 3: Update `ssl_workflow.py`**

Add the import (after the existing `from typing import Optional` line):

```python
from typing import Optional

from cert_discovery import CertDiscoveryError, get_cert_bundle, resolve_cert_dir
```

Replace the existing `validate_certificate_files` function (originally lines 196-275) with:

```python
def validate_certificate_files(cert_dir: str, domain: str = None, key_password: str = None) -> dict:
    """
    Validate certificate files in a directory, auto-detecting vendor
    filenames via cert_discovery.

    Returns dict with:
        - valid: bool
        - errors: list of error messages
        - warnings: list of warning messages
        - cert_info: certificate details
    """
    errors = []
    warnings = []

    try:
        bundle = get_cert_bundle(Path(cert_dir), key_password)
    except CertDiscoveryError as e:
        return {"valid": False, "errors": [str(e)], "warnings": warnings}

    cert_path = bundle["cert"]
    key_path = bundle["key"]
    fullchain_path = bundle["fullchain"]

    # Verify certificate
    cert_info = verify_certificate_expiry(str(cert_path))
    if not cert_info.get("valid"):
        errors.append(f"Certificate validation failed: {cert_info.get('error')}")
        return {"valid": False, "errors": errors, "warnings": warnings, "cert_info": cert_info}

    # Check expiration
    if cert_info["status"] == "expired":
        errors.append(f"Certificate is EXPIRED! Expired on {cert_info['notAfter']}")
    elif cert_info["status"] == "expiring_soon":
        warnings.append(f"Certificate expires in {cert_info['days_left']} days ({cert_info['notAfter']})")

    # Verify private key
    key_info = verify_private_key(str(key_path))
    if not key_info.get("valid"):
        errors.append(f"Private key validation failed: {key_info.get('error')}")
        return {"valid": False, "errors": errors, "warnings": warnings, "cert_info": cert_info}

    # Check key-certificate match
    if not verify_key_cert_match(str(cert_path), str(key_path)):
        errors.append("Private key does NOT match the certificate!")
    else:
        print_success("Private key matches certificate")

    # Verify certificate chain
    chain_info = verify_certificate_chain(str(fullchain_path))
    if chain_info.get("valid"):
        print_success(f"Certificate chain verified ({len(chain_info.get('chain', []))} certificates)")
    else:
        errors.append(f"Certificate chain verification failed: {chain_info.get('error', 'Unknown error')}")

    # Check domain match if provided
    if domain and cert_info.get("subject"):
        if domain.lower() not in cert_info["subject"].lower():
            san_check = subprocess.run(
                ["openssl", "x509", "-in", str(fullchain_path), "-noout", "-text"],
                capture_output=True, text=True, timeout=10
            )
            if domain.lower() not in san_check.stdout.lower():
                warnings.append(f"Domain '{domain}' not found in certificate Subject or SAN")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "cert_info": cert_info,
        "chain_info": chain_info,
    }
```

Update `workflow_validate` (originally around line 722) to accept and forward `key_password`:

```python
def workflow_validate(cert_dir: str, domain: str = None, key_password: str = None) -> dict:
    """
    Validate SSL certificate files locally.

    Steps:
        1. Validate certificate files exist
        2. Verify certificate expiration
        3. Verify private key validity
        4. Verify key-certificate match
        5. Verify domain match (if provided)
    """
    print_step(1, 1, f"Validating certificate files in: {cert_dir}")

    validation = validate_certificate_files(cert_dir, domain, key_password)
```

(the rest of `workflow_validate`'s body is unchanged — only the signature and the `validate_certificate_files` call gained `key_password`)

Update `workflow_compare` (originally around line 948) the same way — change its signature to:

```python
def workflow_compare(
    cert_dir: str,
    ssl_file_name: str,
    domain: str = None,
    auth: dict = None,
    key_password: str = None
) -> dict:
```

and change its call to `validate_certificate_files(cert_dir, domain)` to:

```python
    validation = validate_certificate_files(cert_dir, domain, key_password)
```

(the rest of `workflow_compare`'s body is unchanged)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ssl && python3 -m unittest tests.test_validate_certificate_files -v`
Expected: `OK` (2 tests pass)

Then run the full suite to check for regressions:

Run: `cd ssl && python3 -m unittest discover -s tests -v`
Expected: `OK` (all tests from Tasks 1-3 pass)

- [ ] **Step 5: Commit**

```bash
git add ssl/ssl_workflow.py ssl/tests/test_validate_certificate_files.py
git commit -m "Use cert_discovery auto-detection in validate_certificate_files"
```

---

## Task 4: `--domain` auto-detection wiring in the CLI

**Files:**
- Modify: `ssl/ssl_workflow.py` (function `create_parser`, originally lines 1022-1193)
- Test: `ssl/tests/test_cli_resolution.py`

**Interfaces:**
- Consumes: `resolve_cert_dir`, `get_cert_bundle`, `CertDiscoveryError` (Task 1).
- Produces: `_resolve_validate_cert_dir(args) -> str`, `_resolve_cert_key_args(args, required: bool = True) -> tuple[Optional[str], Optional[str]]`. CLI behavior: `validate`/`compare` accept `--domain` as an alternative to `--cert-dir`; `new`/`renew` accept `--domain` as an alternative to `--ssl-cert`/`--ssl-key`; `domains` accepts `--domain` as an optional alternative (a pure domain-list change still works with neither).

- [ ] **Step 1: Write the failing test**

Create `ssl/tests/test_cli_resolution.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ssl && python3 -m unittest tests.test_cli_resolution -v`
Expected: `FAIL` — `AttributeError: module 'ssl_workflow' has no attribute '_resolve_validate_cert_dir'`

- [ ] **Step 3: Add resolution helpers and wire them into `create_parser`**

Add these two functions to `ssl_workflow.py`, directly above `def create_parser()`:

```python
def _resolve_validate_cert_dir(args) -> str:
    """Resolve the cert directory for validate/compare from --cert-dir or --domain."""
    if args.cert_dir:
        return args.cert_dir
    if not args.domain:
        print_error("Either --cert-dir or --domain must be provided.")
        sys.exit(1)
    try:
        return str(resolve_cert_dir(args.domain))
    except CertDiscoveryError as e:
        print_error(str(e))
        sys.exit(1)


def _resolve_cert_key_args(args, required: bool = True):
    """Resolve (ssl_cert, ssl_key) from explicit flags or --domain auto-detection.

    Returns (None, None) if neither is provided and required=False (the
    'domains' command allows a pure domain-list change without touching
    the certificate).
    """
    if args.ssl_cert and args.ssl_key:
        return args.ssl_cert, args.ssl_key
    if args.ssl_cert or args.ssl_key:
        print_error("Provide both --ssl-cert and --ssl-key together, or use --domain for auto-detection.")
        sys.exit(1)

    domain = getattr(args, "domain", None)
    if not domain:
        if required:
            print_error("Provide --ssl-cert/--ssl-key, or --domain for auto-detection.")
            sys.exit(1)
        return None, None

    try:
        cert_dir = resolve_cert_dir(domain)
        password = getattr(args, "ssl_key_password", None) or os.environ.get("ONS_SSL_KEY_PASSWORD")
        bundle = get_cert_bundle(cert_dir, password)
    except CertDiscoveryError as e:
        print_error(str(e))
        sys.exit(1)

    return str(bundle["fullchain"]), str(bundle["key"])
```

In `create_parser`, update the **validate** subparser: change `--cert-dir` from `required=True` to optional, and add `--ssl-key-password`:

```python
    parser_validate.add_argument("--cert-dir", dest="cert_dir",
                               help="Directory containing certificate files (auto-detected filenames)")
    parser_validate.add_argument("--domain", dest="domain",
                               help="Domain to auto-locate under ~/Certificate/, and to verify against the certificate")
    parser_validate.add_argument("--ssl-key-password", dest="ssl_key_password",
                               help="Password to locally decrypt an encrypted private key (or set ONS_SSL_KEY_PASSWORD)")
    parser_validate.set_defaults(func=lambda args: workflow_validate(
        cert_dir=_resolve_validate_cert_dir(args),
        domain=args.domain,
        key_password=args.ssl_key_password or os.environ.get("ONS_SSL_KEY_PASSWORD"),
    ))
```

(remove the old `required=True` version of `--cert-dir` and the old bare `set_defaults` call for `parser_validate`)

Update the **compare** subparser the same way — `--cert-dir` becomes optional, add `--ssl-key-password`:

```python
    parser_compare.add_argument("--cert-dir", dest="cert_dir",
                               help="Directory containing certificate files (auto-detected filenames)")
    parser_compare.add_argument("--ssl-key-password", dest="ssl_key_password",
                               help="Password to locally decrypt an encrypted private key (or set ONS_SSL_KEY_PASSWORD)")
    parser_compare.set_defaults(func=lambda args: workflow_compare(
        cert_dir=_resolve_validate_cert_dir(args),
        ssl_file_name=args.ssl_file_name,
        domain=args.domain,
        auth=get_auth_params(args.id, args.api_key),
        key_password=args.ssl_key_password or os.environ.get("ONS_SSL_KEY_PASSWORD"),
    ))
```

(`compare` already has `--domain`, required=False by default — keep it as-is; only `--cert-dir`'s `required=True` is removed and `--ssl-key-password` is added)

Update the **new** subparser: add `--domain`, remove `required=True` from `--ssl-cert`/`--ssl-key`, add `--ssl-key-password`:

```python
    parser_new.add_argument("--ssl-cert", dest="ssl_cert",
                            help="Path to SSL certificate file (fullchain)")
    parser_new.add_argument("--ssl-key", dest="ssl_key",
                            help="Path to SSL private key file")
    parser_new.add_argument("--domain", dest="domain",
                            help="Domain to auto-locate under ~/Certificate/ instead of --ssl-cert/--ssl-key")
    parser_new.add_argument("--ssl-key-password", dest="ssl_key_password",
                            help="Password to locally decrypt an encrypted private key (or set ONS_SSL_KEY_PASSWORD)")
    parser_new.add_argument("--domain-list", dest="domain_list",
                            help="Comma-separated list of domains")
    parser_new.add_argument("--memo", help="Memo for the deployment")
    parser_new.add_argument("--skip-verify", dest="skip_verify", action="store_true",
                            help="Skip verification step")
    parser_new.add_argument("--no-auto-deploy", dest="no_auto_deploy", action="store_true",
                            help="Skip automatic final deployment")

    def _run_new(args):
        ssl_cert, ssl_key = _resolve_cert_key_args(args)
        return workflow_new_cert(
            ssl_file_name=args.ssl_file_name,
            ssl_cert=ssl_cert,
            ssl_key=ssl_key,
            domain_list=args.domain_list,
            memo=args.memo,
            auth=get_auth_params(args.id, args.api_key),
            skip_verify=args.skip_verify,
            auto_deploy=not args.no_auto_deploy
        )

    parser_new.set_defaults(func=_run_new)
```

(note: `--ssl-cert`/`--ssl-key` lose their old `required=True`; the rest of the subparser is unchanged)

Update the **renew** subparser the same way:

```python
    parser_renew.add_argument("--ssl-cert", dest="ssl_cert",
                              help="Path to new SSL certificate file")
    parser_renew.add_argument("--ssl-key", dest="ssl_key",
                              help="Path to new SSL private key file")
    parser_renew.add_argument("--domain", dest="domain",
                              help="Domain to auto-locate under ~/Certificate/ instead of --ssl-cert/--ssl-key")
    parser_renew.add_argument("--ssl-key-password", dest="ssl_key_password",
                              help="Password to locally decrypt an encrypted private key (or set ONS_SSL_KEY_PASSWORD)")
    parser_renew.add_argument("--memo", help="Memo for the update")
    parser_renew.add_argument("--skip-verify", dest="skip_verify", action="store_true",
                              help="Skip verification step")
    parser_renew.add_argument("--no-auto-deploy", dest="no_auto_deploy", action="store_true",
                              help="Skip automatic final deployment")

    def _run_renew(args):
        ssl_cert, ssl_key = _resolve_cert_key_args(args)
        return workflow_renew_cert(
            ssl_file_name=args.ssl_file_name,
            ssl_cert=ssl_cert,
            ssl_key=ssl_key,
            memo=args.memo,
            auth=get_auth_params(args.id, args.api_key),
            skip_verify=args.skip_verify,
            auto_deploy=not args.no_auto_deploy
        )

    parser_renew.set_defaults(func=_run_renew)
```

Update the **domains** subparser: add `--domain` and `--ssl-key-password`, and pass `required=False` to `_resolve_cert_key_args`:

```python
    parser_domains.add_argument("--domain", dest="domain",
                               help="Domain to auto-locate under ~/Certificate/ for a certificate rotation (optional)")
    parser_domains.add_argument("--ssl-key-password", dest="ssl_key_password",
                               help="Password to locally decrypt an encrypted private key (or set ONS_SSL_KEY_PASSWORD)")

    def _run_domains(args):
        ssl_cert, ssl_key = _resolve_cert_key_args(args, required=False)
        return workflow_domain_update(
            ssl_file_name=args.ssl_file_name,
            add_domain_list=args.add_domain_list,
            del_domain_list=args.del_domain_list,
            ssl_cert=ssl_cert,
            ssl_key=ssl_key,
            memo=args.memo,
            auth=get_auth_params(args.id, args.api_key),
            skip_verify=args.skip_verify,
            auto_deploy=not args.no_auto_deploy
        )

    parser_domains.set_defaults(func=_run_domains)
```

(the existing `--ssl-cert`/`--ssl-key` options on this subparser are already optional — no change needed to them)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ssl && python3 -m unittest tests.test_cli_resolution -v`
Expected: `OK` (9 tests pass)

Then run the full suite:

Run: `cd ssl && python3 -m unittest discover -s tests -v`
Expected: `OK` (all tests from Tasks 1-4 pass)

- [ ] **Step 5: Commit**

```bash
git add ssl/ssl_workflow.py ssl/tests/test_cli_resolution.py
git commit -m "Wire --domain auto-detection into validate/compare/new/renew/domains commands"
```

---

## Task 5: Install the Claude Code skill

**Files:**
- Create: `/Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/SKILL.md`
- Create: `/Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/references/scenarios.md`
- Delete: `ssl/SKILL.md`

**Interfaces:** none (documentation-only task).

- [ ] **Step 1: Create the skill directory**

```bash
mkdir -p /Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/references
```

- [ ] **Step 2: Write `SKILL.md`**

Create `/Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/SKILL.md`:

```markdown
---
name: ons-ssl-certificate
description: "ONS CDN SSL 인증서 관리 — 조회/신규등록/갱신/도메인변경/로컬-원격 비교를 자동 실행. Triggers on: 'SSL 인증서 등록', '인증서 갱신', 'ONS 인증서 조회', '인증서 비교', 'ssl_workflow'."
---

# ONS SSL Certificate Management

ONS CDN SSL 인증서를 조회·등록·갱신하는 스킬입니다. `ssl_workflow.py`(워크플로우 자동화) + `ssl_api_manager.py`(저수준 API CLI)를 사용합니다.

## 스크립트 위치

```
/Users/shlee/mynotes/ons-api-tools/ssl/ssl_workflow.py
/Users/shlee/mynotes/ons-api-tools/ssl/ssl_api_manager.py
```

## 사용 전 준비

```bash
export ONS_API_KEY="<User Portal에서 발급받은 API 키>"
export ONS_API_ID="cdnetworks"   # 기본값, 생략 가능
```

암호화된 개인키를 다루는 경우:

```bash
export ONS_SSL_KEY_PASSWORD="<키 암호>"   # 또는 --ssl-key-password 로 매번 지정
```

## 인증서 위치 규칙

로컬 인증서는 `~/Certificate/{YYYYMMDD}_{도메인}/`에 CA가 제공한 원본 파일명 그대로 보관합니다 (예: `~/Certificate/20260702_hani.com/star_hani_com_cert.pem`). 파일명을 맞추거나 병합할 필요 없이 `--domain <도메인>`만 지정하면 스크립트가 최신 날짜 폴더를 찾아 cert/key/chain 파일을 자동 탐지하고 `fullchain.pem`을 생성합니다. 암호화된 키만 있으면 비밀번호로 자동 해독합니다.

폴더나 파일을 직접 지정하고 싶으면 기존처럼 `--cert-dir`/`--ssl-cert`/`--ssl-key`를 사용해도 됩니다 (둘 다 지원, `--domain`이 없으면 명시적 경로가 필수).

## 명령어

| 명령 | 용도 |
|------|------|
| `validate --domain <도메인>` | 로컬 인증서 검증 (만료일, 키 일치, 체인) |
| `new --ssl-file-name <이름> --domain <도메인> --domain-list "..."` | 신규 인증서 등록 |
| `renew --ssl-file-name <이름> --domain <도메인>` | 기존 인증서 갱신 |
| `domains --ssl-file-name <이름> --add-domain-list "..."` | 도메인 매핑 변경 (인증서 미변경 시 `--domain` 불필요) |
| `lookup --ssl-file-name <이름> --verify` | ONS CDN에서 인증서 정보 조회 |
| `compare --domain <도메인> --ssl-file-name <이름>` | 로컬 vs ONS CDN 인증서 비교 |

각 워크플로우(`new`/`renew`/`domains`)는 내부적으로 `staging-* → lookup --verify → deploy` 순서로 실행되고, 실패 시 어느 단계에서 멈췄는지 알려줍니다. 검증만 하고 최종 배포는 나중에 하려면 `--no-auto-deploy`를 붙이세요.

상세 명령어 예시, 출력 샘플, 체인 검증 원리는 [references/scenarios.md](references/scenarios.md) 참고.

## 롤백

```bash
python3 ssl_api_manager.py staging-cancel --id cdnetworks --api-key $ONS_API_KEY --ssl-file-name <이름>
```

## 관련 문서

- [[ssl_workflow.py]] — 워크플로우 자동화 스크립트 노트
- [[ssl-api-manager.py]] — 저수준 API CLI 스크립트 노트
```

- [ ] **Step 3: Write `references/scenarios.md`**

Create `/Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/references/scenarios.md`:

```markdown
# ONS SSL Certificate — Detailed Scenarios

All examples use generic placeholder domains (`example.com`) — substitute your real domain and `--ssl-file-name`.

## 시나리오 A: 신규 인증서 등록

```bash
python3 ssl_workflow.py new \
  --ssl-file-name wildcard.example.com \
  --domain example.com \
  --domain-list "cdn.example.com,api.example.com" \
  --memo "신규 인증서 등록"
```

흐름: `staging-deploy` → `lookup --verify` (만료일, Subject, SAN 확인, 30일 이하 경고) → `deploy`.

## 시나리오 B: 기존 인증서 갱신

```bash
python3 ssl_workflow.py renew \
  --ssl-file-name example.com \
  --domain example.com \
  --memo "인증서 갱신"
```

흐름: `staging-update` → `lookup --verify` → `deploy`.

## 시나리오 C: 도메인 매핑 변경

```bash
# 추가
python3 ssl_workflow.py domains \
  --ssl-file-name wildcard.example.com \
  --add-domain-list "new.example.com"

# 삭제
python3 ssl_workflow.py domains \
  --ssl-file-name wildcard.example.com \
  --del-domain-list "old.example.com"
```

인증서 자체는 바뀌지 않으므로 `--domain`/`--ssl-cert`/`--ssl-key` 없이 실행 가능. 인증서를 함께 교체하려면 `--domain example.com`을 추가.

## 시나리오 D: 인증서 정보 조회

```bash
python3 ssl_workflow.py lookup --ssl-file-name example.com --verify
```

Staging IP, 배포 상태, 만료일, Subject/Issuer/Serial, 체인 검증 결과를 출력합니다.

## 시나리오 E: 로컬 vs ONS CDN 인증서 비교

```bash
python3 ssl_workflow.py compare --domain example.com --ssl-file-name example.com
```

비교 항목: Serial, Domain(CN), 만료일, 남은 일수, Issuer. Serial이 같으면 "업로드 불필요", 다르면 "업로드 필요"로 결론.

## 체인 검증 원리

`fullchain.pem`(leaf + intermediate)을 자동 생성하거나 기존 파일을 사용해, intermediate는 `-untrusted`로 전달하고 최상위 신뢰는 시스템 기본 CA 저장소를 사용합니다. 특정 고객사 전용 루트 체인 디렉터리는 필요하지 않습니다.

## 인증서 검증 명령어 (수동 디버깅용)

```bash
# 인증서 정보
openssl x509 -in cert.pem -noout -dates -subject -issuer

# 개인키/인증서 일치 확인
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5

# 개인키 비밀번호 확인
openssl rsa -check -in key.pem

# 체인 검증
openssl verify -untrusted chain.pem cert.pem
```
```

- [ ] **Step 4: Delete the retired draft skill file**

```bash
rm /Users/shlee/mynotes/ons-api-tools/ssl/SKILL.md
```

- [ ] **Step 5: Verify installation**

```bash
test -f /Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/SKILL.md && echo "SKILL.md present"
test -f /Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/references/scenarios.md && echo "scenarios.md present"
test ! -f /Users/shlee/mynotes/ons-api-tools/ssl/SKILL.md && echo "old SKILL.md removed"
head -5 /Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/SKILL.md
```

Expected: all three `echo` lines print, and the frontmatter shows `name: ons-ssl-certificate`.

- [ ] **Step 6: Commit the script-repo deletion**

```bash
cd /Users/shlee/mynotes/ons-api-tools && git add -A ssl/SKILL.md && git commit -m "Remove draft SKILL.md; skill now lives in the vault's .claude/skills/"
```

(the `.claude/skills/ons-ssl-certificate/` files are in the vault, which is not a git repository — no commit needed for them)

---

## Task 6: Vault cleanup — duplicate note removal and script-note sync

**Files:**
- Delete: `/Users/shlee/mynotes/03_Resources/Scripts/ssl-api-manager.md`
- Modify: `/Users/shlee/mynotes/03_Resources/Scripts/CDN/ssl-api-manager.md`
- Modify: `/Users/shlee/mynotes/03_Resources/Scripts/CDN/ssl_workflow.md`

**Interfaces:** none (documentation-only task).

- [ ] **Step 1: Confirm the duplicate is still byte-identical, then delete it**

```bash
diff /Users/shlee/mynotes/03_Resources/Scripts/ssl-api-manager.md /Users/shlee/mynotes/03_Resources/Scripts/CDN/ssl-api-manager.md && echo "IDENTICAL — safe to delete"
rm /Users/shlee/mynotes/03_Resources/Scripts/ssl-api-manager.md
```

Expected: `IDENTICAL — safe to delete` printed before the file is removed. If the diff shows any difference, stop and reconcile manually instead of deleting.

- [ ] **Step 2: Read the current notes before editing**

Read `/Users/shlee/mynotes/03_Resources/Scripts/CDN/ssl-api-manager.md` and `/Users/shlee/mynotes/03_Resources/Scripts/CDN/ssl_workflow.md` in full (needed before using the Edit tool, and to find the exact `updated:` line and the right section to extend).

- [ ] **Step 3: Update `03_Resources/Scripts/CDN/ssl_workflow.md`**

Using the Edit tool:
- Change the frontmatter `updated:` field to today's date (only if it isn't already today's date — per CLAUDE.md, don't touch it if already current).
- In the "주요 기능" or "사용법" section, add a bullet describing: (a) `--domain` now auto-locates `~/Certificate/{YYYYMMDD}_{도메인}/` and auto-detects vendor filenames (no more manual `ssl.crt`/`ssl.key`/`fullchain.pem` renaming required), (b) chain verification no longer depends on a per-customer `RootChain` directory, (c) encrypted private keys are auto-decrypted via `--ssl-key-password`/`ONS_SSL_KEY_PASSWORD`.
- Add a link to the new skill: `[[ons-ssl-certificate]]` (or a plain path reference, since it's a `.claude/skills/` file rather than a vault note — use a fenced-code path reference: `` `.claude/skills/ons-ssl-certificate/SKILL.md` ``).

- [ ] **Step 4: Update `03_Resources/Scripts/CDN/ssl-api-manager.md`**

Using the Edit tool, add a short cross-reference note (in the "관련 문서" section or equivalent) pointing to the new skill and to `ssl_workflow.py`'s note, since `ssl_api_manager.py` itself is unchanged by this plan.

- [ ] **Step 5: Verify no other notes still link to the deleted path**

```bash
grep -rl "Scripts/ssl-api-manager\]\]" /Users/shlee/mynotes --include="*.md" 2>/dev/null | grep -v "03_Resources/Scripts/CDN/ssl-api-manager.md"
```

Expected: no output (already confirmed empty during brainstorming; re-check here in case new links were added since).

---

## Task 7: End-to-end verification against real data and final regression pass

**Files:** none created/modified — verification only.

- [ ] **Step 1: Run the full automated test suite once more**

```bash
cd /Users/shlee/mynotes/ons-api-tools/ssl && python3 -m unittest discover -s tests -v
```

Expected: `OK`, all tests from Tasks 1-4 pass.

- [ ] **Step 2: Validate against the real `~/Certificate/` folders (manual, read-only)**

```bash
cd /Users/shlee/mynotes/ons-api-tools/ssl
python3 ssl_workflow.py validate --domain hani.com
python3 ssl_workflow.py validate --domain star_legendofymir_co_kr
```

Expected: both report certificate details, private key match, and chain verification `OK` — with no reference to any hardcoded customer directory, confirming the fix generalizes to real data untouched by the test suite.

- [ ] **Step 3: Regression-check the legacy fixed-filename fixtures still work**

```bash
python3 ssl_workflow.py validate --cert-dir certs/cdnbundle.ideadreamsoft.com
```

Expected: validates successfully exactly as before (this fixture already uses `ssl.crt`/`ssl.key`/`fullchain.pem`, confirming `--cert-dir` with pre-existing fixed filenames still works unchanged).

- [ ] **Step 4: Confirm no ambiguous-domain error path is reachable by accident**

```bash
python3 ssl_workflow.py validate --domain this-domain-does-not-exist.invalid
```

Expected: clear `[ERROR]` message stating no certificate directory was found under `~/Certificate/`, exit code 1 — not a stack trace.

- [ ] **Step 5: Report results and stop for user review**

Summarize pass/fail for Steps 1-4. Do not proceed to push or take any further action — this task's only job is confirmation that the real-world behavior matches the spec's test plan.
