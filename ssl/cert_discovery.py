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
