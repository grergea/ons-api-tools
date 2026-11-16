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

# Archives and binary keystores are never read as PEM candidates
_IGNORED_SUFFIXES = {".zip", ".pfx", ".p12", ".jks"}
_IGNORED_NAMES = {".ds_store", "fullchain.pem"}

_CHAIN_PATTERN = re.compile(r"chain", re.IGNORECASE)
_FULLCHAIN_PATTERN = re.compile(r"fullchain", re.IGNORECASE)
_KEY_PATTERN = re.compile(r"key", re.IGNORECASE)
_NOPASS_KEY_PATTERN = re.compile(r"nopass.*key", re.IGNORECASE)
_CERT_PATTERN = re.compile(r"cert|\.(crt|cer|pem)$", re.IGNORECASE)
_BUNDLE_PATTERN = re.compile(r"\.all\.|fullchain", re.IGNORECASE)


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


def _has_cert_material(cert_dir: Path) -> bool:
    """True if cert_dir itself holds anything that looks like cert/key/chain."""
    return any(
        _CERT_PATTERN.search(f.name)
        or _KEY_PATTERN.search(f.name)
        or _CHAIN_PATTERN.search(f.name)
        for f in _relevant_files(cert_dir)
    )


def _candidate_subdirs(cert_dir: Path) -> list:
    """Immediate subfolders worth searching (no hidden dirs or __MACOSX)."""
    return sorted(
        p
        for p in cert_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".") and p.name != "__MACOSX"
    )


def discover_cert_bundle(cert_dir: Path) -> dict:
    """Auto-detect cert/key/chain files with vendor-arbitrary names.

    Returns {"cert": Path, "key": Path, "chain": Path | None,
    "bundle": Path | None}. Raises CertDiscoveryError if the cert or key
    candidate is missing or ambiguous (zero or multiple matches). A chain
    file is optional. "bundle" is a vendor-supplied cert+chain file
    (`*.all.*`) delivered next to the single leaf cert.

    If cert_dir holds no cert/key/chain files at all (e.g. an extra folder
    level left by unzipping the vendor archive), looks one level down and
    uses the single subfolder where discovery succeeds. Subfolders such as
    Convert/ or RootChain/ never qualify since they lack a cert+key pair.
    """
    try:
        return _discover_in_dir(cert_dir)
    except CertDiscoveryError as top_level_error:
        if _has_cert_material(cert_dir):
            raise

        found = []
        for sub in _candidate_subdirs(cert_dir):
            try:
                found.append(_discover_in_dir(sub))
            except CertDiscoveryError:
                continue

        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            names = [b["cert"].parent.name for b in found]
            raise CertDiscoveryError(
                f"Found certificate files in multiple subfolders of {cert_dir}: "
                f"{names}. Pass --cert-dir to pick one."
            )
        raise top_level_error


def _discover_in_dir(cert_dir: Path) -> dict:
    """Discover cert/key/chain files directly inside cert_dir."""
    files = _relevant_files(cert_dir)

    # A vendor "fullchain" file is a cert+chain bundle, not a chain-only file
    chain_candidates = [
        f
        for f in files
        if _CHAIN_PATTERN.search(f.name) and not _FULLCHAIN_PATTERN.search(f.name)
    ]
    all_key_files = [
        f
        for f in files
        if _KEY_PATTERN.search(f.name)
        and f not in chain_candidates
        and not _FULLCHAIN_PATTERN.search(f.name)
    ]
    nopass_key_candidates = [f for f in files if _NOPASS_KEY_PATTERN.search(f.name)]
    key_candidates = nopass_key_candidates or all_key_files
    # Every key file is excluded here, not only the selected one: a plain
    # `*_key.pem` next to a `nopass_*` key would otherwise match `.pem$`.
    cert_files = [
        f
        for f in files
        if _CERT_PATTERN.search(f.name)
        and f not in chain_candidates
        and f not in all_key_files
        and f not in nopass_key_candidates
    ]
    bundle_files = [f for f in cert_files if _BUNDLE_PATTERN.search(f.name)]
    cert_candidates = [f for f in cert_files if f not in bundle_files]
    bundle = None

    if len(cert_candidates) == 1 and len(bundle_files) <= 1:
        bundle = bundle_files[0] if bundle_files else None
    elif not cert_candidates and len(bundle_files) == 1:
        cert_candidates = bundle_files
    else:
        cert_candidates = cert_files

    if len(cert_candidates) != 1:
        raise CertDiscoveryError(
            f"Expected exactly 1 certificate file in {cert_dir}, found "
            f"{len(cert_candidates)}: {[f.name for f in cert_candidates]}"
        )
    key_candidates = _select_key(cert_candidates[0], all_key_files, key_candidates)
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
        "bundle": bundle,
    }


def _public_key(args: list) -> Optional[str]:
    """Public key PEM printed by `openssl <args>`, or None if it can't be read."""
    result = subprocess.run(
        ["openssl", *args],
        capture_output=True,
        text=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
    )
    out = result.stdout.strip()
    return out if result.returncode == 0 and "BEGIN PUBLIC KEY" in out else None


def key_matches_cert(cert_path: Path, key_path: Path) -> Optional[bool]:
    """True/False if the key pairs with the cert, None if either is unreadable.

    Compares public keys, so it works for RSA and EC. A password-protected key
    can't be read without the password and yields None.
    """
    cert_pub = _public_key(["x509", "-in", str(cert_path), "-pubkey", "-noout"])
    key_pub = _public_key(["pkey", "-in", str(key_path), "-pubout"])
    if cert_pub is None or key_pub is None:
        return None
    return cert_pub == key_pub


def _select_key(cert_path: Path, all_keys: list, name_preferred: list) -> list:
    """Choose the key by content, falling back to filename when unreadable.

    A key that provably pairs with the certificate wins over any filename
    heuristic. If every readable key mismatches, raise rather than fall back.
    """
    verdicts = {k: key_matches_cert(cert_path, k) for k in all_keys}
    matching = [k for k, v in verdicts.items() if v is True]
    if matching:
        return matching[:1]
    readable = [k for k, v in verdicts.items() if v is not None]
    if readable and len(readable) == len(all_keys):
        raise CertDiscoveryError(
            f"None of the private key files matches the certificate "
            f"{cert_path.name}: {[k.name for k in all_keys]}"
        )
    return name_preferred


def is_key_encrypted(key_path: Path) -> bool:
    """Return True if the private key requires a password to load."""
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-noout", "-check"],
        capture_output=True,
        text=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
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
        [
            "openssl",
            "rsa",
            "-in",
            str(key_path),
            "-passin",
            "env:_ONS_KEY_PASSIN",
            "-out",
            str(decrypted_path),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise CertDiscoveryError(
            f"Failed to decrypt {key_path.name}: {result.stderr.strip()}"
        )

    return decrypted_path


_DN_CN = re.compile(r"CN\s*=\s*([^,/\n]+)")


def describe_certificate(cert_path: Path) -> dict:
    """Read identity fields straight from the certificate file.

    Callers should identify a certificate by these values, never by the
    folder or file name it was delivered under.
    """
    result = subprocess.run(
        [
            "openssl", "x509", "-in", str(cert_path), "-noout",
            "-serial", "-subject", "-issuer", "-dates", "-ext", "subjectAltName",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip
    if result.returncode != 0:
        raise CertDiscoveryError(
            f"Cannot read certificate {cert_path}: {result.stderr.strip()}"
        )

    # Separate call: with -ext in the same invocation, OpenSSL 4.1 prints a
    # fingerprint that differs from the certificate's real SHA-256 fingerprint.
    fp = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-fingerprint", "-sha256"],
        capture_output=True,
        text=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
    )
    info = {"san": [], "fingerprint": fp.stdout.strip().split("=", 1)[-1].upper()}
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("serial="):
            info["serial"] = line.split("=", 1)[1].upper()
        elif line.startswith("subject="):
            m = _DN_CN.search(line)
            info["subject_cn"] = m.group(1).strip() if m else ""
        elif line.startswith("issuer="):
            m = _DN_CN.search(line)
            info["issuer_cn"] = m.group(1).strip() if m else ""
        elif line.startswith("notBefore="):
            info["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            info["not_after"] = line.split("=", 1)[1].strip()
        elif line.startswith("DNS:"):
            info["san"] = [
                part.strip()[4:] for part in line.split(",") if part.strip().startswith("DNS:")
            ]
    return info


def san_covers_domain(san: list, domain: str) -> bool:
    """True if any SAN entry covers domain (a wildcard matches exactly one label)."""
    domain = domain.lower().rstrip(".")
    for entry in san:
        entry = entry.lower().rstrip(".")
        if entry == domain:
            return True
        if entry.startswith("*."):
            head, _, rest = domain.partition(".")
            if head and rest == entry[2:]:
                return True
    return False


def build_fullchain(
    cert_path: Path, chain_path: Optional[Path], output_path: Path
) -> Path:
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
    otherwise builds one from the vendor's cert+chain bundle if there is
    one, else from the discovered cert + chain. Decrypts the private key
    if needed.
    """
    bundle = discover_cert_bundle(cert_dir)
    key_path = ensure_decrypted_key(bundle["key"], key_password)

    # Next to the discovered files, which may be one folder below cert_dir
    fullchain_path = bundle["cert"].parent / "fullchain.pem"
    if not fullchain_path.exists():
        if bundle["bundle"]:
            build_fullchain(bundle["bundle"], None, fullchain_path)
        else:
            build_fullchain(bundle["cert"], bundle["chain"], fullchain_path)

    return {
        "cert": bundle["cert"],
        "key": key_path,
        "chain": bundle["chain"],
        "fullchain": fullchain_path,
    }
