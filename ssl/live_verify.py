#!/usr/bin/env python3
"""Check which certificate the edge IPs of a hostname actually serve.

After a deploy the ONS API reports success, but only a TLS handshake against
each edge IP shows whether the new certificate is live there. The IP set is
whatever the queried resolvers return, so the result covers those IPs and is
not a claim about the whole fleet.
"""

import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

# System resolver plus public ones: CDN DNS can answer differently per resolver
DEFAULT_RESOLVERS = (None, "8.8.8.8", "1.1.1.1")
_RECORD_TYPES = ("A", "AAAA")


def parse_dig(output: str) -> list:
    """IP literals from `dig +short` output (CNAMEs and error text dropped)."""
    ips = []
    for line in output.splitlines():
        try:
            ipaddress.ip_address(line.strip())
        except ValueError:
            continue
        ips.append(line.strip())
    return ips


def resolve_ips(host: str, resolvers: tuple = DEFAULT_RESOLVERS) -> list:
    """Union of A/AAAA answers for host across resolvers, sorted."""
    found = set()
    for resolver in resolvers:
        for rtype in _RECORD_TYPES:
            cmd = ["dig", "+short", "+time=3", "+tries=1"]
            if resolver:
                cmd.append(f"@{resolver}")
            cmd.extend([host, rtype])
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
            found.update(parse_dig(result.stdout))
    return sorted(found)


def fetch_served_fingerprint(ip: str, host: str) -> Optional[str]:
    """SHA-256 fingerprint of the leaf cert ip serves for SNI host, else None."""
    try:
        handshake = subprocess.run(
            [
                "openssl", "s_client", "-connect", f"[{ip}]:443" if ":" in ip else f"{ip}:443",
                "-servername", host,
            ],
            input="",
            capture_output=True,
            text=True,
            timeout=15,
        )  # fmt: skip
        x509 = subprocess.run(
            ["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
            input=handshake.stdout,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return None
    if x509.returncode != 0 or "=" not in x509.stdout:
        return None
    return x509.stdout.strip().split("=", 1)[1].upper()


def verify_host(
    host: str,
    expected_fingerprint: str,
    ips: Optional[list] = None,
    fetch: Callable = fetch_served_fingerprint,
    resolvers: tuple = DEFAULT_RESOLVERS,
) -> dict:
    """Compare what every IP of host serves with the expected fingerprint."""
    ips = resolve_ips(host, resolvers) if ips is None else ips
    with ThreadPoolExecutor(max_workers=8) as pool:
        served = dict(zip(ips, pool.map(lambda ip: fetch(ip, host), ips)))

    expected = expected_fingerprint.upper()
    unreachable = [ip for ip, fp in served.items() if fp is None]
    mismatched = {
        ip: fp for ip, fp in served.items() if fp is not None and fp != expected
    }
    matched = len(served) - len(unreachable) - len(mismatched)
    return {
        "host": host,
        "ok": bool(served) and matched == len(served),
        "total": len(served),
        "matched": matched,
        "mismatched": mismatched,
        "unreachable": unreachable,
        "ips": ips,
    }
