#!/usr/bin/env python3
"""
SSL Certificate Workflow Automation for ONS CDN Platform.

This script automates SSL certificate management workflows:
- new:      New certificate registration
- renew:    Existing certificate renewal
- domains:  Domain mapping changes
- lookup:  Certificate information lookup
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


# --- Configuration ---
DEFAULT_AUTH = {
    "id": "cdnetworks",
    "api_key": "d3a5acf9-b537-4a30-a269-c95d1c599bcd"
}

SCRIPT_DIR = Path(__file__).parent
# ssl_api_manager.py is located in the ons-api-tools/ssl/ directory
# From ssl-certificate-workflow/, go up 4 levels to reach mynotes/
MANAGER_SCRIPT = Path("/Users/shlee/leesh/mynotes/ons-api-tools/ssl/ssl_api_manager.py")


# --- Helper Functions ---

def print_step(step_num: int, total: int, message: str) -> None:
    """Print a workflow step."""
    print(f"\n[{step_num}/{total}] {message}")
    print("=" * 60)


def print_success(message: str) -> None:
    """Print success message."""
    print(f"\033[92m[SUCCESS]\033[0m {message}")


def print_error(message: str) -> None:
    """Print error message."""
    print(f"\033[91m[ERROR]\033[0m {message}", file=sys.stderr)


def print_warning(message: str) -> None:
    """Print warning message."""
    print(f"\033[93m[WARNING]\033[0m {message}")


def extract_cn(dn: str) -> str:
    """Extract CN from a Distinguished Name string."""
    if not dn:
        return "N/A"
    for part in dn.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:].strip()
    return dn


def _parse_expiry_date(not_after: str) -> Optional[int]:
    """Parse certificate notAfter string and return days_left, or None on failure."""
    date_formats = ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"]
    for fmt in date_formats:
        try:
            expiry_date = datetime.strptime(not_after, fmt)
            now = datetime.now(expiry_date.tzinfo) if expiry_date.tzinfo else datetime.now()
            return (expiry_date - now).days
        except ValueError:
            continue
    return None


def _auth_args(auth: dict) -> list:
    """Build common auth argument list for ssl_api_manager.py."""
    return ["--id", auth["id"], "--api-key", auth["api_key"]]


def _warn_cert_expiry(raw: str) -> None:
    """Print warning if certificate is expired or expiring soon."""
    if "EXPIRED" in raw:
        print_warning("Certificate is expired!")
    elif "EXPIRES IN" in raw:
        match = re.search(r"EXPIRES IN (\d+) DAYS", raw)
        if match and int(match.group(1)) <= 30:
            print_warning(f"Certificate expires in {match.group(1)} days")


# --- Certificate Verification Functions ---

def verify_certificate_expiry(cert_path: str) -> dict:
    """Verify certificate expiration and return details."""
    try:
        cmd = [
            "openssl", "x509", "-in", cert_path, "-noout",
            "-dates", "-subject", "-issuer", "-serial"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            return {"valid": False, "error": f"Failed to parse certificate: {result.stderr}"}

        lines = result.stdout.strip().split("\n")
        cert_info = {}
        for line in lines:
            if "notBefore=" in line:
                cert_info["notBefore"] = line.split("=", 1)[1].strip()
            elif "notAfter=" in line:
                cert_info["notAfter"] = line.split("=", 1)[1].strip()
            elif "subject=" in line:
                cert_info["subject"] = line.split("=", 1)[1].strip()
            elif "issuer=" in line:
                cert_info["issuer"] = line.split("=", 1)[1].strip()
            elif "serial=" in line:
                cert_info["serial"] = line.split("=", 1)[1].strip()

        # Parse expiration date
        days_left = _parse_expiry_date(cert_info.get("notAfter", ""))

        status = "unknown"
        if days_left is not None:
            if days_left < 0:
                status = "expired"
            elif days_left <= 30:
                status = "expiring_soon"
            else:
                status = "valid"

        return {
            "valid": True,
            "subject": cert_info.get("subject", "N/A"),
            "issuer": cert_info.get("issuer", "N/A"),
            "serial": cert_info.get("serial", "N/A"),
            "notBefore": cert_info.get("notBefore", "N/A"),
            "notAfter": cert_info.get("notAfter", "N/A"),
            "days_left": days_left,
            "status": status
        }

    except subprocess.TimeoutExpired:
        return {"valid": False, "error": "Timeout while verifying certificate"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def verify_private_key(key_path: str) -> dict:
    """Verify private key is valid and get its modulus."""
    try:
        # Check if key is valid
        cmd = ["openssl", "rsa", "-in", key_path, "-check", "-noout"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            return {"valid": False, "error": "Invalid private key"}

        # Get modulus for matching with certificate
        cmd = ["openssl", "rsa", "-in", key_path, "-modulus", "-noout"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            return {"valid": True, "modulus": result.stdout.strip()}
        else:
            return {"valid": True, "modulus": None}

    except Exception as e:
        return {"valid": False, "error": str(e)}


def verify_key_cert_match(cert_path: str, key_path: str) -> bool:
    """Verify that private key matches the certificate."""
    try:
        # Get certificate modulus
        cert_cmd = ["openssl", "x509", "-in", cert_path, "-modulus", "-noout"]
        cert_result = subprocess.run(cert_cmd, capture_output=True, text=True, timeout=10)

        # Get key modulus
        key_cmd = ["openssl", "rsa", "-in", key_path, "-modulus", "-noout"]
        key_result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=10)

        if cert_result.returncode == 0 and key_result.returncode == 0:
            return cert_result.stdout.strip() == key_result.stdout.strip()
        return False

    except Exception:
        return False


def validate_certificate_files(cert_dir: str, domain: str = None) -> dict:
    """
    Validate certificate files in a directory.

    Returns dict with:
        - valid: bool
        - errors: list of error messages
        - warnings: list of warning messages
        - cert_info: certificate details
    """
    errors = []
    warnings = []

    cert_path = Path(cert_dir) / "ssl.crt"
    key_path = Path(cert_dir) / "ssl.key"
    fullchain_path = Path(cert_dir) / "fullchain.pem"

    # Check required files exist
    if not cert_path.exists():
        errors.append(f"Certificate file not found: {cert_path}")
    if not key_path.exists():
        errors.append(f"Private key file not found: {key_path}")

    if errors:
        return {"valid": False, "errors": errors, "warnings": warnings}

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

    # Verify certificate chain (if fullchain exists)
    chain_info = None
    if fullchain_path.exists():
        chain_info = verify_certificate_chain(str(fullchain_path), cert_dir)
        if chain_info.get("valid"):
            print_success(f"Certificate chain verified ({len(chain_info.get('chain', []))//2} certificates)")
        else:
            errors.append(f"Certificate chain verification failed: {chain_info.get('error', 'Unknown error')}")

    # Check domain match if provided
    if domain and cert_info.get("subject"):
        if domain.lower() not in cert_info["subject"].lower():
            # Check SAN in fullchain if available
            if fullchain_path.exists():
                san_check = subprocess.run(
                    ["openssl", "x509", "-in", str(fullchain_path), "-noout", "-text"],
                    capture_output=True, text=True, timeout=10
                )
                if domain.lower() not in san_check.stdout.lower():
                    warnings.append(f"Domain '{domain}' not found in certificate Subject or SAN")
            else:
                warnings.append(f"Domain '{domain}' not found in certificate Subject")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "cert_info": cert_info,
        "chain_info": chain_info
    }


def verify_certificate_chain(fullchain_path: str, cert_dir: str) -> dict:
    """
    Verify the full certificate chain using OpenSSL.

    Returns dict with:
        - valid: bool
        - chain: list of certificate subjects
        - error: error message if failed
    """
    try:
        # Look for root chain files in the original directory
        original_dir = Path(cert_dir).parent / f"{Path(cert_dir).name}_2026032792EC5"
        root_chain_path = original_dir / "RootChain" / "root-chain-bundle.pem"
        intermediate_path = original_dir / "RootChain" / "GoGetSSLRSADVCAChain2.crt.pem"

        # If chain files don't exist, try alternate locations
        if not root_chain_path.exists():
            root_chain_path = original_dir / "RootChain" / "chain-bundle.pem"
        if not root_chain_path.exists():
            return {"valid": False, "error": "Root chain file not found"}

        # Verify using openssl
        cmd = [
            "openssl", "verify",
            "-CAfile", str(root_chain_path),
            "-untrusted", str(intermediate_path) if intermediate_path.exists() else str(root_chain_path),
            str(fullchain_path)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        # Extract certificate chain info using pipe
        chain_cmd = f"""
            openssl crl2pkcs7 -nocrl -certfile "{fullchain_path}" | \
            openssl pkcs7 -print_certs -noout 2>/dev/null
        """
        chain_result = subprocess.run(
            chain_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
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

        if result.returncode == 0:
            return {
                "valid": True,
                "chain": chain,
                "message": result.stdout.strip()
            }
        else:
            return {
                "valid": False,
                "chain": chain,
                "error": result.stderr.strip() or result.stdout.strip()
            }

    except subprocess.TimeoutExpired:
        return {"valid": False, "error": "Timeout while verifying certificate chain"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def print_certificate_info(cert_info: dict, key_info: dict = None, chain_info: dict = None) -> None:
    """Print formatted certificate information."""
    print(f"\n{'='*60}")
    print("Certificate Information")
    print(f"{'='*60}")
    print(f"  Subject: {cert_info.get('subject', 'N/A')}")
    print(f"  Issuer: {cert_info.get('issuer', 'N/A')}")
    print(f"  Serial: {cert_info.get('serial', 'N/A')}")
    print(f"  Valid From: {cert_info.get('notBefore', 'N/A')}")
    print(f"  Valid Until: {cert_info.get('notAfter', 'N/A')}")

    days_left = cert_info.get("days_left")
    if days_left is not None:
        if days_left < 0:
            print(f"  Status: \033[91m[EXPIRED]\033[0m")
        elif days_left <= 30:
            print(f"  Status: \033[93m[EXPIRES IN {days_left} DAYS]\033[0m")
        else:
            print(f"  Status: \033[92m[VALID - {days_left} days]\033[0m")

    if key_info:
        print(f"\nPrivate Key: \033[92mOK\033[0m")

    # Print certificate chain info
    if chain_info:
        print(f"\nCertificate Chain Verification:")
        if chain_info.get("valid"):
            print(f"  Chain Status: \033[92mOK\033[0m")
            if chain_info.get("chain"):
                chain = chain_info["chain"]
                print(f"  Chain ({len(chain)} certificates):")
                for i, cert in enumerate(chain, 1):
                    subject = cert.get("subject", "Unknown")
                    cn = extract_cn(subject)
                    print(f"    {i}. {cn}")
        else:
            print(f"  Chain Status: \033[91mFAILED\033[0m")
            if chain_info.get("error"):
                print(f"    Error: {chain_info['error']}")

    print(f"{'='*60}")


def run_manager_command(command: list) -> dict:
    """Run ssl_api_manager.py command and return parsed JSON response."""
    cmd = ["python3", str(MANAGER_SCRIPT)] + command
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print_error(f"Command failed: {' '.join(command)}")
        print_error(result.stderr)
        return {"success": False, "error": result.stderr}

    try:
        return {"success": True, "data": json.loads(result.stdout)}
    except json.JSONDecodeError:
        return {"success": True, "raw": result.stdout}


def get_auth_params(id: str = None, api_key: str = None) -> dict:
    """Get authentication parameters."""
    return {
        "id": id or DEFAULT_AUTH["id"],
        "api_key": api_key or DEFAULT_AUTH["api_key"]
    }


def lookup_cert(ssl_file_name: str, auth: dict, verify: bool = False) -> dict:
    """Lookup certificate information."""
    cmd = ["lookup", *_auth_args(auth), "--ssl-file-name", ssl_file_name]
    if verify:
        cmd.append("--verify")

    result = run_manager_command(cmd)

    if not result["success"]:
        return {"found": False, "staging_ip": None}

    # Parse output to extract staging IP
    staging_ip = None
    if "raw" in result:
        for line in result["raw"].split("\n"):
            if "Staging Server IP:" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    staging_ip = parts[1].strip()
                    break

    return {
        "found": True,
        "staging_ip": staging_ip,
        "raw": result.get("raw", "")
    }


# --- Workflow Functions ---

def workflow_new_cert(
    ssl_file_name: str,
    ssl_cert: str,
    ssl_key: str,
    domain_list: str = None,
    memo: str = None,
    auth: dict = None,
    skip_verify: bool = False,
    auto_deploy: bool = True
) -> dict:
    """
    Workflow for new certificate registration.

    Steps:
        1. staging-deploy
        2. lookup --verify (if not skipped)
        3. deploy (if auto_deploy)
    """
    auth = auth or get_auth_params()
    steps = 3 if auto_deploy else 2

    # Step 1: Staging Deploy
    print_step(1, steps, f"Deploying new certificate to staging: {ssl_file_name}")

    cmd = ["staging-deploy", *_auth_args(auth), "--ssl-cert", ssl_cert, "--ssl-key", ssl_key]
    if domain_list:
        cmd.extend(["--domain-list", domain_list])
    if memo:
        cmd.extend(["--memo", memo])

    result = run_manager_command(cmd)
    if not result["success"]:
        return {"success": False, "step": 1}

    api_resp = result.get("data", {}).get("api_response", {})
    if api_resp.get("result_code") != "200":
        print_error(f"API error: {api_resp.get('result_msg', 'Unknown')}")
        return {"success": False, "step": 1, "error": api_resp}

    print_success(f"Staging deployment successful")
    ssl_file_name = api_resp.get("data", {}).get("ssl_file_name", ssl_file_name)

    # Step 2: Verify
    if skip_verify:
        print_step(2, steps, "Skipping verification")
    else:
        print_step(2, steps, f"Verifying certificate on staging")

        lookup_result = lookup_cert(ssl_file_name, auth, verify=True)
        if not lookup_result["found"]:
            print_error("Failed to lookup certificate")
            return {"success": False, "step": 2}

        _warn_cert_expiry(lookup_result.get("raw", ""))

    # Step 3: Final Deploy
    if auto_deploy:
        print_step(3, steps, f"Finalizing deployment: {ssl_file_name}")

        result = run_manager_command(["deploy", *_auth_args(auth), "--ssl-file-name", ssl_file_name])
        if not result["success"]:
            return {"success": False, "step": 3}

        api_resp = result.get("data", {}).get("api_response", {})
        if api_resp.get("result_code") != "200":
            print_error(f"API error: {api_resp.get('result_msg', 'Unknown')}")
            return {"success": False, "step": 3}

        print_success("Deployment finalized")
    else:
        print_warning("Auto-deploy skipped. Run 'deploy' command manually when ready.")

    return {
        "success": True,
        "ssl_file_name": ssl_file_name,
        "staging_ip": lookup_result.get("staging_ip") if not skip_verify else None
    }


def workflow_renew_cert(
    ssl_file_name: str,
    ssl_cert: str,
    ssl_key: str,
    memo: str = None,
    auth: dict = None,
    skip_verify: bool = False,
    auto_deploy: bool = True
) -> dict:
    """
    Workflow for existing certificate renewal.

    Steps:
        1. staging-update
        2. lookup --verify (if not skipped)
        3. deploy (if auto_deploy)
    """
    auth = auth or get_auth_params()
    steps = 3 if auto_deploy else 2

    # Step 1: Staging Update
    print_step(1, steps, f"Updating certificate on staging: {ssl_file_name}")

    cmd = ["staging-update", *_auth_args(auth), "--ssl-file-name", ssl_file_name,
           "--ssl-cert", ssl_cert, "--ssl-key", ssl_key]
    if memo:
        cmd.extend(["--memo", memo])

    result = run_manager_command(cmd)
    if not result["success"]:
        return {"success": False, "step": 1}

    api_resp = result.get("data", {}).get("api_response", {})
    if api_resp.get("result_code") != "200":
        print_error(f"API error: {api_resp.get('result_msg', 'Unknown')}")
        return {"success": False, "step": 1, "error": api_resp}

    print_success(f"Staging update successful")

    # Step 2: Verify
    if skip_verify:
        print_step(2, steps, "Skipping verification")
    else:
        print_step(2, steps, f"Verifying certificate on staging")

        lookup_result = lookup_cert(ssl_file_name, auth, verify=True)
        if not lookup_result["found"]:
            print_error("Failed to lookup certificate")
            return {"success": False, "step": 2}

        _warn_cert_expiry(lookup_result.get("raw", ""))

    # Step 3: Final Deploy
    if auto_deploy:
        print_step(3, steps, f"Finalizing deployment: {ssl_file_name}")

        result = run_manager_command(["deploy", *_auth_args(auth), "--ssl-file-name", ssl_file_name])
        if not result["success"]:
            return {"success": False, "step": 3}

        api_resp = result.get("data", {}).get("api_response", {})
        if api_resp.get("result_code") != "200":
            print_error(f"API error: {api_resp.get('result_msg', 'Unknown')}")
            return {"success": False, "step": 3}

        print_success("Deployment finalized")
    else:
        print_warning("Auto-deploy skipped. Run 'deploy' command manually when ready.")

    return {
        "success": True,
        "ssl_file_name": ssl_file_name,
        "staging_ip": lookup_result.get("staging_ip") if not skip_verify else None
    }


def workflow_domain_update(
    ssl_file_name: str,
    add_domain_list: str = None,
    del_domain_list: str = None,
    ssl_cert: str = None,
    ssl_key: str = None,
    memo: str = None,
    auth: dict = None,
    skip_verify: bool = False,
    auto_deploy: bool = True
) -> dict:
    """
    Workflow for domain mapping changes.

    Steps:
        1. staging-update (domain changes)
        2. lookup --verify (if not skipped)
        3. deploy (if auto_deploy)
    """
    auth = auth or get_auth_params()
    steps = 3 if auto_deploy else 2

    if not add_domain_list and not del_domain_list and not ssl_cert:
        print_error("Must specify at least one of: add-domain-list, del-domain-list, ssl-cert")
        return {"success": False}

    # Step 1: Staging Update
    action = "Updating domains" if (add_domain_list or del_domain_list) else "Updating certificate"
    print_step(1, steps, f"{action} on staging: {ssl_file_name}")

    cmd = ["staging-update", *_auth_args(auth), "--ssl-file-name", ssl_file_name]
    if add_domain_list:
        cmd.extend(["--add-domain-list", add_domain_list])
    if del_domain_list:
        cmd.extend(["--del-domain-list", del_domain_list])
    if ssl_cert:
        cmd.extend(["--ssl-cert", ssl_cert])
    if ssl_key:
        cmd.extend(["--ssl-key", ssl_key])
    if memo:
        cmd.extend(["--memo", memo])

    result = run_manager_command(cmd)
    if not result["success"]:
        return {"success": False, "step": 1}

    api_resp = result.get("data", {}).get("api_response", {})
    if api_resp.get("result_code") != "200":
        print_error(f"API error: {api_resp.get('result_msg', 'Unknown')}")
        return {"success": False, "step": 1, "error": api_resp}

    print_success(f"Staging update successful")

    # Step 2: Verify
    if skip_verify:
        print_step(2, steps, "Skipping verification")
    else:
        print_step(2, steps, f"Verifying changes on staging")

        lookup_result = lookup_cert(ssl_file_name, auth, verify=True)
        if not lookup_result["found"]:
            print_error("Failed to lookup certificate")
            return {"success": False, "step": 2}

    # Step 3: Final Deploy
    if auto_deploy:
        print_step(3, steps, f"Finalizing deployment: {ssl_file_name}")

        result = run_manager_command(["deploy", *_auth_args(auth), "--ssl-file-name", ssl_file_name])
        if not result["success"]:
            return {"success": False, "step": 3}

        api_resp = result.get("data", {}).get("api_response", {})
        if api_resp.get("result_code") != "200":
            print_error(f"API error: {api_resp.get('result_msg', 'Unknown')}")
            return {"success": False, "step": 3}

        print_success("Deployment finalized")
    else:
        print_warning("Auto-deploy skipped. Run 'deploy' command manually when ready.")

    return {
        "success": True,
        "ssl_file_name": ssl_file_name
    }


def workflow_lookup(
    ssl_file_name: str,
    auth: dict = None,
    verify: bool = False
) -> dict:
    """
    Lookup certificate information.

    Step:
        1. lookup [--verify]
    """
    auth = auth or get_auth_params()

    print_step(1, 1, f"Looking up certificate: {ssl_file_name}")

    result = lookup_cert(ssl_file_name, auth, verify=verify)

    if result.get("raw"):
        print(result["raw"])

    return {
        "success": result["found"],
        "staging_ip": result.get("staging_ip")
    }


def workflow_validate(
    cert_dir: str,
    domain: str = None
) -> dict:
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

    # Validate certificate files
    validation = validate_certificate_files(cert_dir, domain)

    # Print certificate info
    if validation.get("cert_info"):
        print_certificate_info(
            validation["cert_info"],
            chain_info=validation.get("chain_info")
        )

    # Print errors
    if validation.get("errors"):
        print("\n\033[91mErrors:\033[0m")
        for error in validation["errors"]:
            print(f"  - {error}")

    # Print warnings
    if validation.get("warnings"):
        print("\n\033[93mWarnings:\033[0m")
        for warning in validation["warnings"]:
            print(f"  - {warning}")

    if validation["valid"]:
        print_success("All validations passed!")
        return {"success": True, "cert_dir": cert_dir}
    else:
        print_error("Validation failed!")
        return {"success": False, "cert_dir": cert_dir}


def get_ons_cdn_cert_info(ssl_file_name: str, auth: dict) -> dict:
    """
    Get certificate information from ONS CDN staging server.

    Returns dict with:
        - success: bool
        - staging_ip: str or None
        - serial: str or None
        - subject: str or None
        - issuer: str or None
        - not_before: str or None
        - not_after: str or None
        - days_left: int or None
    """
    # Step 1: Get staging IP from history API
    cmd = ["python3", str(MANAGER_SCRIPT), "history", *_auth_args(auth), "--ssl-file-name", ssl_file_name]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    if result.returncode != 0:
        return {"success": False, "error": f"History API failed: {result.stderr}"}

    try:
        data = json.loads(result.stdout)
        api_resp = data.get("api_response", {})
        if api_resp.get("result_code") != "200":
            return {"success": False, "error": f"API error: {api_resp.get('result_msg')}"}

        history_data = api_resp.get("data", {})
        staging_history = history_data.get("staging_history", [])
        deploy_history = history_data.get("deploy_history", [])

        staging_ip = None
        cname = None
        service_domain = None

        # Try staging_history first
        if staging_history:
            latest_staging = staging_history[0]
            staging_ip = latest_staging.get("pv_ip")
            cname = latest_staging.get("cname", "")
            service_domain = latest_staging.get("service_domain", "")
        # Fall back to deploy_history if staging is empty
        elif deploy_history:
            latest_deploy = deploy_history[0]
            cname = latest_deploy.get("cname", "")
            service_domain = latest_deploy.get("service_domain", "")

        if not service_domain:
            return {"success": False, "error": "No deployment history found"}

        # Step 2: Connect to staging server and get certificate info using pipe
        primary_domain = cname.split(".58.wskam.com")[0] if ".58.wskam.com" in cname else ssl_file_name

        # If we don't have staging IP, try to resolve the domain
        if not staging_ip:
            print_warning("Staging IP not found in history, attempting DNS resolution...")
            try:
                resolved_ip = socket.gethostbyname(service_domain)
                staging_ip = resolved_ip
                print_success(f"Resolved {service_domain} -> {staging_ip}")
            except socket.gaierror:
                return {"success": False, "error": f"Could not resolve domain: {service_domain}"}


        # Use shell pipe to get certificate directly
        shell_cmd = f'openssl s_client -connect {staging_ip}:443 -servername {primary_domain} </dev/null 2>/dev/null | openssl x509 -noout -serial -subject -issuer -dates'
        cert_result = subprocess.run(
            shell_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )

        if cert_result.returncode != 0:
            return {"success": False, "error": f"Failed to get certificate from {staging_ip}: {cert_result.stderr}"}

        # Parse certificate info
        serial = None
        subject = None
        issuer = None
        not_before = None
        not_after = None

        for line in cert_result.stdout.strip().split("\n"):
            line = line.strip()
            if line.startswith("serial="):
                serial = line.split("=", 1)[1].strip()
            elif line.startswith("subject="):
                subject = line.split("=", 1)[1].strip()
            elif line.startswith("issuer="):
                issuer = line.split("=", 1)[1].strip()
            elif line.startswith("notBefore="):
                not_before = line.split("=", 1)[1].strip()
            elif line.startswith("notAfter="):
                not_after = line.split("=", 1)[1].strip()

        # Calculate days left
        days_left = _parse_expiry_date(not_after) if not_after else None

        return {
            "success": True,
            "staging_ip": staging_ip,
            "cname": cname,
            "service_domain": service_domain,
            "serial": serial,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "days_left": days_left
        }

    except json.JSONDecodeError:
        return {"success": False, "error": "Failed to parse API response"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def print_comparison(
    local_info: dict,
    ons_info: dict,
    domain: str = None
) -> None:
    """Print comparison table between local and ONS CDN certificate."""
    print(f"\n{'='*80}")
    print("Certificate Comparison: Local vs ONS CDN")
    print(f"{'='*80}")

    def status_icon(matches: bool) -> str:
        return "\033[92m✓\033[0m" if matches else "\033[91m✗\033[0m"

    # Table header
    print(f"{'항목':<20} {'로컬':<35} {'ONS CDN':<35} {'상태':<8}")
    print("-" * 100)

    # Serial
    local_serial = local_info.get("serial", "N/A")
    ons_serial = ons_info.get("serial", "N/A")
    serial_match = local_serial == ons_serial
    print(f"{'Serial':<20} {local_serial:<35} {ons_serial:<35} {status_icon(serial_match):<8}")

    # Subject/CN
    local_cn = extract_cn(local_info.get("subject", ""))
    ons_cn = extract_cn(ons_info.get("subject", ""))
    cn_match = local_cn == ons_cn
    print(f"{'Domain (CN)':<20} {local_cn:<35} {ons_cn:<35} {status_icon(cn_match):<8}")

    # Expiry Date
    local_expiry = local_info.get("notAfter", "N/A")
    ons_expiry = ons_info.get("not_after", ons_info.get("notAfter", "N/A"))
    expiry_match = local_expiry == ons_expiry
    print(f"{'만료일':<20} {local_expiry:<35} {ons_expiry:<35} {status_icon(expiry_match):<8}")

    # Days Left
    local_days = local_info.get("days_left", "N/A")
    ons_days = ons_info.get("days_left", "N/A")
    if isinstance(local_days, int) and isinstance(ons_days, int):
        days_match = local_days == ons_days
        print(f"{'남은 일수':<20} {f'{local_days}일':<35} {f'{ons_days}일':<35} {status_icon(days_match):<8}")
    else:
        print(f"{'남은 일수':<20} {str(local_days):<35} {str(ons_days):<35} {'N/A':<8}")

    # Issuer
    local_issuer = extract_cn(local_info.get("issuer", ""))
    ons_issuer = extract_cn(ons_info.get("issuer", ""))
    issuer_match = local_issuer == ons_issuer
    print(f"{'Issuer':<20} {local_issuer:<35} {ons_issuer:<35} {status_icon(issuer_match):<8}")

    print("=" * 100)

    # Overall result
    all_match = serial_match and cn_match and expiry_match and issuer_match
    if all_match:
        print(f"\n\033[92m결과: 로컬과 ONS CDN 인증서가 동일합니다 (업로드 불필요)\033[0m")
    else:
        print(f"\n\033[91m결과: 인증서가 다릅니다 (업로드 필요)\033[0m")


def workflow_compare(
    cert_dir: str,
    ssl_file_name: str,
    domain: str = None,
    auth: dict = None
) -> dict:
    """
    Compare local certificate with ONS CDN deployed certificate.

    Steps:
        1. Validate local certificate files
        2. Get ONS CDN certificate info
        3. Compare and display results
    """
    auth = auth or get_auth_params()

    # Step 1: Validate local certificate
    print_step(1, 3, f"로컬 인증서 검증: {cert_dir}")

    validation = validate_certificate_files(cert_dir, domain)
    local_cert_info = validation.get("cert_info", {})

    if not validation["valid"]:
        print_error("로컬 인증서 검증 실패!")
        for error in validation.get("errors", []):
            print(f"  - {error}")
        return {"success": False, "step": 1, "reason": "local_validation_failed"}

    if local_cert_info.get("status") == "expired":
        print_error("로컬 인증서가 만료되었습니다!")
        return {"success": False, "step": 1, "reason": "local_cert_expired"}

    print_success(f"로컬 인증서 유효함 (만료일: {local_cert_info.get('notAfter', 'N/A')})")

    # Step 2: Get ONS CDN certificate info
    print_step(2, 3, f"ONS CDN 인증서 조회: {ssl_file_name}")

    ons_info = get_ons_cdn_cert_info(ssl_file_name, auth)

    if not ons_info.get("success"):
        print_error(f"ONS CDN 인증서 조회 실패: {ons_info.get('error')}")
        return {"success": False, "step": 2, "reason": ons_info.get('error')}

    print_success(f"ONS CDN 인증서 조회 성공 (Staging IP: {ons_info.get('staging_ip')})")

    # Step 3: Compare
    print_step(3, 3, "비교 결과")

    print_comparison(local_cert_info, ons_info, domain)

    # Determine if upload is needed
    local_serial = local_cert_info.get("serial", "")
    ons_serial = ons_info.get("serial", "")

    if local_serial == ons_serial:
        return {
            "success": True,
            "match": True,
            "ssl_file_name": ssl_file_name,
            "local_serial": local_serial,
            "ons_serial": ons_serial
        }
    else:
        return {
            "success": True,
            "match": False,
            "ssl_file_name": ssl_file_name,
            "local_serial": local_serial,
            "ons_serial": ons_serial
        }


# --- Argument Parser ---

def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="SSL Certificate Workflow Automation for ONS CDN Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # New certificate registration
  %(prog)s new --ssl-file-name example.com --ssl-cert cert.pem --ssl-key key.pem --domain-list "cdn.example.com"

  # Renew existing certificate
  %(prog)s renew --ssl-file-name example.com --ssl-cert new_cert.pem --ssl-key new_key.pem

  # Add domains to existing certificate
  %(prog)s domains --ssl-file-name example.com --add-domain-list "new.example.com"

  # Lookup certificate info with verification
  %(prog)s lookup --ssl-file-name example.com --verify
        """
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Available commands"
    )

    # Common auth arguments
    auth_parser = argparse.ArgumentParser(add_help=False)
    auth_parser.add_argument("--id", help="Account ID (default: cdnetworks)")
    auth_parser.add_argument("--api-key", dest="api_key", help="API Key")

    # --- new command ---
    parser_new = subparsers.add_parser(
        "new",
        help="Register a new SSL certificate",
        parents=[auth_parser]
    )
    parser_new.add_argument("--ssl-file-name", dest="ssl_file_name", required=True,
                            help="Certificate file name (without extension)")
    parser_new.add_argument("--ssl-cert", dest="ssl_cert", required=True,
                            help="Path to SSL certificate file (fullchain)")
    parser_new.add_argument("--ssl-key", dest="ssl_key", required=True,
                            help="Path to SSL private key file")
    parser_new.add_argument("--domain-list", dest="domain_list",
                            help="Comma-separated list of domains")
    parser_new.add_argument("--memo", help="Memo for the deployment")
    parser_new.add_argument("--skip-verify", dest="skip_verify", action="store_true",
                            help="Skip verification step")
    parser_new.add_argument("--no-auto-deploy", dest="no_auto_deploy", action="store_true",
                            help="Skip automatic final deployment")
    parser_new.set_defaults(func=lambda args: workflow_new_cert(
        ssl_file_name=args.ssl_file_name,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        domain_list=args.domain_list,
        memo=args.memo,
        auth=get_auth_params(args.id, args.api_key),
        skip_verify=args.skip_verify,
        auto_deploy=not args.no_auto_deploy
    ))

    # --- renew command ---
    parser_renew = subparsers.add_parser(
        "renew",
        help="Renew an existing SSL certificate",
        parents=[auth_parser]
    )
    parser_renew.add_argument("--ssl-file-name", dest="ssl_file_name", required=True,
                              help="Certificate file name (without extension)")
    parser_renew.add_argument("--ssl-cert", dest="ssl_cert", required=True,
                              help="Path to new SSL certificate file")
    parser_renew.add_argument("--ssl-key", dest="ssl_key", required=True,
                              help="Path to new SSL private key file")
    parser_renew.add_argument("--memo", help="Memo for the update")
    parser_renew.add_argument("--skip-verify", dest="skip_verify", action="store_true",
                              help="Skip verification step")
    parser_renew.add_argument("--no-auto-deploy", dest="no_auto_deploy", action="store_true",
                              help="Skip automatic final deployment")
    parser_renew.set_defaults(func=lambda args: workflow_renew_cert(
        ssl_file_name=args.ssl_file_name,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        memo=args.memo,
        auth=get_auth_params(args.id, args.api_key),
        skip_verify=args.skip_verify,
        auto_deploy=not args.no_auto_deploy
    ))

    # --- domains command ---
    parser_domains = subparsers.add_parser(
        "domains",
        help="Update domain mappings for an existing certificate",
        parents=[auth_parser]
    )
    parser_domains.add_argument("--ssl-file-name", dest="ssl_file_name", required=True,
                               help="Certificate file name (without extension)")
    parser_domains.add_argument("--add-domain-list", dest="add_domain_list",
                               help="Comma-separated list of domains to add")
    parser_domains.add_argument("--del-domain-list", dest="del_domain_list",
                               help="Comma-separated list of domains to remove")
    parser_domains.add_argument("--ssl-cert", dest="ssl_cert",
                               help="Path to new SSL certificate file (optional)")
    parser_domains.add_argument("--ssl-key", dest="ssl_key",
                               help="Path to new SSL private key file (optional)")
    parser_domains.add_argument("--memo", help="Memo for the update")
    parser_domains.add_argument("--skip-verify", dest="skip_verify", action="store_true",
                               help="Skip verification step")
    parser_domains.add_argument("--no-auto-deploy", dest="no_auto_deploy", action="store_true",
                               help="Skip automatic final deployment")
    parser_domains.set_defaults(func=lambda args: workflow_domain_update(
        ssl_file_name=args.ssl_file_name,
        add_domain_list=args.add_domain_list,
        del_domain_list=args.del_domain_list,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        memo=args.memo,
        auth=get_auth_params(args.id, args.api_key),
        skip_verify=args.skip_verify,
        auto_deploy=not args.no_auto_deploy
    ))

    # --- validate command ---
    parser_validate = subparsers.add_parser(
        "validate",
        help="Validate SSL certificate files (local verification)"
    )
    parser_validate.add_argument("--cert-dir", dest="cert_dir", required=True,
                               help="Directory containing certificate files (ssl.crt, ssl.key, fullchain.pem)")
    parser_validate.add_argument("--domain", dest="domain",
                               help="Expected domain name to verify against certificate")
    parser_validate.set_defaults(func=lambda args: workflow_validate(
        cert_dir=args.cert_dir,
        domain=args.domain
    ))

    # --- compare command ---
    parser_compare = subparsers.add_parser(
        "compare",
        help="Compare local certificate with ONS CDN deployed certificate",
        parents=[auth_parser]
    )
    parser_compare.add_argument("--cert-dir", dest="cert_dir", required=True,
                               help="Directory containing certificate files (ssl.crt, ssl.key, fullchain.pem)")
    parser_compare.add_argument("--ssl-file-name", dest="ssl_file_name", required=True,
                               help="Certificate file name on ONS CDN (without extension)")
    parser_compare.add_argument("--domain", dest="domain",
                               help="Expected domain name to verify against certificate")
    parser_compare.set_defaults(func=lambda args: workflow_compare(
        cert_dir=args.cert_dir,
        ssl_file_name=args.ssl_file_name,
        domain=args.domain,
        auth=get_auth_params(args.id, args.api_key)
    ))

    # --- lookup command ---
    parser_lookup = subparsers.add_parser(
        "lookup",
        help="Lookup SSL certificate information",
        parents=[auth_parser]
    )
    parser_lookup.add_argument("--ssl-file-name", dest="ssl_file_name", required=True,
                              help="Certificate file name (without extension)")
    parser_lookup.add_argument("--verify", action="store_true",
                              help="Perform SSL certificate verification")
    parser_lookup.set_defaults(func=lambda args: workflow_lookup(
        ssl_file_name=args.ssl_file_name,
        auth=get_auth_params(args.id, args.api_key),
        verify=args.verify
    ))

    return parser


# --- Main ---

def main() -> None:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    result = args.func(args)

    print("\n" + "=" * 60)
    if result.get("success"):
        print_success("Workflow completed successfully")
        if result.get("ssl_file_name"):
            print(f"Certificate: {result['ssl_file_name']}")
        if result.get("staging_ip"):
            print(f"Staging IP: {result['staging_ip']}")
    else:
        print_error(f"Workflow failed at step {result.get('step', 'unknown')}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
