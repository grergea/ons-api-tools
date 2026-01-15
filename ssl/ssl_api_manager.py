#!/usr/bin/env python3
"""
SSL Certificate Management API CLI for ONS CDN Platform.

This script provides a command-line interface to manage SSL certificates
through the ONS CDN OpenAPI.
"""

import argparse
import json
import os
import sys
from typing import Any

import requests


# --- API Configuration ---
BASE_URL = "https://openapi.onscdn.com/cdnservice/ssl"
API_URLS = {
    "staging_deploy": f"{BASE_URL}/staging/deploy",
    "staging_update": f"{BASE_URL}/staging/update",
    "deploy": f"{BASE_URL}/update",
    "staging_cancel": f"{BASE_URL}/staging/cancel",
    "history": f"{BASE_URL}/history",
}


# --- Helper Functions ---

def handle_response(response: requests.Response) -> None:
    """Print the formatted JSON response from the API."""
    try:
        response.raise_for_status()
        data = response.json()
        print(json.dumps(data, indent=4, ensure_ascii=False))

        # Check API-level result code
        api_response = data.get("api_response", {})
        result_code = api_response.get("result_code", "")
        if result_code != "200":
            result_msg = api_response.get("result_msg", "Unknown error")
            print(f"\n[Warning] API returned non-success code: {result_code} - {result_msg}", file=sys.stderr)

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}", file=sys.stderr)
        print(f"Response body: {response.text}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("Failed to decode JSON from response.", file=sys.stderr)
        print(f"Response text: {response.text}", file=sys.stderr)
        sys.exit(1)


def get_form_auth_params(args: argparse.Namespace) -> dict[str, str]:
    """Return authentication parameters for form-data requests."""
    auth = {"id": args.id}
    if args.password:
        auth["passwd"] = args.password
    elif args.api_key:
        auth["cloud_key_value"] = args.api_key
    else:
        raise ValueError("Either --password or --api-key must be provided.")
    return auth


def get_json_auth_params(args: argparse.Namespace) -> dict[str, str]:
    """Return authentication parameters for JSON requests."""
    auth = {"id": args.id}
    if args.password:
        auth["password"] = args.password
    elif args.api_key:
        auth["cloud_key_value"] = args.api_key
    else:
        raise ValueError("Either --password or --api-key must be provided.")
    return auth


def validate_file(file_path: str) -> str:
    """Validate that a file exists and return its path."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file '{file_path}' was not found.")
    if not os.path.isfile(file_path):
        raise ValueError(f"'{file_path}' is not a file.")
    return file_path


# --- API Call Functions ---

def staging_deploy(args: argparse.Namespace) -> None:
    """Deploy a new SSL certificate to staging environment."""
    try:
        data = get_form_auth_params(args)

        # Optional parameters
        if args.domain_list:
            data["domain_list"] = args.domain_list
        if args.memo:
            data["memo"] = args.memo
        if args.ssl_key_password:
            data["ssl_key_password"] = args.ssl_key_password

        # Validate certificate files
        cert_path = validate_file(args.ssl_cert)
        key_path = validate_file(args.ssl_key)

        with open(cert_path, "rb") as cert_file, open(key_path, "rb") as key_file:
            files = {
                "ssl_cert": (os.path.basename(cert_path), cert_file),
                "ssl_key": (os.path.basename(key_path), key_file),
            }
            response = requests.post(
                API_URLS["staging_deploy"],
                data=data,
                files=files,
                timeout=60
            )
            handle_response(response)

    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def staging_update(args: argparse.Namespace) -> None:
    """Update an existing SSL certificate in staging environment."""
    try:
        data = get_form_auth_params(args)
        data["ssl_file_name"] = args.ssl_file_name

        # Optional parameters
        if args.add_domain_list:
            data["add_domain_list"] = args.add_domain_list
        if args.del_domain_list:
            data["del_domain_list"] = args.del_domain_list
        if args.memo:
            data["memo"] = args.memo
        if args.ssl_key_password:
            data["ssl_key_password"] = args.ssl_key_password

        files = {}
        opened_files = []

        try:
            # Handle certificate renewal (both cert and key must be provided together)
            if args.ssl_cert and args.ssl_key:
                cert_path = validate_file(args.ssl_cert)
                key_path = validate_file(args.ssl_key)

                cert_file = open(cert_path, "rb")
                key_file = open(key_path, "rb")
                opened_files.extend([cert_file, key_file])

                files = {
                    "ssl_cert": (os.path.basename(cert_path), cert_file),
                    "ssl_key": (os.path.basename(key_path), key_file),
                }
            elif args.ssl_cert or args.ssl_key:
                print("Warning: Both --ssl-cert and --ssl-key must be provided together for certificate renewal.", file=sys.stderr)
                sys.exit(1)

            response = requests.post(
                API_URLS["staging_update"],
                data=data,
                files=files if files else None,
                timeout=60
            )
            handle_response(response)

        finally:
            for f in opened_files:
                f.close()

    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def deploy(args: argparse.Namespace) -> None:
    """Finalize the deployment of a staged SSL certificate."""
    try:
        data = get_form_auth_params(args)
        data["ssl_file_name"] = args.ssl_file_name

        # Convert to multipart/form-data format
        files = {key: (None, value) for key, value in data.items()}

        response = requests.post(
            API_URLS["deploy"],
            files=files,
            timeout=60
        )
        handle_response(response)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def staging_cancel(args: argparse.Namespace) -> None:
    """Cancel a staged SSL certificate deployment."""
    try:
        data = get_form_auth_params(args)
        data["ssl_file_name"] = args.ssl_file_name

        # Convert to multipart/form-data format
        files = {key: (None, value) for key, value in data.items()}

        response = requests.post(
            API_URLS["staging_cancel"],
            files=files,
            timeout=60
        )
        handle_response(response)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def history(args: argparse.Namespace) -> None:
    """Retrieve the SSL certificate deployment history."""
    try:
        auth_params = get_json_auth_params(args)

        payload = {
            "api_request": {
                "common": auth_params,
                "data": {
                    "ssl_file_name": args.ssl_file_name
                }
            }
        }

        headers = {"Content-Type": "application/json"}
        response = requests.post(
            API_URLS["history"],
            json=payload,
            headers=headers,
            timeout=60
        )
        handle_response(response)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


# --- Argument Parser Setup ---

def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="SSL Certificate Management API CLI for ONS CDN Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Deploy new certificate to staging
  %(prog)s staging-deploy --id admin --password pass --ssl-cert cert.crt --ssl-key key.key

  # Update certificate in staging (add domains)
  %(prog)s staging-update --id admin --api-key KEY --ssl-file-name example.com --add-domain-list "api.example.com"

  # Finalize deployment
  %(prog)s deploy --id admin --password pass --ssl-file-name example.com

  # Check deployment history
  %(prog)s history --id admin --password pass --ssl-file-name example.com
        """
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Available commands"
    )

    # Common authentication arguments
    auth_parser = argparse.ArgumentParser(add_help=False)
    auth_parser.add_argument(
        "--id",
        required=True,
        help="User Portal account ID"
    )
    auth_group = auth_parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument(
        "--password",
        help="User Portal account password"
    )
    auth_group.add_argument(
        "--api-key",
        dest="api_key",
        help="User Portal account API KEY"
    )

    # --- staging-deploy command ---
    parser_staging_deploy = subparsers.add_parser(
        "staging-deploy",
        help="Deploy a new SSL certificate to staging",
        parents=[auth_parser]
    )
    parser_staging_deploy.add_argument(
        "--ssl-cert",
        dest="ssl_cert",
        required=True,
        help="Path to the SSL certificate file (.crt)"
    )
    parser_staging_deploy.add_argument(
        "--ssl-key",
        dest="ssl_key",
        required=True,
        help="Path to the SSL private key file (.key)"
    )
    parser_staging_deploy.add_argument(
        "--ssl-key-password",
        dest="ssl_key_password",
        help="Password for encrypted key file"
    )
    parser_staging_deploy.add_argument(
        "--domain-list",
        dest="domain_list",
        help="Comma-separated list of domains for the certificate"
    )
    parser_staging_deploy.add_argument(
        "--memo",
        help="Memo for the deployment"
    )
    parser_staging_deploy.set_defaults(func=staging_deploy)

    # --- staging-update command ---
    parser_staging_update = subparsers.add_parser(
        "staging-update",
        help="Update an existing SSL certificate in staging",
        parents=[auth_parser]
    )
    parser_staging_update.add_argument(
        "--ssl-file-name",
        dest="ssl_file_name",
        required=True,
        help="Certificate file name to update (without extension)"
    )
    parser_staging_update.add_argument(
        "--ssl-cert",
        dest="ssl_cert",
        help="Path to new SSL certificate file (.crt) for renewal"
    )
    parser_staging_update.add_argument(
        "--ssl-key",
        dest="ssl_key",
        help="Path to new SSL private key file (.key) for renewal"
    )
    parser_staging_update.add_argument(
        "--ssl-key-password",
        dest="ssl_key_password",
        help="Password for new encrypted key file"
    )
    parser_staging_update.add_argument(
        "--add-domain-list",
        dest="add_domain_list",
        help="Comma-separated list of domains to add"
    )
    parser_staging_update.add_argument(
        "--del-domain-list",
        dest="del_domain_list",
        help="Comma-separated list of domains to remove"
    )
    parser_staging_update.add_argument(
        "--memo",
        help="Memo for the update"
    )
    parser_staging_update.set_defaults(func=staging_update)

    # --- deploy command ---
    parser_deploy = subparsers.add_parser(
        "deploy",
        help="Finalize deployment of a staged SSL certificate",
        parents=[auth_parser]
    )
    parser_deploy.add_argument(
        "--ssl-file-name",
        dest="ssl_file_name",
        required=True,
        help="Certificate file name to deploy (without extension)"
    )
    parser_deploy.set_defaults(func=deploy)

    # --- staging-cancel command ---
    parser_staging_cancel = subparsers.add_parser(
        "staging-cancel",
        help="Cancel a staged SSL certificate deployment",
        parents=[auth_parser]
    )
    parser_staging_cancel.add_argument(
        "--ssl-file-name",
        dest="ssl_file_name",
        required=True,
        help="Certificate file name to cancel (without extension)"
    )
    parser_staging_cancel.set_defaults(func=staging_cancel)

    # --- history command ---
    parser_history = subparsers.add_parser(
        "history",
        help="Retrieve SSL certificate deployment history",
        parents=[auth_parser]
    )
    parser_history.add_argument(
        "--ssl-file-name",
        dest="ssl_file_name",
        required=True,
        help="Certificate file name to check (without extension)"
    )
    parser_history.set_defaults(func=history)

    return parser


# --- Main Execution ---

def main() -> None:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
