"""Command-line interface."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from huffman_cyber.crypto import (
    decrypt_bytes,
    encrypt_bytes,
    generate_ed25519,
    sign_file,
    verify_signature,
)
from huffman_cyber.feeds.kev import save_kev
from huffman_cyber.feeds.osv import query_osv
from huffman_cyber.integrity import create_manifest, verify_manifest, write_json
from huffman_cyber.report import report
from huffman_cyber.sbom import correlate_kev, load_sbom
from huffman_cyber.scanners.secrets import scan_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hco", description="Local-first defensive security toolkit"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    kev = sub.add_parser("kev", help="fetch and validate the CISA KEV catalog")
    kev.add_argument("--output", default="kev-snapshot.json")

    secrets = sub.add_parser(
        "secrets", help="scan a local directory for redacted secret candidates"
    )
    secrets.add_argument("target")
    secrets.add_argument("--json", dest="output")

    hashing = sub.add_parser("hash", help="create a SHA-256 file manifest")
    hashing.add_argument("target")
    hashing.add_argument("--output", default="hco-manifest.json")

    verify = sub.add_parser("verify", help="verify a SHA-256 file manifest")
    verify.add_argument("manifest")
    verify.add_argument("--target", default=".")

    sbom = sub.add_parser("sbom", help="inventory and audit a software bill of materials")
    sbom_sub = sbom.add_subparsers(dest="sbom_command", required=True)
    inventory = sbom_sub.add_parser("inventory", help="normalize CycloneDX or SPDX JSON")
    inventory.add_argument("source")
    inventory.add_argument("--output", default="sbom-inventory.json")
    correlate = sbom_sub.add_parser("correlate", help="match explicit SBOM CVEs against a saved KEV snapshot")
    correlate.add_argument("source")
    correlate.add_argument("kev_snapshot")
    correlate.add_argument("--output", default="sbom-kev-report.json")
    osv = sbom_sub.add_parser(
        "osv-correlate",
        help="opt in to sending component package URLs and versions to OSV.dev",
    )
    osv.add_argument("source")
    osv.add_argument("--output", default="sbom-osv-report.json")
    osv.add_argument("--timeout", type=float, default=20.0)

    for name, help_text in (
        ("encrypt", "encrypt a file with AES-256-GCM"),
        ("decrypt", "decrypt an HCO encrypted file"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("source")
        command.add_argument("destination")

    keys = sub.add_parser("keygen", help="generate an encrypted Ed25519 key pair")
    keys.add_argument("private_key")
    keys.add_argument("public_key")

    sign = sub.add_parser("sign", help="sign a file with Ed25519")
    sign.add_argument("private_key")
    sign.add_argument("source")
    sign.add_argument("--output", default="signature.json")

    check = sub.add_parser("verify-signature", help="verify an Ed25519 file signature")
    check.add_argument("public_key")
    check.add_argument("source")
    check.add_argument("signature")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        if args.command == "kev":
            data = save_kev(args.output)
            print(
                f"Saved {data['vulnerability_count']} KEV records to "
                f"{args.output}; SHA-256 {data['sha256']}"
            )
        elif args.command == "secrets":
            scan_data = scan_report(args.target)
            data = report("secret_scan", scan_data["findings"])
            data["files_scanned"] = scan_data["files_scanned"]
            data["files_skipped"] = scan_data["files_skipped"]
            if args.output:
                write_json(args.output, data)
                print(f"{len(scan_data['findings'])} candidate(s); redacted report saved to {args.output}")
            else:
                print(json.dumps(data, indent=2))
        elif args.command == "hash":
            data = create_manifest(args.target)
            write_json(args.output, data)
            print(f"Manifest contains {len(data['entries'])} files: {args.output}")
        elif args.command == "verify":
            data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            result = verify_manifest(data, args.target)
            print(json.dumps(result, indent=2))
            if any(result.values()):
                sys.exit(1)
        elif args.command == "sbom" and args.sbom_command == "inventory":
            result = load_sbom(args.source)
            write_json(args.output, result)
            print(f"Inventoried {result['component_count']} components: {args.output}")
        elif args.command == "sbom" and args.sbom_command == "correlate":
            inventory_data = load_sbom(args.source)
            kev_data = json.loads(Path(args.kev_snapshot).read_text(encoding="utf-8"))
            result = correlate_kev(inventory_data, kev_data)
            write_json(args.output, result)
            print(f"Found {result['finding_count']} explicit KEV match(es): {args.output}")
        elif args.command == "sbom" and args.sbom_command == "osv-correlate":
            inventory_data = load_sbom(args.source)
            result = query_osv(inventory_data, timeout=args.timeout)
            write_json(args.output, result)
            state = "complete" if result["complete"] else "partial; pagination limit reached"
            print(
                f"Found {result['finding_count']} OSV advisory match(es) "
                f"({state}); report saved to {args.output}"
            )
        elif args.command in {"encrypt", "decrypt"}:
            password = getpass.getpass("Passphrase (minimum 12 bytes): ").encode()
            source = Path(args.source).read_bytes()
            if args.command == "encrypt":
                output = encrypt_bytes(source, password)
            else:
                output = decrypt_bytes(source, password)
            with Path(args.destination).open("xb") as destination:
                destination.write(output)
            print(f"Wrote {args.destination}")
        elif args.command == "keygen":
            password = getpass.getpass("Private-key encryption passphrase: ").encode()
            confirmation = getpass.getpass("Confirm passphrase: ").encode()
            if password != confirmation:
                raise ValueError("passphrases do not match")
            generate_ed25519(args.private_key, args.public_key, password)
            print("Encrypted Ed25519 key pair generated; protect the passphrase and private key.")
        elif args.command == "sign":
            password = getpass.getpass("Private-key encryption passphrase: ").encode()
            sign_file(args.private_key, args.source, args.output, password)
            print(f"Signature written to {args.output}")
        elif args.command == "verify-signature":
            valid = verify_signature(args.public_key, args.source, args.signature)
            print("VALID" if valid else "INVALID")
            if not valid:
                sys.exit(1)
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
