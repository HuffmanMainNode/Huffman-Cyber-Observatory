"""Command-line interface."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from huffman_cyber.crypto import (
    decrypt_bytes, encrypt_bytes, generate_ed25519, sign_file, verify_signature,
)
from huffman_cyber.feeds.kev import save_kev
from huffman_cyber.integrity import create_manifest, verify_manifest, write_json
from huffman_cyber.report import report
from huffman_cyber.scanners.secrets import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hco", description="Local-first defensive security toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    kev = sub.add_parser("kev", help="fetch and validate the CISA KEV catalog")
    kev.add_argument("--output", default="kev-snapshot.json")

    secrets = sub.add_parser("secrets", help="scan a local directory for redacted secret candidates")
    secrets.add_argument("target")
    secrets.add_argument("--json", dest="output")

    hashing = sub.add_parser("hash", help="create a SHA-256 file manifest")
    hashing.add_argument("target")
    hashing.add_argument("--output", default="hco-manifest.json")

    verify = sub.add_parser("verify", help="verify a SHA-256 file manifest")
    verify.add_argument("manifest")
    verify.add_argument("--target", default=".")

    for name, help_text in (
        ("encrypt", "encrypt a file with AES-256-GCM"),
        ("decrypt", "decrypt an HCO encrypted file"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("source")
        command.add_argument("destination")

    keys = sub.add_parser("keygen", help="generate an Ed25519 key pair")
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
            print(f"Saved {data['vulnerability_count']} KEV records to {args.output}; SHA-256 {data['sha256']}")
        elif args.command == "secrets":
            findings = scan(args.target)
            data = report("secret_scan", findings)
            if args.output:
                write_json(args.output, data)
                print(f"{len(findings)} candidate(s); redacted report saved to {args.output}")
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
        elif args.command in {"encrypt", "decrypt"}:
            password = getpass.getpass("Passphrase (minimum 12 bytes): ").encode()
            source = Path(args.source).read_bytes()
            output = encrypt_bytes(source, password) if args.command == "encrypt" else decrypt_bytes(source, password)
            Path(args.destination).write_bytes(output)
            print(f"Wrote {args.destination}")
        elif args.command == "keygen":
            generate_ed25519(args.private_key, args.public_key)
            print("Ed25519 key pair generated; protect the private key.")
        elif args.command == "sign":
            sign_file(args.private_key, args.source, args.output)
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