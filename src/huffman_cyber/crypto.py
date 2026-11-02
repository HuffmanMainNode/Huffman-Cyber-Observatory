"""Authenticated encryption and encrypted Ed25519 key handling."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"HCOENC01"
SALT_LEN = 16
NONCE_LEN = 12
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
MAX_INPUT_BYTES = 64 * 1024 * 1024


def _derive(password: bytes, salt: bytes) -> bytes:
    if len(password) < 12:
        raise ValueError("passphrase must contain at least 12 bytes; use a long unique passphrase")
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password)


def encrypt_bytes(plaintext: bytes, password: bytes) -> bytes:
    if len(plaintext) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds 64 MiB safety limit; use a reviewed streaming format")
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    key = _derive(password, salt)
    header = MAGIC + bytes([1]) + salt + nonce
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


def decrypt_bytes(envelope: bytes, password: bytes) -> bytes:
    header_len = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN
    if len(envelope) < header_len + 16 or not envelope.startswith(MAGIC):
        raise ValueError("invalid or truncated HCO encrypted file")
    if envelope[len(MAGIC)] != 1:
        raise ValueError("unsupported encrypted file version")
    salt_start = len(MAGIC) + 1
    salt = envelope[salt_start:salt_start + SALT_LEN]
    nonce = envelope[salt_start + SALT_LEN:header_len]
    header = envelope[:header_len]
    key = _derive(password, salt)
    return AESGCM(key).decrypt(nonce, envelope[header_len:], header)


def generate_ed25519(
    private_path: str | Path, public_path: str | Path, password: bytes
) -> None:
    if len(password) < 12:
        raise ValueError("key-encryption passphrase must contain at least 12 bytes")
    private_file, public_file = Path(private_path), Path(public_path)
    if private_file.resolve() == public_file.resolve():
        raise ValueError("private and public key paths must be different")
    if private_file.exists() or public_file.exists():
        raise FileExistsError("refusing to overwrite an existing key file")
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    descriptor = os.open(
        private_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(private_bytes)
    try:
        with public_file.open("xb") as stream:
            stream.write(public_bytes)
    except Exception:
        private_file.unlink(missing_ok=True)
        raise
    if os.name == "posix":
        try:
            os.chmod(private_file, 0o600)
        except OSError as exc:
            print(
                f"warning: could not enforce private-key permissions: {exc}",
                file=sys.stderr,
            )
    else:
        print(
            "warning: POSIX private-key permissions are not enforced on this platform",
            file=sys.stderr,
        )


def sign_file(
    private_path: str | Path, data_path: str | Path, output_path: str | Path, password: bytes
) -> None:
    private = serialization.load_pem_private_key(
        Path(private_path).read_bytes(), password=password
    )
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("private key is not Ed25519")
    payload = Path(data_path).read_bytes()
    document = {
        "schema_version": "1.0",
        "algorithm": "Ed25519",
        "signature_base64": base64.b64encode(private.sign(payload)).decode("ascii"),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    Path(output_path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def verify_signature(
    public_path: str | Path, data_path: str | Path, signature_path: str | Path
) -> bool:
    public = serialization.load_pem_public_key(Path(public_path).read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    document = json.loads(Path(signature_path).read_text(encoding="utf-8"))
    if document.get("schema_version") != "1.0" or document.get("algorithm") != "Ed25519":
        raise ValueError("unsupported signature document")
    payload = Path(data_path).read_bytes()
    if hashlib.sha256(payload).hexdigest() != document.get("sha256"):
        return False
    try:
        signature = base64.b64decode(document["signature_base64"], validate=True)
        public.verify(signature, payload)
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False