"""Authenticated encryption and Ed25519 signatures via pyca/cryptography."""
from __future__ import annotations

import base64
import hashlib
import json
import os
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


def generate_ed25519(private_path: str | Path, public_path: str | Path) -> None:
    private = Ed25519PrivateKey.generate()
    Path(private_path).write_bytes(private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    Path(public_path).write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass


def sign_file(private_path: str | Path, data_path: str | Path, output_path: str | Path) -> None:
    private = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
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


def verify_signature(public_path: str | Path, data_path: str | Path, signature_path: str | Path) -> bool:
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