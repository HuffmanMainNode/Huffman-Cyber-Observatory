import os
import stat

import pytest
from cryptography.exceptions import InvalidTag

from huffman_cyber.crypto import (
    decrypt_bytes,
    encrypt_bytes,
    generate_ed25519,
    sign_file,
    verify_signature,
)


def test_authenticated_round_trip():
    password = b"correct horse battery staple"
    encrypted = encrypt_bytes(b"observatory test payload", password)
    assert decrypt_bytes(encrypted, password) == b"observatory test payload"


def test_wrong_password_fails():
    encrypted = encrypt_bytes(b"classified test", b"correct horse battery staple")
    with pytest.raises(InvalidTag):
        decrypt_bytes(encrypted, b"different horse battery staple")


def test_tampering_fails():
    encrypted = bytearray(encrypt_bytes(b"payload", b"correct horse battery staple"))
    encrypted[-1] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_bytes(bytes(encrypted), b"correct horse battery staple")


def test_short_password_rejected():
    with pytest.raises(ValueError):
        encrypt_bytes(b"payload", b"short")


def test_encrypted_ed25519_sign_and_verify(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    source = tmp_path / "artifact.bin"
    signature = tmp_path / "artifact.sig.json"
    password = b"strong unique passphrase"
    source.write_bytes(b"release artifact")
    generate_ed25519(private, public, password)
    assert b"ENCRYPTED" in private.read_bytes()
    sign_file(private, source, signature, password)
    assert verify_signature(public, source, signature)
    source.write_bytes(b"tampered artifact")
    assert not verify_signature(public, source, signature)


def test_keygen_refuses_overwrite(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    private.write_text("existing")
    with pytest.raises(FileExistsError):
        generate_ed25519(private, public, b"strong unique passphrase")
    assert private.read_text() == "existing"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are unavailable")
def test_generated_private_key_has_owner_only_permissions(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_ed25519(private, public, b"strong unique passphrase")
    assert stat.S_IMODE(private.stat().st_mode) == 0o600


def test_decrypt_rejects_oversized_envelope_before_decryption(monkeypatch):
    from huffman_cyber import crypto

    monkeypatch.setattr(crypto, "MAX_INPUT_BYTES", 4)
    header = crypto.MAGIC + bytes([1]) + b"s" * crypto.SALT_LEN + b"n" * crypto.NONCE_LEN
    with pytest.raises(ValueError, match="exceeds 64 MiB"):
        decrypt_bytes(header + b"x" * 21, b"correct horse battery staple")


def test_signing_refuses_to_overwrite_signature_document(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    source = tmp_path / "artifact.bin"
    signature = tmp_path / "artifact.sig.json"
    source.write_bytes(b"release artifact")
    generate_ed25519(private, public, b"strong unique passphrase")
    signature.write_text("keep me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        sign_file(private, source, signature, b"strong unique passphrase")
    assert signature.read_text(encoding="utf-8") == "keep me"


def test_signing_rejects_oversized_input(tmp_path, monkeypatch):
    from huffman_cyber import crypto

    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    source = tmp_path / "artifact.bin"
    signature = tmp_path / "artifact.sig.json"
    generate_ed25519(private, public, b"strong unique passphrase")
    source.write_bytes(b"12345")
    monkeypatch.setattr(crypto, "MAX_INPUT_BYTES", 4)

    with pytest.raises(ValueError, match="size limit"):
        sign_file(private, source, signature, b"strong unique passphrase")


def test_signature_document_must_be_valid_json_object(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    source = tmp_path / "artifact.bin"
    signature = tmp_path / "artifact.sig.json"
    source.write_bytes(b"release artifact")
    generate_ed25519(private, public, b"strong unique passphrase")
    signature.write_text("[]", encoding="utf-8")

    with pytest.raises(TypeError, match="JSON object"):
        verify_signature(public, source, signature)
