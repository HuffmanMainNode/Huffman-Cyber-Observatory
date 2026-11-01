import pytest

from huffman_cyber.crypto import decrypt_bytes, encrypt_bytes


def test_authenticated_round_trip():
    password = b"correct horse battery staple"
    encrypted = encrypt_bytes(b"observatory test payload", password)
    assert decrypt_bytes(encrypted, password) == b"observatory test payload"


def test_wrong_password_fails():
    encrypted = encrypt_bytes(b"classified test", b"correct horse battery staple")
    with pytest.raises(Exception):
        decrypt_bytes(encrypted, b"different horse battery staple")


def test_tampering_fails():
    encrypted = bytearray(encrypt_bytes(b"payload", b"correct horse battery staple"))
    encrypted[-1] ^= 1
    with pytest.raises(Exception):
        decrypt_bytes(bytes(encrypted), b"correct horse battery staple")


def test_short_password_rejected():
    with pytest.raises(ValueError):
        encrypt_bytes(b"payload", b"short")