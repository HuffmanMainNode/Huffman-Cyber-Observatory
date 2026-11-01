# Cryptography design

## File encryption

The initial envelope uses AES-256-GCM from `cryptography` with a 256-bit key derived by scrypt. Each file receives a fresh 16-byte random salt and 12-byte random nonce. The fixed header (magic, format version, salt, nonce) is authenticated as associated data. Authentication failure raises an error; unauthenticated plaintext must never be used.

Format v1: `HCOENC01 || version(1) || salt(16) || nonce(12) || ciphertext_and_tag`.

Scrypt parameters: N=32768, r=8, p=1. These constants are part of format v1 and must not be silently changed. The implementation limits input to 64 MiB because it buffers the complete file in memory.

Passphrases must be at least 12 bytes. Prefer a unique, randomly generated passphrase with substantially more entropy. Do not reuse passwords. The application does not store or recover passphrases.

## Digital signatures

Detached signatures use Ed25519. Private-key PEM files are encrypted at rest with the cryptography library's best-available PEM encryption and require an interactive passphrase to sign. New key files are created exclusively, not overwritten. The private key file is restricted to owner read/write permissions where the platform supports POSIX modes.

Public keys may be distributed; private keys must remain confidential and should be stored in a hardware-backed or otherwise protected key store for production use. A valid signature proves that signed bytes match a key, not that the key owner is trustworthy.

## Hashes

SHA-256 manifests detect byte-level changes relative to a trusted manifest. A manifest stored beside the files it protects can itself be replaced; sign or store manifests in a separate trusted location.

## Prohibited shortcuts

- No custom cipher, homemade KDF, or unauthenticated encryption mode.
- No hard-coded keys, default passwords, or embedded secrets.
- No claim that AES-256 alone makes an application secure.
- No silent crypto-format or KDF-parameter changes. Introduce a new format version and migration tests.