# Threat model

## Assets
- Operator source files and local system metadata.
- Private signing keys and encryption passphrases.
- Scan reports and integrity manifests.
- Advisory-feed provenance and cached snapshots.

## Trust boundaries
- The operator-selected local filesystem is the scan boundary.
- Public advisory feeds are untrusted external input; responses are size-limited and structurally validated.
- Report consumers must treat paths, filenames, advisory descriptions, and package metadata as untrusted data.
- Future agent integrations must not expand scope beyond operator-approved paths.

## Threats considered
- Accidental disclosure of secrets in logs or reports.
- Tampering with files after a baseline manifest is created.
- Malformed or oversized advisory-feed responses.
- Unauthorized or unintended network activity.
- Ciphertext tampering, wrong passwords, and signature substitution.

## Mitigations in this release
- Secret findings contain redacted evidence only.
- Hashing streams file data in bounded chunks, excludes symlinks, validates manifest paths and metadata, and rejects duplicate entries.
- KEV retrieval uses HTTPS, a timeout, and a maximum response size.
- AES-GCM authenticates ciphertext and the fixed-format header; each encryption uses a fresh random salt and nonce.
- Ed25519 signatures bind exact file bytes; a detached document also records SHA-256. Signing and verification inputs are size-limited, and signature output files are not overwritten.
- Tests cover tampering, wrong passwords, symlink exclusion, and feed validation.

## Non-goals
No exploit testing, endpoint detection, malware analysis, remote port scanning, penetration testing, compliance certification, or proof of absence of vulnerabilities. The project does not defend against a compromised operating system, malicious administrator, keylogger, memory extraction, or stolen private key.

## Operator guidance
Use least privilege. Keep private keys outside the repository. Back up keys offline. Review findings manually. Treat generated reports as potentially sensitive. Filesystem checks do not eliminate time-of-check/time-of-use races if another process can mutate a scanned directory concurrently.