# Threat model

## Assets
- Operator source files and local system metadata.
- Private signing keys and encryption passphrases.
- Scan reports and integrity manifests.
- Advisory-feed provenance and cached snapshots.
- Software inventory metadata, including package URLs and versions.

## Trust boundaries
- The operator-selected local filesystem is the scan boundary.
- Public advisory feeds are untrusted external input; responses are size-limited and structurally validated.
- OSV receives only package URLs and versions after an explicit operator command; raw SBOM files and local paths remain local.
- Report consumers must treat paths, filenames, advisory descriptions, and package metadata as untrusted data.
- Future agent integrations must not expand scope beyond operator-approved paths.

## Threats considered
- Accidental disclosure of secrets in logs or reports.
- Tampering with files after a baseline manifest is created.
- Malformed or oversized advisory-feed and SBOM responses.
- Unauthorized or unintended network activity.
- Disclosure of private package inventory through external advisory queries.
- Ciphertext tampering, wrong passwords, and signature substitution.

## Mitigations in this release
- Secret findings contain redacted evidence only.
- Hashing streams file data in bounded chunks, excludes symlinks, validates manifest paths and metadata, and rejects duplicate entries.
- KEV retrieval uses HTTPS, a timeout, and a maximum response size.
- SBOM JSON is size-limited; component structures and relevant field types are validated.
- OSV queries are opt-in, restricted to a fixed HTTPS endpoint, use bounded batches, timeouts, response sizes and pagination, and hash exact request/response bytes.
- AES-GCM authenticates ciphertext and the fixed-format header; each encryption uses a fresh random salt and nonce.
- Ed25519 signatures bind exact file bytes; a detached document also records SHA-256. Signing and verification inputs are size-limited, and signature output files are not overwritten.
- Tests cover tampering, wrong passwords, symlink exclusion, feed validation, malformed SBOM records, OSV response handling and network boundaries.

## Non-goals
No exploit testing, endpoint detection, malware analysis, remote port scanning, penetration testing, compliance certification, or proof of absence of vulnerabilities. The project does not defend against a compromised operating system, malicious administrator, keylogger, memory extraction, or stolen private key.

## Operator guidance
Use least privilege. Keep private keys outside the repository. Back up keys offline. Review findings manually. Treat generated reports as potentially sensitive. Filesystem checks do not eliminate time-of-check/time-of-use races if another process can mutate a scanned directory concurrently.
