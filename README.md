# Huffman Cyber Observatory

Open-source defensive security tooling for local-first assessment, vulnerability intelligence, evidence integrity, and practical cryptography.

> **Security posture:** experimental defensive tooling with local processing, evidence-backed findings, and no exploit execution. It is not a certification or guarantee of security.

## Initial release

- CISA Known Exploited Vulnerabilities (KEV) feed retrieval with provenance and response hashing.
- Local secret-candidate scanning with mandatory redaction.
- SHA-256 integrity manifests and verification.
- AES-256-GCM authenticated file encryption using scrypt-derived keys.
- Ed25519 file signing and verification.
- Versioned JSON reports, tests, and minimal-permission CI.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
pytest
hco --help
```

## Examples

```bash
hco kev --output kev-snapshot.json
hco secrets ./project --json findings.json
hco hash ./project --output manifest.json
hco verify manifest.json --target ./project
hco encrypt private.txt private.txt.hco
hco decrypt private.txt.hco restored.txt
hco keygen signing-key.pem signing-key.pub
hco sign signing-key.pem release.tar.gz --output release.sig.json
hco verify-signature signing-key.pub release.tar.gz release.sig.json
```

## Safety boundaries

- Assess only files, devices, and systems you own or are explicitly authorized to assess.
- Filesystem scanning is local and read-only. File contents are not uploaded; secret values are never printed or stored in reports.
- The KEV command contacts only the documented CISA feed over HTTPS.
- No exploit execution, persistence, stealth, credential validation, lateral movement, destructive testing, or arbitrary-target scanning.
- Cryptographic operations use established primitives from the maintained `cryptography` library.
- The initial encryption implementation buffers complete files and enforces a 64 MiB limit. It is not a streaming format.

## Limitations

This is an initial foundation, not a certified security product or a substitute for a professional assessment. Secret detection is heuristic and has false positives and false negatives. A clean scan is not proof of security. KEV is one intelligence source, not a complete vulnerability database.

## Roadmap

1. OSV and NVD advisory enrichment.
2. OSV and NVD advisory enrichment beyond explicit CVE-to-KEV correlation.
3. Versioned CIS/NIST host configuration checks.
4. Local stdio agent interface with strict path scoping.
5. Signed release attestations, reproducible builds, and independent review.

## Sources

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST NVD: https://nvd.nist.gov/developers/vulnerabilities
- OSV: https://osv.dev/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks

## License

MIT. See [LICENSE](LICENSE).