# Huffman Cyber Observatory

Open-source defensive security tooling for local-first assessment, vulnerability intelligence, evidence integrity, and practical cryptography.

> **Security posture:** experimental defensive tooling with local processing, evidence-backed findings, and no exploit execution. It is not a certification or guarantee of security.

## Initial release

- CISA Known Exploited Vulnerabilities (KEV) feed retrieval with provenance and response hashing.
- Local secret-candidate scanning with mandatory redaction.
- SHA-256 integrity manifests and verification.
- AES-256-GCM authenticated file encryption using scrypt-derived keys.
- Ed25519 file signing and verification.
- CycloneDX/SPDX JSON SBOM inventory and explicit-CVE correlation against a saved CISA KEV snapshot.
- Optional, operator-invoked OSV.dev package-version advisory queries with request/response hashes and bounded input/output.
- Versioned JSON reports, tests, and minimal-permission CI.

## Onboarding

New operators: start with [Human Onboarding](docs/USER-ONBOARDING.md). Agents and automation developers: read [Agent Onboarding](docs/AGENT-ONBOARDING.md) and [AGENTS.md](AGENTS.md). The supported interfaces are the local CLI and Python library; this release does not provide an MCP server.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\Activate.ps1
python -m pip install .
hco --help

# Optional contributor/development environment:
python -m pip install -e '.[dev]'
pytest
```

## Pinned installation for automation

For reproducible agent or deployment installs, pin the verified repository revision instead of following the moving `main` branch:

```bash
python -m pip install "git+https://github.com/HuffmanMainNode/Huffman-Cyber-Observatory.git@542bfdc32cf460415a95e1c78bb0ac2001494b77"
hco --help
```

This is a source install from a public Git commit, not a hosted HCO service or package-registry dependency. Update the pinned commit deliberately after reviewing a newer revision.

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
hco sbom inventory bom.cdx.json --output inventory.json
hco sbom correlate bom.cdx.json kev-snapshot.json --output sbom-kev-report.json
# Explicitly contacts OSV.dev with package URLs and versions, not the raw SBOM:
hco sbom osv-correlate bom.cdx.json --output sbom-osv-report.json
```

## Safety boundaries

- Assess only files, devices, and systems you own or are explicitly authorized to assess.
- Filesystem scanning is local and read-only. File contents are not uploaded; secret values are never printed or stored in reports.
- The KEV command contacts only the documented CISA feed over HTTPS.
- OSV queries are a separate opt-in command. Only component package URLs and versions are sent; raw SBOM contents and local file paths are not transmitted. The query count, request timeout, and response size are bounded.
- No exploit execution, persistence, stealth, credential validation, lateral movement, destructive testing, or arbitrary-target scanning.
- Cryptographic operations use established primitives from the maintained `cryptography` library.
- The initial encryption implementation buffers complete files and enforces a 64 MiB limit. It is not a streaming format.

## Limitations

This is an experimental defensive toolkit, not a certification or a substitute for a professional assessment. Secret detection is heuristic and has false positives and false negatives. Reports include files scanned and files skipped by reason, but a clean scan is not proof of security. KEV is one intelligence source, not a complete vulnerability database. OSV querybatch returns advisory identifiers and modification timestamps, not severity or remediation details. A package-version advisory match does not prove vulnerable code is present, reachable, or exploitable. Package URLs and versions can reveal software inventory and should be treated as potentially sensitive. Private-key files are created with POSIX mode 0600 where supported; Windows does not enforce POSIX mode bits.

## Roadmap

1. Enrich OSV advisory IDs with carefully bounded advisory details and remediation metadata.
2. Add NVD enrichment with source-specific provenance and rate-limit handling.
3. Versioned CIS/NIST host configuration checks.
4. Local stdio agent interface with strict path scoping.
5. Reproducible builds, independent security review, and release-process hardening. GitHub build-provenance attestations are implemented; bit-for-bit reproducibility and independent review remain open.

## Sources

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST NVD: https://nvd.nist.gov/developers/vulnerabilities
- OSV API: https://google.github.io/osv.dev/api/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks

## License

MIT. See [LICENSE](LICENSE).

## Release artifact verification

The tag-triggered release workflow builds wheel and source distributions, generates a SHA-256 manifest, and creates/verifies GitHub build-provenance attestations. It does not publish a GitHub Release or package to PyPI. See [Release Artifact Verification](docs/RELEASE-VERIFICATION.md) for independent verification steps.

## Optional OIX evidence exchange

Install Open Intelligence Exchange alongside Cyber Observatory to enable `huffman_cyber.oix_bridge`. The bridge hashes a selected local SBOM report or file manifest and creates a signed, metadata-only OIX `evidence.submit` envelope. The report itself is never uploaded or attached.

The receiving OIX agent validates the signature and schema, then places the submission in its pending-review queue. An operator must approve it before downstream ingestion. See [OIX Evidence Bridge](docs/OIX-EVIDENCE-BRIDGE.md) and run the synthetic demonstration:

```bash
python examples/oix_evidence_bridge_demo.py
```
