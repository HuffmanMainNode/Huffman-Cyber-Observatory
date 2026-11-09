# Changelog

All notable changes to Huffman Cyber Observatory are recorded here. This project is experimental and is not a security certification.

## 0.1.0 - Unreleased

- Add a tag-triggered release build that generates SHA-256 manifests and GitHub build-provenance attestations, verifies attestations, and uploads workflow artifacts without publishing a package or GitHub Release.

- Preserve package versions embedded in PURLs in OSV findings; reject invalid top-level SBOM input with clear errors.
- Build wheel and source distributions in CI and verify independent installation of both artifacts in clean virtual environments.
- Separate runtime installation instructions from contributor-only development dependencies.
- Add bounded, opt-in OSV.dev package-version advisory queries with provenance hashes and explicit disclosure boundaries.
- Bound SBOM input size and component counts; reject malformed component records and duplicate CycloneDX references.
- Strengthen CISA KEV feed validation, date/count consistency checks, and redirect destination checks.
- Refresh the pinned OIX interoperability test dependency after reviewing upstream compatibility changes.
- Run pip-audit in CI and modernize SPDX license metadata for current setuptools.

- Add local secrets-candidate scanning with mandatory evidence redaction.
- Add scan coverage accounting and expanded private-key/token patterns.
- Add CycloneDX/SPDX JSON SBOM inventory and explicit-CVE correlation against a saved CISA KEV snapshot.
- Add encrypted evidence bundles, Ed25519 signing, and integrity manifests.
- Fix scan-root filtering so parent directory names do not cause false-clean results.
- Create private Ed25519 key files with restrictive POSIX permissions where supported.
