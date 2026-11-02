# Changelog

All notable changes to Huffman Cyber Observatory are recorded here. This project is experimental and is not a security certification.

## 0.1.0 - Unreleased

- Add local secrets-candidate scanning with mandatory evidence redaction.
- Add scan coverage accounting and expanded private-key/token patterns.
- Add CycloneDX/SPDX JSON SBOM inventory and explicit-CVE correlation against a saved CISA KEV snapshot.
- Add encrypted evidence bundles, Ed25519 signing, and integrity manifests.
- Fix scan-root filtering so parent directory names do not cause false-clean results.
- Create private Ed25519 key files with restrictive POSIX permissions where supported.
