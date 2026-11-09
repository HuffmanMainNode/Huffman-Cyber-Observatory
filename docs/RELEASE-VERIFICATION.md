# Release artifact verification

Huffman Cyber Observatory release builds are created from version tags by
`.github/workflows/release-artifacts.yml`. The workflow builds a wheel and
source distribution, writes a SHA-256 manifest, creates GitHub build-provenance
attestations, and verifies those attestations before uploading the artifacts.

The workflow does **not** publish a GitHub Release, upload to PyPI, or deploy a
service. A maintainer must separately review and authorize any public release.

## Verify artifact bytes

After downloading the workflow artifact, run:

```bash
sha256sum -c SHA256SUMS.txt
```

This checks that each downloaded distribution matches the accompanying
manifest. A checksum alone proves consistency with that manifest, not who
built the files or whether the source is trustworthy.

## Verify build provenance

Install the official GitHub CLI (`gh`) and authenticate if required by your
environment. For each downloaded wheel or source archive, run:

```bash
gh attestation verify huffman_cyber_observatory-0.1.0-py3-none-any.whl \
  --repo HuffmanMainNode/Huffman-Cyber-Observatory
```

Use the actual downloaded filename. Verify the checksum manifest too:

```bash
gh attestation verify SHA256SUMS.txt \
  --repo HuffmanMainNode/Huffman-Cyber-Observatory
```

The attestation verification checks GitHub's signed provenance against the
repository identity and workflow claims. Review the reported source commit,
workflow, and repository before trusting an artifact. Do not treat a valid
attestation as a security audit of the source code.

## Reproducibility and trust boundaries

- Build provenance identifies the source revision and GitHub Actions workflow
  that produced the artifact; it does not by itself prove bit-for-bit
  reproducibility.
- The SHA-256 manifest detects accidental or malicious artifact changes only
  when the manifest itself is obtained through a trusted channel.
- Prefer verifying both the manifest and each artifact's attestation.
- Compare the attested source revision with the release tag and reviewed
  repository history.
- Do not install an artifact solely because it has a valid checksum or
  attestation. Review the code, dependencies, permissions, and release notes.
- The current release workflow is tag-triggered and uploads workflow artifacts
  for 90 days. It does not create a permanent release asset or package-registry
  publication.
