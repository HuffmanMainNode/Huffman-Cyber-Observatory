# SBOM inventory and KEV correlation

The `hco sbom inventory` command reads CycloneDX JSON or SPDX JSON and produces a normalized component inventory. `hco sbom correlate` can correlate explicit CVE IDs already present in component metadata against a locally saved CISA KEV snapshot.

This initial implementation deliberately does not guess vulnerabilities from package names or versions. It is not a replacement for OSV, NVD, package-manager advisory resolution, reachability analysis, or a software composition analysis platform. A match is a triage lead, not proof of exploitability.
