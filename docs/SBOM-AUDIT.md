# SBOM inventory and vulnerability correlation

The `hco sbom inventory` command reads CycloneDX JSON or SPDX JSON and produces a normalized component inventory. SBOM files are limited to 10 MiB and 10,000 components. Malformed component records and duplicate CycloneDX `bom-ref` values are rejected rather than silently omitted.

The `hco sbom correlate` command correlates explicit CVE IDs already present in component metadata against a locally saved CISA KEV snapshot. It does not infer vulnerabilities from package names or versions.

The separate, opt-in `hco sbom osv-correlate` command submits eligible package URLs and versions to OSV.dev. It does not upload the raw SBOM or local file path. Components without a usable PURL and version are reported as skipped. Identical package/version queries are deduplicated. Requests, responses, batch sizes, timeouts and pagination are bounded.

The OSV querybatch endpoint returns advisory IDs and modification timestamps, not full severity or remediation details. HCO therefore reports advisory identifiers as triage leads and does not invent severity, exploitation status, or reachability. A match does not prove the vulnerable code path is present or reachable. A clean or incomplete result is not proof that dependencies are vulnerability-free.

Package URLs and versions may reveal proprietary software inventory. Review that disclosure before invoking OSV queries. Inventory and KEV workflows remain local unless the operator separately invokes a network command.
