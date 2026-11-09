# Data sources and provenance

## CISA Known Exploited Vulnerabilities

- Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Catalog overview: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Retrieved timestamp is generated locally in UTC.
- Source release date is copied from the feed's `dateReleased` field.
- SHA-256 is calculated over the exact downloaded response bytes.
- Catalog presence alone does not establish that a particular local asset is vulnerable.

## OSV.dev package-version query

- API: https://api.osv.dev/v1/querybatch
- Documentation: https://google.github.io/osv.dev/api/
- The operator explicitly invokes `hco sbom osv-correlate`; it is not contacted by inventory or KEV commands.
- Only package URLs and versions for eligible components are transmitted. Raw SBOM documents, local file paths, and other component metadata are not sent.
- Request and response bodies are SHA-256 hashed; retrieval time is recorded in UTC.
- Querybatch returns advisory identifiers and modification timestamps only. It does not provide full severity, affected-range explanation, or remediation detail.
- Inputs, batch sizes, timeouts, pagination attempts, and response sizes are bounded. Incomplete pagination is reported as incomplete, not clean.
- A package-version query match is a triage lead, not proof of vulnerable code reachability or exploitability.
- Package URLs and versions can reveal private software inventory. Operators should review disclosure implications before invoking the command.

## Planned integrations

- NVD 2.0 API: https://nvd.nist.gov/developers/vulnerabilities

Future connectors must record source URL, retrieval time, source publication/modification time where available, response hash, and parser/schema version. API keys must be supplied through environment variables or secret stores, never committed.
