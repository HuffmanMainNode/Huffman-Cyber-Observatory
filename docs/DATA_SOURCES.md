# Data sources and provenance

## CISA Known Exploited Vulnerabilities

- Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Catalog overview: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Retrieved timestamp is generated locally in UTC.
- Source release date is copied from the feed's `dateReleased` field.
- SHA-256 is calculated over the exact downloaded response bytes.
- Catalog presence alone does not establish that a particular local asset is vulnerable.

## Planned integrations

- NVD 2.0 API: https://nvd.nist.gov/developers/vulnerabilities
- OSV API: https://google.github.io/osv.dev/api/

Future connectors must record source URL, retrieval time, source publication/modification time where available, response hash, and parser/schema version. API keys must be supplied through environment variables or secret stores, never committed.