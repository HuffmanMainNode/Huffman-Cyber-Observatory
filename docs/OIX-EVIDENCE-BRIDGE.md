# OIX Evidence Bridge

The optional `huffman_cyber.oix_bridge.create_evidence_message` helper turns a selected local Cyber Observatory report or SBOM artifact into a signed OIX `evidence.submit` envelope.

## Supported artifact types

- `sbom_analysis`: SBOM inventory and explicit CVE-to-KEV correlation reports.
- `file_manifest`: local integrity manifests.

The helper rejects unrelated evidence types rather than mislabeling a report.

## Workflow

1. Install Cyber Observatory and the OIX repository in the same Python environment.
2. Create an OIX Ed25519 identity and obtain the recipient's OIX agent ID.
3. Run a local assessment and save the JSON report.
4. Call `create_evidence_message` with the report path, method, bounded summary, limitations, classification, and recipient.
5. Send the returned envelope using OIX transport or submit it to a local OIX inbox.

The bridge streams the selected file through SHA-256 hashing. It includes the digest, byte size, media type, collector, method, summary, classification, status, source reference, and limitations. It does not upload report bytes, fetch source URLs, or open network connections.

## Trust boundaries

- A signed envelope proves possession of the sender's OIX signing key, not that the report is accurate.
- SBOM findings are explicit metadata matches and require manual triage; they do not establish exploitability.
- Classification and status are sender assertions.
- The receiving OIX inbox validates the signature and schema, then creates a pending-review item.
- An operator must approve evidence before downstream ingestion.
- No exploit execution or external action is part of this bridge.

Run the synthetic demonstration with `python examples/oix_evidence_bridge_demo.py`.
