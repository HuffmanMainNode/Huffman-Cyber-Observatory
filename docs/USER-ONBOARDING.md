# Human onboarding

Huffman Cyber Observatory (HCO) is a local-first defensive security toolkit for evidence integrity, secret-candidate scanning, SBOM inventory, KEV correlation and file cryptography. It does not execute exploits or upload scanned file contents.

## Install

Python 3.11+:

```bash
git clone https://github.com/HuffmanMainNode/Huffman-Cyber-Observatory.git
cd Huffman-Cyber-Observatory
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\\Scripts\\Activate.ps1
python -m pip install .
```

## First safe checks

```bash
hco --help
hco hash ./your-project --output project-manifest.json
hco verify project-manifest.json --target ./your-project

For contributor testing, install the development extras with `python -m pip install -e ".[dev]"` and run `pytest -q`.
```

The hash and verify commands operate on local files. Review the manifest before sharing it because paths and file metadata can be sensitive.

## Other workflows

- Secret candidates: `hco secrets ./your-project --json redacted-findings.json`. Findings are heuristic and can include false positives and false negatives.
- SBOM inventory: `hco sbom inventory bom.cdx.json --output inventory.json`.
- KEV correlation: `hco kev --output kev-snapshot.json`, then `hco sbom correlate bom.cdx.json kev-snapshot.json --output report.json`.
- Optional OSV package-version lookup: `hco sbom osv-correlate bom.cdx.json --output sbom-osv-report.json`. This explicitly sends eligible package URLs and versions to OSV.dev; it does not upload the raw SBOM.
- File signing: see `hco keygen`, `hco sign` and `hco verify-signature`. Protect the encrypted private key and passphrase.

## Agent access

The current Cyber Observatory release exposes a CLI and Python library. It does not currently provide a dedicated MCP server. Agents should use an operator-controlled wrapper with narrow file scope and explicit approval for any external action. See [Agent Onboarding](AGENT-ONBOARDING.md).

## Safety and limitations

Only assess files and systems you own or are authorized to assess. Secret scanning is heuristic. KEV is not a complete vulnerability database. A clean report is not proof that a system is secure. The file encryption command buffers the complete file and enforces a 64 MiB limit.
