"""Minimal, dependency-free SBOM inventory and CISA KEV correlation.

Supports CycloneDX JSON and SPDX JSON. This is inventory matching, not a full
package-manager resolver or proof that a component is exploitable.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _cyclonedx(document: dict[str, Any]) -> list[dict[str, str]]:
    components = document.get("components", [])
    if not isinstance(components, list):
        raise ValueError("CycloneDX components must be an array")
    records = []
    for component in components:
        if not isinstance(component, dict):
            continue
        records.append({
            "name": str(component.get("name", "unknown")),
            "version": str(component.get("version", "")),
            "purl": str(component.get("purl", "")),
            "cpe": str(component.get("cpe", "")),
            "source_type": "cyclonedx",
        })
    return records


def _spdx(document: dict[str, Any]) -> list[dict[str, str]]:
    packages = document.get("packages", [])
    if not isinstance(packages, list):
        raise ValueError("SPDX packages must be an array")
    records = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        refs = package.get("externalRefs", [])
        purl = ""
        cpe = ""
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                locator = str(ref.get("referenceLocator", ""))
                category = str(ref.get("referenceCategory", "")).lower()
                if locator.startswith("pkg:"):
                    purl = locator
                if "cpe" in category or locator.startswith("cpe:"):
                    cpe = locator
        records.append({
            "name": str(package.get("name", "unknown")),
            "version": str(package.get("versionInfo", "")),
            "purl": purl,
            "cpe": cpe,
            "source_type": "spdx",
        })
    return records


def load_sbom(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser().resolve(strict=True)
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("SBOM root must be a JSON object")
    if "bomFormat" in document and document.get("bomFormat") == "CycloneDX":
        records = _cyclonedx(document)
        kind = "CycloneDX"
    elif "spdxVersion" in document:
        records = _spdx(document)
        kind = "SPDX"
    else:
        raise ValueError("unsupported SBOM: expected CycloneDX JSON or SPDX JSON")
    return {
        "schema_version": "1.0",
        "format": kind,
        "source_file": source.name,
        "component_count": len(records),
        "components": records,
    }


def correlate_kev(sbom: dict[str, Any], kev_snapshot: dict[str, Any]) -> dict[str, Any]:
    """Correlate explicit CVE references in SBOM metadata with KEV CVE IDs."""
    catalog = kev_snapshot.get("catalog", {})
    vulnerabilities = catalog.get("vulnerabilities", []) if isinstance(catalog, dict) else []
    kev_ids = {
        item.get("cveID") for item in vulnerabilities
        if isinstance(item, dict) and isinstance(item.get("cveID"), str)
    }
    findings = []
    for component in sbom.get("components", []):
        # CVE matching is only possible where the SBOM explicitly carries CVE
        # identifiers in its component metadata; package-name guessing is avoided.
        refs = component.get("cve_ids", [])
        if not isinstance(refs, list):
            continue
        for cve in refs:
            if isinstance(cve, str) and cve in kev_ids:
                findings.append({
                    "cve_id": cve,
                    "component": component.get("name"),
                    "version": component.get("version"),
                    "match_type": "explicit_sbom_cve_reference",
                    "severity": "known_exploited_vulnerability_catalog",
                    "requires_manual_triage": True,
                })
    return {
        "schema_version": "1.0",
        "sbom_format": sbom.get("format"),
        "kev_source": kev_snapshot.get("source"),
        "kev_sha256": kev_snapshot.get("sha256"),
        "component_count": sbom.get("component_count", 0),
        "finding_count": len(findings),
        "findings": findings,
        "limitations": [
            "This does not infer CVEs from package names or versions.",
            "An SBOM match does not prove the vulnerable code path is present or reachable.",
            "Absence of a match does not establish that dependencies are vulnerability-free.",
            "Use a dedicated version-aware advisory matcher for comprehensive dependency analysis."
        ]
    }
