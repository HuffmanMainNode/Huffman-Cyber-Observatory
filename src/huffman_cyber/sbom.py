"""Minimal, dependency-free SBOM inventory and CISA KEV correlation.

Supports CycloneDX JSON and SPDX JSON. This is inventory matching, not a full
package-manager resolver or proof that a component is exploitable.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _cyclonedx(document: dict[str, Any]) -> list[dict[str, Any]]:
    components = document.get("components", [])
    if not isinstance(components, list):
        raise ValueError("CycloneDX components must be an array")
    records: list[dict[str, Any]] = []
    by_ref: dict[str, dict[str, Any]] = {}
    for component in components:
        if not isinstance(component, dict):
            continue
        record = {
            "name": str(component.get("name", "unknown")),
            "version": str(component.get("version", "")),
            "purl": str(component.get("purl", "")),
            "cpe": str(component.get("cpe", "")),
            "bom_ref": str(component.get("bom-ref", "")),
            "cve_ids": [],
            "source_type": "cyclonedx",
        }
        records.append(record)
        if record["bom_ref"]:
            by_ref[record["bom_ref"]] = record

    vulnerabilities = document.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("CycloneDX vulnerabilities must be an array")
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        cve_id = vulnerability.get("id")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        affects = vulnerability.get("affects", [])
        if not isinstance(affects, list):
            continue
        for affected in affects:
            if isinstance(affected, dict):
                target = by_ref.get(str(affected.get("ref", "")))
                if target is not None:
                    target["cve_ids"].append(cve_id)
    for record in records:
        record["cve_ids"] = sorted(set(record["cve_ids"]))
    return records


def _spdx(document: dict[str, Any]) -> list[dict[str, Any]]:
    packages = document.get("packages", [])
    if not isinstance(packages, list):
        raise ValueError("SPDX packages must be an array")
    records: list[dict[str, Any]] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        refs = package.get("externalRefs", [])
        purl = ""
        cpe = ""
        cve_ids: list[str] = []
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
                if locator.startswith("CVE-"):
                    cve_ids.append(locator)
        records.append({
            "name": str(package.get("name", "unknown")),
            "version": str(package.get("versionInfo", "")),
            "purl": purl,
            "cpe": cpe,
            "cve_ids": sorted(set(cve_ids)),
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
