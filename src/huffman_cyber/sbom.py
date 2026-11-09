"""Bounded SBOM inventory and explicit CISA KEV correlation.

Supports CycloneDX JSON and SPDX JSON. Version-aware advisory queries are
implemented separately and must be explicitly invoked by the operator.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_SBOM_COMPONENTS = 10_000


def _string_field(record: dict[str, Any], field: str, default: str = "") -> str:
    value = record.get(field, default)
    if not isinstance(value, str):
        raise ValueError(f"SBOM field {field!r} must be a string")
    return value


def _cyclonedx(document: dict[str, Any]) -> list[dict[str, Any]]:
    components = document.get("components", [])
    if not isinstance(components, list):
        raise ValueError("CycloneDX components must be an array")
    if len(components) > MAX_SBOM_COMPONENTS:
        raise ValueError(f"SBOM exceeds {MAX_SBOM_COMPONENTS} components")
    records: list[dict[str, Any]] = []
    by_ref: dict[str, dict[str, Any]] = {}
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ValueError(f"CycloneDX component {index} must be an object")
        record = {
            "name": _string_field(component, "name", "unknown"),
            "version": _string_field(component, "version"),
            "purl": _string_field(component, "purl"),
            "cpe": _string_field(component, "cpe"),
            "bom_ref": _string_field(component, "bom-ref"),
            "cve_ids": [],
            "source_type": "cyclonedx",
        }
        records.append(record)
        if record["bom_ref"]:
            if record["bom_ref"] in by_ref:
                raise ValueError(f"duplicate CycloneDX bom-ref: {record['bom_ref']}")
            by_ref[record["bom_ref"]] = record

    vulnerabilities = document.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("CycloneDX vulnerabilities must be an array")
    for index, vulnerability in enumerate(vulnerabilities):
        if not isinstance(vulnerability, dict):
            raise ValueError(f"CycloneDX vulnerability {index} must be an object")
        cve_id = vulnerability.get("id")
        if cve_id is not None and not isinstance(cve_id, str):
            raise ValueError("CycloneDX vulnerability id must be a string")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        affects = vulnerability.get("affects", [])
        if not isinstance(affects, list):
            raise ValueError("CycloneDX vulnerability affects must be an array")
        for affected in affects:
            if not isinstance(affected, dict):
                raise ValueError("CycloneDX affected component reference must be an object")
            target = by_ref.get(_string_field(affected, "ref"))
            if target is not None:
                target["cve_ids"].append(cve_id)
    for record in records:
        record["cve_ids"] = sorted(set(record["cve_ids"]))
    return records


def _spdx(document: dict[str, Any]) -> list[dict[str, Any]]:
    packages = document.get("packages", [])
    if not isinstance(packages, list):
        raise ValueError("SPDX packages must be an array")
    if len(packages) > MAX_SBOM_COMPONENTS:
        raise ValueError(f"SBOM exceeds {MAX_SBOM_COMPONENTS} components")
    records: list[dict[str, Any]] = []
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise ValueError(f"SPDX package {index} must be an object")
        refs = package.get("externalRefs", [])
        if not isinstance(refs, list):
            raise ValueError("SPDX externalRefs must be an array")
        purl = ""
        cpe = ""
        cve_ids: list[str] = []
        for ref in refs:
            if not isinstance(ref, dict):
                raise ValueError("SPDX external reference must be an object")
            locator = _string_field(ref, "referenceLocator")
            category = _string_field(ref, "referenceCategory").lower()
            if locator.startswith("pkg:"):
                purl = locator
            if "cpe" in category or locator.startswith("cpe:"):
                cpe = locator
            if locator.startswith("CVE-"):
                cve_ids.append(locator)
        records.append({
            "name": _string_field(package, "name", "unknown"),
            "version": _string_field(package, "versionInfo"),
            "purl": purl,
            "cpe": cpe,
            "cve_ids": sorted(set(cve_ids)),
            "source_type": "spdx",
        })
    return records


def load_sbom(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser().resolve(strict=True)
    if not source.is_file():
        raise ValueError("SBOM source must be a regular file")
    if source.stat().st_size > MAX_SBOM_BYTES:
        raise ValueError(f"SBOM exceeds configured size limit ({MAX_SBOM_BYTES} bytes)")
    raw = source.read_bytes()
    if len(raw) > MAX_SBOM_BYTES:
        raise ValueError(f"SBOM exceeds {MAX_SBOM_BYTES} byte safety limit")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("SBOM root must be a JSON object")
    if document.get("bomFormat") == "CycloneDX":
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
