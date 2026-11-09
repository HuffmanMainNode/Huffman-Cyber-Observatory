"""Bounded, opt-in OSV.dev package-version queries.

Only package URLs and versions are transmitted. Raw SBOM documents and local
file paths are never sent to OSV. The querybatch API returns advisory IDs and
modification timestamps, not severity or exploitability determinations.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from datetime import UTC, datetime
from typing import Any

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
MAX_COMPONENTS = 1000
BATCH_SIZE = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES_PER_BATCH = 10
CVE_OR_ADVISORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _query_for_component(component: dict[str, Any]) -> dict[str, Any] | None:
    purl = component.get("purl")
    version = component.get("version")
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    if len(purl) > 2048 or any(ord(char) < 0x21 or ord(char) > 0x7E for char in purl):
        return None
    # A versioned PURL already carries its version. OSV rejects a second,
    # top-level version field when both are supplied.
    purl_without_qualifiers = purl.split("?", 1)[0].split("#", 1)[0]
    package_path = purl_without_qualifiers.split("/", 1)[-1]
    query: dict[str, Any] = {"package": {"purl": purl}}
    if "@" not in package_path:
        if not isinstance(version, str) or not version.strip():
            return None
        if len(version) > 256 or any(ord(char) < 0x20 for char in version):
            return None
        query["version"] = version
    return query


def _post_batch(queries: list[dict[str, Any]], timeout: float) -> tuple[dict[str, Any], bytes, bytes]:
    body = json.dumps({"queries": queries}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "HuffmanCyberObservatory/0.2 (+defensive-security)",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        final_url = response.geturl()
        if not final_url.startswith(OSV_QUERY_URL):
            raise ValueError("OSV request redirected to an unexpected endpoint")
        if response.status != 200:
            raise RuntimeError(f"OSV API returned HTTP {response.status}")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("OSV response exceeds configured size limit")
    document = json.loads(raw)
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise ValueError("unexpected OSV querybatch response structure")
    if len(document["results"]) != len(queries):
        raise ValueError("OSV response count does not match submitted query count")
    return document, body, raw


def query_osv(sbom: dict[str, Any], timeout: float = 20.0) -> dict[str, Any]:
    """Query OSV for components with usable PURLs and versions.

    The function is intentionally opt-in and makes no request for components
    that lack a usable package URL and version. Results are advisory leads.
    """
    components = sbom.get("components")
    if not isinstance(components, list):
        raise ValueError("SBOM components must be an array")
    if len(components) > MAX_COMPONENTS:
        raise ValueError(f"OSV query is limited to {MAX_COMPONENTS} SBOM components")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= 60:
        raise ValueError("OSV timeout must be between 1 and 60 seconds")

    unique_queries: list[dict[str, Any]] = []
    query_indexes: dict[str, int] = {}
    component_query_indexes: dict[int, int] = {}
    skipped: list[dict[str, Any]] = []
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ValueError(f"SBOM component {index} must be an object")
        query = _query_for_component(component)
        if query is None:
            skipped.append({
                "component": component.get("name", "unknown"),
                "reason": "missing_or_invalid_package_url_or_version",
            })
            continue
        key = json.dumps(query, sort_keys=True, separators=(",", ":"))
        if key not in query_indexes:
            query_indexes[key] = len(unique_queries)
            unique_queries.append(query)
        component_query_indexes[index] = query_indexes[key]

    advisory_by_query: dict[int, list[dict[str, str | None]]] = {
        index: [] for index in range(len(unique_queries))
    }
    request_hashes: list[str] = []
    response_hashes: list[str] = []
    complete = True

    for offset in range(0, len(unique_queries), BATCH_SIZE):
        batch = unique_queries[offset:offset + BATCH_SIZE]
        pending = [(offset + index, query) for index, query in enumerate(batch)]
        page = 0
        while pending and page < MAX_PAGES_PER_BATCH:
            document, request_bytes, response_bytes = _post_batch(
                [query for _, query in pending], float(timeout)
            )
            request_hashes.append(hashlib.sha256(request_bytes).hexdigest())
            response_hashes.append(hashlib.sha256(response_bytes).hexdigest())
            next_pending: list[tuple[int, dict[str, Any]]] = []
            for (query_index, original_query), result in zip(pending, document["results"], strict=True):
                if not isinstance(result, dict):
                    raise ValueError("OSV response contains a malformed result")
                vulnerabilities = result.get("vulns", [])
                if not isinstance(vulnerabilities, list):
                    raise ValueError("OSV result vulns field must be an array")
                for vulnerability in vulnerabilities:
                    if not isinstance(vulnerability, dict):
                        raise ValueError("OSV vulnerability record must be an object")
                    advisory_id = vulnerability.get("id")
                    if not isinstance(advisory_id, str) or not CVE_OR_ADVISORY_ID.fullmatch(advisory_id):
                        raise ValueError("OSV returned an invalid advisory identifier")
                    modified = vulnerability.get("modified")
                    if modified is not None and not isinstance(modified, str):
                        raise ValueError("OSV advisory modified field must be a string")
                    advisory_by_query[query_index].append({
                        "id": advisory_id,
                        "modified": modified,
                    })
                token = result.get("next_page_token")
                if token is not None:
                    if not isinstance(token, str) or not token:
                        raise ValueError("OSV pagination token is invalid")
                    next_query = dict(original_query)
                    next_query["page_token"] = token
                    next_pending.append((query_index, next_query))
            pending = next_pending
            page += 1
        if pending:
            complete = False

    findings: list[dict[str, Any]] = []
    for component_index, query_index in component_query_indexes.items():
        component = components[component_index]
        for advisory in advisory_by_query[query_index]:
            advisory_id = advisory["id"]
            findings.append({
                "advisory_id": advisory_id,
                "advisory_url": f"https://osv.dev/vulnerability/{advisory_id}",
                "advisory_modified": advisory["modified"],
                "component": component.get("name", "unknown"),
                "version": component.get("version", ""),
                "purl": component.get("purl"),
                "match_type": "osv_package_version_query",
                "exploitation_status": "not_determined_by_osv_querybatch",
                "requires_manual_triage": True,
            })

    return {
        "schema_version": "1.0",
        "source": "OSV.dev",
        "source_url": OSV_QUERY_URL,
        "retrieved_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "sbom_format": sbom.get("format"),
        "component_count": len(components),
        "queried_package_count": len(unique_queries),
        "skipped_components": skipped,
        "finding_count": len(findings),
        "findings": findings,
        "complete": complete,
        "request_sha256": request_hashes,
        "response_sha256": response_hashes,
        "limitations": [
            "Only components with usable package URLs and versions are queried.",
            "OSV querybatch returns advisory identifiers and modification timestamps, not full severity or remediation details.",
            "A package-version match does not prove vulnerable code is present, reachable, or exploitable.",
            "OSV coverage depends on the advisories and ecosystems represented in OSV.dev.",
            "A clean result or incomplete query is not proof that dependencies are vulnerability-free.",
            "Package URLs and versions are transmitted to OSV.dev; raw SBOM files and local paths are not transmitted.",
        ],
    }
