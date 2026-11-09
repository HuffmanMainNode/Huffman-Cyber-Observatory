"""CISA KEV feed client with HTTPS, size limits, validation, and provenance."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .http import open_https_no_redirect

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_FEED_BYTES = 20 * 1024 * 1024
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def fetch_kev(timeout: float = 20.0) -> dict[str, Any]:
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= 60:
        raise ValueError("CISA feed timeout must be between 1 and 60 seconds")
    request = urllib.request.Request(
        FEED_URL,
        headers={"User-Agent": "HuffmanCyberObservatory/0.1.0 (+defensive-security)"},
    )
    # The URL is a fixed, code-owned HTTPS endpoint, not user-supplied input.
    with open_https_no_redirect(request, timeout=timeout, allowed_host="www.cisa.gov") as response:
        final = urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname not in {"cisa.gov", "www.cisa.gov"}:
            raise ValueError("CISA feed returned an unexpected endpoint")
        if response.status != 200:
            raise RuntimeError(f"CISA feed returned HTTP {response.status}")
        raw = response.read(MAX_FEED_BYTES + 1)
    if len(raw) > MAX_FEED_BYTES:
        raise ValueError("CISA feed exceeds configured size limit")
    document = json.loads(raw)
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise ValueError("unexpected CISA KEV feed structure")
    released = document.get("dateReleased")
    if not isinstance(released, str):
        raise ValueError("CISA feed dateReleased must be a date string")
    try:
        date.fromisoformat(released)
    except ValueError as exc:
        raise ValueError("CISA feed dateReleased must use YYYY-MM-DD") from exc
    declared_count = document.get("count")
    if declared_count is not None and (
        not isinstance(declared_count, int) or isinstance(declared_count, bool)
        or declared_count != len(document["vulnerabilities"])
    ):
        raise ValueError("CISA feed count does not match its vulnerability records")
    for index, item in enumerate(document["vulnerabilities"]):
        if not isinstance(item, dict):
            raise ValueError(f"CISA vulnerability record {index} must be an object")
        cve_id = item.get("cveID")
        date_added = item.get("dateAdded")
        if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
            raise ValueError(f"CISA vulnerability record {index} has an invalid CVE ID")
        if not isinstance(date_added, str):
            raise ValueError(f"CISA vulnerability record {index} dateAdded must be a date string")
        try:
            date.fromisoformat(date_added)
        except ValueError as exc:
            raise ValueError(f"CISA vulnerability record {index} dateAdded must use YYYY-MM-DD") from exc
        for field in ("vendorProject", "product", "vulnerabilityName", "shortDescription", "requiredAction"):
            if field in item and not isinstance(item[field], str):
                raise ValueError(f"CISA vulnerability record {index} {field} must be a string")
        if "dueDate" in item:
            if not isinstance(item["dueDate"], str):
                raise ValueError(f"CISA vulnerability record {index} dueDate must be a date string")
            try:
                date.fromisoformat(item["dueDate"])
            except ValueError as exc:
                raise ValueError(f"CISA vulnerability record {index} dueDate must use YYYY-MM-DD") from exc
        if "notes" in item and not isinstance(item["notes"], str):
            raise ValueError(f"CISA vulnerability record {index} notes must be a string")
    return {
        "schema_version": "1.0",
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "source_url": FEED_URL,
        "retrieved_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source_date": document.get("dateReleased"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "vulnerability_count": len(document["vulnerabilities"]),
        "catalog": document,
    }


def save_kev(output: str | Path) -> dict[str, Any]:
    snapshot = fetch_kev()
    Path(output).write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return snapshot