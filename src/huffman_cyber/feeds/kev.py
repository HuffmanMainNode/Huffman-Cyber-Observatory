"""CISA KEV feed client with HTTPS, size limits, validation, and provenance."""
from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_FEED_BYTES = 20 * 1024 * 1024


def fetch_kev(timeout: float = 20.0) -> dict[str, Any]:
    request = urllib.request.Request(
        FEED_URL,
        headers={"User-Agent": "HuffmanCyberObservatory/0.1 (+defensive-security)"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"CISA feed returned HTTP {response.status}")
        raw = response.read(MAX_FEED_BYTES + 1)
    if len(raw) > MAX_FEED_BYTES:
        raise ValueError("CISA feed exceeds configured size limit")
    document = json.loads(raw)
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise ValueError("unexpected CISA KEV feed structure")
    for item in document["vulnerabilities"]:
        if not isinstance(item, dict) or not isinstance(item.get("cveID"), str) or not item["cveID"].startswith("CVE-"):
            raise ValueError("feed contains an invalid vulnerability record")
    return {
        "schema_version": "1.0",
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "source_url": FEED_URL,
        "retrieved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_date": document.get("dateReleased"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "vulnerability_count": len(document["vulnerabilities"]),
        "catalog": document,
    }


def save_kev(output: str | Path) -> dict[str, Any]:
    snapshot = fetch_kev()
    Path(output).write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return snapshot