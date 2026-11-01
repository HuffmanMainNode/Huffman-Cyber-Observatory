"""Versioned JSON report helpers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"


def report(kind: str, findings: list[dict[str, Any]], *, sources: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "huffman-cyber-observatory",
        "report_type": kind,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sources": sources or [],
        "findings": findings,
        "limitations": [
            "A clean result is not proof of security.",
            "Heuristic findings require human validation.",
        ],
    }