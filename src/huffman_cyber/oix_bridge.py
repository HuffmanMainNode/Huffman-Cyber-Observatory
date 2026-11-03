"""Optional OIX bridge for local Cyber Observatory reports and SBOM evidence.

The adapter hashes a selected local report and signs only bounded metadata.
It does not upload artifacts, fetch source URLs, or start a network session.
"""
from __future__ import annotations

import hashlib
import mimetypes
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from . import __version__


def create_evidence_message(
    *,
    identity_dir: str | Path,
    recipient: str,
    artifact_path: str | Path,
    evidence_type: str,
    method_name: str,
    method_version: str,
    summary: dict[str, Any],
    limitations: list[str],
    classification: str = "internal",
    status: str = "derived",
    source_uri: str | None = None,
    source_timestamp: str | None = None,
    media_type: str | None = None,
    capability: str = "public.research",
) -> dict[str, Any]:
    """Hash a local report and return a signed OIX evidence.submit envelope.

    Supported report types are SBOM analysis and file manifests. The artifact
    remains local; the message carries only its digest and metadata.
    """
    try:
        from oix.envelope import create_message
        from oix.identity import load_private_key
        from oix.inbox import validate_evidence_submit_payload
    except ImportError as exc:
        raise RuntimeError(
            "OIX is optional; install Open-Intelligence-Exchange alongside this project"
        ) from exc

    if evidence_type not in {"sbom_analysis", "file_manifest"}:
        raise ValueError("Cyber Observatory evidence type must be sbom_analysis or file_manifest")
    source = Path(artifact_path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise ValueError("artifact_path must be an existing regular file, not a symlink")
    source = source.resolve(strict=True)

    digest = hashlib.sha256()
    size_bytes = 0
    with source.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size_bytes += len(chunk)

    payload = {
        "schema_version": "1.0",
        "evidence_id": str(uuid4()),
        "evidence_type": evidence_type,
        "source_uri": source_uri,
        "source_timestamp": source_timestamp,
        "collected_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "collector": {"name": "huffman-cyber-observatory", "version": __version__},
        "method": {"name": method_name, "version": method_version},
        "artifact": {
            "sha256": digest.hexdigest(),
            "size_bytes": size_bytes,
            "media_type": media_type
            or mimetypes.guess_type(source.name)[0]
            or "application/octet-stream",
        },
        "classification": classification,
        "status": status,
        "summary": summary,
        "limitations": limitations,
    }
    validate_evidence_submit_payload(payload)
    return create_message(
        load_private_key(identity_dir),
        recipient,
        "evidence.submit",
        payload,
        capability=capability,
    )
