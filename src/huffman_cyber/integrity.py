"""Deterministic SHA-256 manifests; symlinks are excluded."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_manifest(root: str | Path) -> dict[str, Any]:
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise ValueError("manifest target must be a directory")
    entries = []
    for path in sorted(base.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        entries.append({
            "path": path.relative_to(base).as_posix(),
            "size": path.stat().st_size,
            "sha256": _digest(path),
        })
    return {"schema_version": "1.0", "algorithm": "sha256", "entries": entries}


def verify_manifest(manifest: dict[str, Any], root: str | Path) -> dict[str, list[str]]:
    if manifest.get("schema_version") != "1.0" or manifest.get("algorithm") != "sha256":
        raise ValueError("unsupported manifest schema or hash algorithm")
    base = Path(root).expanduser().resolve(strict=True)
    expected = {item["path"]: item["sha256"] for item in manifest.get("entries", [])}
    if any(Path(name).is_absolute() or ".." in Path(name).parts for name in expected):
        raise ValueError("manifest contains an unsafe path")
    actual: dict[str, str] = {}
    for name in expected:
        target = base / name
        if target.is_symlink():
            continue
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(base)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            actual[name] = _digest(resolved)
    changed = sorted(
        name for name, digest in expected.items()
        if name in actual and actual[name] != digest
    )
    missing = sorted(set(expected) - set(actual))
    unexpected = []
    for path in base.rglob("*"):
        if path.is_file() and not path.is_symlink():
            name = path.relative_to(base).as_posix()
            if name not in expected:
                unexpected.append(name)
    return {"changed": changed, "missing": missing, "unexpected": sorted(unexpected)}


def write_json(path: str | Path, data: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")