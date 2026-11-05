"""Deterministic SHA-256 manifests; symlinks are excluded."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PureWindowsPath
from typing import Any

SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


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


def _validate_manifest(manifest: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(manifest, dict):
        raise TypeError("manifest must be a JSON object")
    if manifest.get("schema_version") != "1.0" or manifest.get("algorithm") != "sha256":
        raise ValueError("unsupported manifest schema or hash algorithm")
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise TypeError("manifest entries must be an array")

    expected: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise TypeError(f"manifest entry {index} must be an object")
        name = item.get("path")
        digest = item.get("sha256")
        size = item.get("size")
        if not isinstance(name, str):
            raise TypeError(f"manifest entry {index} path must be a string")
        if not name.strip():
            raise ValueError(f"manifest entry {index} path must not be empty")
        relative = Path(name)
        windows = PureWindowsPath(name)
        if (
            relative.is_absolute()
            or windows.is_absolute()
            or windows.drive
            or "\\" in name
            or ":" in name
            or ".." in relative.parts
            or relative.as_posix() in {"", "."}
        ):
            raise ValueError(f"manifest contains an unsafe path: {name}")
        normalized = relative.as_posix()
        if normalized in expected:
            raise ValueError(f"manifest contains a duplicate path: {normalized}")
        if not isinstance(digest, str):
            raise TypeError(f"manifest SHA-256 must be a string: {normalized}")
        if not SHA256_PATTERN.fullmatch(digest):
            raise ValueError(f"manifest contains an invalid SHA-256 digest: {normalized}")
        if not isinstance(size, int) or isinstance(size, bool):
            raise TypeError(f"manifest file size must be an integer: {normalized}")
        if size < 0:
            raise ValueError(f"manifest file size must be non-negative: {normalized}")
        expected[normalized] = {"sha256": digest.lower(), "size": size}
    return expected


def _has_symlink_component(root: Path, relative: Path) -> bool:
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            return True
    return False


def verify_manifest(manifest: dict[str, Any], root: str | Path) -> dict[str, list[str]]:
    expected = _validate_manifest(manifest)
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise ValueError("verification target must be a directory")

    actual: dict[str, dict[str, Any]] = {}
    for name in expected:
        relative = Path(name)
        if _has_symlink_component(base, relative):
            continue
        target = base / relative
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(base)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            digest = hashlib.sha256()
            size = 0
            with resolved.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            actual[name] = {"sha256": digest.hexdigest(), "size": size}

    changed = sorted(
        name for name, expected_item in expected.items()
        if name in actual and (
            actual[name]["sha256"] != expected_item["sha256"]
            or actual[name]["size"] != expected_item["size"]
        )
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
