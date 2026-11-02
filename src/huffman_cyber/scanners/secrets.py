"""Local-only heuristic secret candidate scanner with mandatory redaction."""
from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"
}
PATTERNS = {
    "private_key_header": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    ),
    "pgp_private_key_block": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    "aws_access_key_candidate": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token_candidate": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "gitlab_token_candidate": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    "slack_token_candidate": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "google_api_key_candidate": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "stripe_secret_candidate": re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    "generic_assignment_candidate": re.compile(
        r"""(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|password|token|access[_-]?token)\s*[:=]\s*["']?([^\s"'#]{12,})"""
    ),
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (probability := value.count(char) / len(value))
        * math.log2(probability)
        for char in set(value)
    )


def scan_report(root: str | Path) -> dict[str, Any]:
    """Scan a directory and return redacted findings plus coverage accounting."""
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise ValueError("scan target must be a directory")

    findings: list[dict[str, object]] = []
    files_scanned = 0
    files_skipped = {
        "oversize": 0,
        "undecodable": 0,
        "unreadable": 0,
        "skipped_dir": 0,
    }

    for path in base.rglob("*"):
        relative_parts = path.relative_to(base).parts
        if path.is_dir() and path.name in SKIP_DIRS:
            files_skipped["skipped_dir"] += 1
            continue
        if any(part in SKIP_DIRS for part in relative_parts):
            continue
        if not path.is_file() or path.is_symlink():
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                files_skipped["oversize"] += 1
                continue
        except OSError:
            files_skipped["unreadable"] += 1
            continue
        try:
            source_text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            files_skipped["undecodable"] += 1
            continue
        except OSError:
            files_skipped["unreadable"] += 1
            continue

        files_scanned += 1
        relative = path.relative_to(base).as_posix()
        for line_no, line in enumerate(source_text.splitlines(), 1):
            for rule, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    if rule == "generic_assignment_candidate" and match.lastindex:
                        candidate = match.group(1)
                    else:
                        candidate = match.group(0)
                    findings.append(
                        {
                            "id": f"secret-candidate:{relative}:{line_no}:{rule}",
                            "type": "secret_candidate",
                            "rule": rule,
                            "path": relative,
                            "line": line_no,
                            "evidence": "[REDACTED]",
                            "candidate_length": len(candidate),
                            "candidate_entropy_bits_per_char": round(
                                _entropy(candidate), 2
                            ),
                            "confidence": "heuristic",
                            "status": "requires_manual_validation",
                        }
                    )

    return {
        "findings": findings,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
    }


def scan(root: str | Path) -> list[dict[str, object]]:
    """Backward-compatible findings-only interface."""
    return scan_report(root)["findings"]
