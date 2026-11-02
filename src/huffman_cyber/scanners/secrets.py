"""Local-only heuristic secret candidate scanner with mandatory redaction."""
from __future__ import annotations

import math
import re
from collections.abc import Iterator
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
PATTERNS = {
    "private_key_header": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "aws_access_key_candidate": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token_candidate": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "generic_assignment_candidate": re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*["']?([^\s"'#]{12,})"""
    ),
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((p := value.count(ch) / len(value)) * math.log2(p) for ch in set(value))


def _walk(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        relative_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in relative_parts):
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def scan(root: str | Path) -> list[dict[str, object]]:
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise ValueError("scan target must be a directory")
    findings: list[dict[str, object]] = []
    for path in _walk(base):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for rule, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    if rule == "generic_assignment_candidate" and match.lastindex:
                        candidate = match.group(1)
                    else:
                        candidate = match.group(0)
                    relative = path.relative_to(base).as_posix()
                    findings.append({
                        "id": f"secret-candidate:{relative}:{line_no}:{rule}",
                        "type": "secret_candidate",
                        "rule": rule,
                        "path": relative,
                        "line": line_no,
                        "evidence": "[REDACTED]",
                        "candidate_length": len(candidate),
                        "candidate_entropy_bits_per_char": round(_entropy(candidate), 2),
                        "confidence": "heuristic",
                        "status": "requires_manual_validation",
                    })
    return findings