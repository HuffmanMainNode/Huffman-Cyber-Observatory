from pathlib import Path

from huffman_cyber.scanners.secrets import MAX_FILE_BYTES, scan, scan_report


def test_secret_scanner_redacts_candidate(tmp_path):
    (tmp_path / "config.txt").write_text("api_key = 'abcdefghijklmnop123456'\n")
    findings = scan(tmp_path)
    assert findings
    assert all(item["evidence"] == "[REDACTED]" for item in findings)
    assert "abcdefghijklmnop123456" not in str(findings)


def test_scan_root_under_skipped_name_parent_is_scanned(tmp_path):
    root = tmp_path / "build" / "proj"
    root.mkdir(parents=True)
    (root / "config.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan(root)
    assert any(item["rule"] == "aws_access_key_candidate" for item in findings)


def test_scan_root_under_venv_parent_is_scanned(tmp_path):
    root = tmp_path / "venv" / "x"
    root.mkdir(parents=True)
    (root / "config.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
    assert scan(root)


def test_nested_node_modules_is_skipped(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "src" / "config.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / "node_modules" / "pkg" / "config.py").write_text(
        'key = "AKIAIOSFODNN7EXAMPLE"\n'
    )
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0]["path"] == "src/config.py"


def test_scan_report_accounts_for_skipped_files_and_directories(tmp_path):
    (tmp_path / "readme.txt").write_text("ordinary text")
    (tmp_path / "oversize.bin").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    (tmp_path / "binary.bin").write_bytes(b"\xff\xfe")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "secret.txt").write_text(
        "api_key=abcdefghijklmnop"
    )

    result = scan_report(tmp_path)

    assert result["files_scanned"] == 1
    assert result["files_skipped"] == {
        "oversize": 1,
        "undecodable": 1,
        "unreadable": 0,
        "skipped_dir": 1,
    }


def test_scan_report_counts_unreadable_file(tmp_path, monkeypatch):
    target = tmp_path / "blocked.txt"
    target.write_text("secret")
    original_read_text = Path.read_text

    def fail_for_target(path, *args, **kwargs):
        if path.name == "blocked.txt":
            raise PermissionError("permission denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_for_target)
    result = scan_report(tmp_path)
    assert result["files_skipped"]["unreadable"] == 1
    assert result["files_scanned"] == 0


def test_extended_secret_patterns_are_redacted(tmp_path):
    tokens = [
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuvwxyz123456",
        "glpat-abcdefghijklmnopqrstuvwxyz123456",
        "xoxb-123456789012345678901234",
        "AIza123456789012345678901234567890123",
        "sk_live_12345678901234567890",
        "API_KEY=abcdefghijklmnop123456",
        "SECRET_KEY=abcdefghijklmnop123456",
    ]
    (tmp_path / ".env").write_text("\n".join(tokens))
    result = scan_report(tmp_path)
    rules = {item["rule"] for item in result["findings"]}

    assert {
        "private_key_header",
        "pgp_private_key_block",
        "aws_access_key_candidate",
        "github_token_candidate",
        "gitlab_token_candidate",
        "slack_token_candidate",
        "google_api_key_candidate",
        "stripe_secret_candidate",
        "generic_assignment_candidate",
    } <= rules
    assert all(item["evidence"] == "[REDACTED]" for item in result["findings"])
    assert all(token not in str(result) for token in tokens)
