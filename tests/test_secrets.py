from huffman_cyber.scanners.secrets import scan


def test_secret_scanner_redacts_candidate(tmp_path):
    (tmp_path / "config.txt").write_text("api_key = 'abcdefghijklmnop123456'\\n")
    findings = scan(tmp_path)
    assert findings
    assert all(item["evidence"] == "[REDACTED]" for item in findings)
    assert "abcdefghijklmnop123456" not in str(findings)


def test_scan_root_under_skipped_name_parent_is_scanned(tmp_path):
    root = tmp_path / "build" / "proj"
    root.mkdir(parents=True)
    (root / "config.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\\n')
    findings = scan(root)
    assert any(item["rule"] == "aws_access_key_candidate" for item in findings)


def test_scan_root_under_venv_parent_is_scanned(tmp_path):
    root = tmp_path / "venv" / "x"
    root.mkdir(parents=True)
    (root / "config.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\\n')
    assert scan(root)


def test_nested_node_modules_is_skipped(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "src" / "config.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\\n')
    (tmp_path / "node_modules" / "pkg" / "config.py").write_text(
        'key = "AKIAIOSFODNN7EXAMPLE"\\n'
    )
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0]["path"] == "src/config.py"
