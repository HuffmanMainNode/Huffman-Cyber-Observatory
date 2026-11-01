from huffman_cyber.scanners.secrets import scan


def test_secret_scanner_redacts_candidate(tmp_path):
    (tmp_path / "config.txt").write_text("api_key = 'abcdefghijklmnop123456'\n")
    findings = scan(tmp_path)
    assert findings
    assert all(item["evidence"] == "[REDACTED]" for item in findings)
    assert "abcdefghijklmnop123456" not in str(findings)