from huffman_cyber.integrity import create_manifest, verify_manifest


def test_manifest_detects_tamper_and_unexpected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    manifest = create_manifest(root)
    (root / "a.txt").write_text("changed")
    (root / "b.txt").write_text("new")
    result = verify_manifest(manifest, root)
    assert result["changed"] == ["a.txt"]
    assert result["unexpected"] == ["b.txt"]


def test_manifest_excludes_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("not in scope")
    (root / "link.txt").symlink_to(outside)
    assert create_manifest(root)["entries"] == []