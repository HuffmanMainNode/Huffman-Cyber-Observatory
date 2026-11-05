import pytest

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


def test_manifest_rejects_duplicate_paths(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    manifest = create_manifest(root)
    manifest["entries"].append(dict(manifest["entries"][0]))
    with pytest.raises(ValueError, match="duplicate path"):
        verify_manifest(manifest, root)


@pytest.mark.parametrize(
    "unsafe",
    ["../outside", "/etc/passwd", "C:\\Windows\\win.ini", "folder\\..\\secret"],
)
def test_manifest_rejects_unsafe_paths(tmp_path, unsafe):
    root = tmp_path / "root"
    root.mkdir()
    manifest = {
        "schema_version": "1.0",
        "algorithm": "sha256",
        "entries": [{"path": unsafe, "size": 0, "sha256": "0" * 64}],
    }
    with pytest.raises(ValueError, match="unsafe path"):
        verify_manifest(manifest, root)


@pytest.mark.parametrize(
    "entry, error",
    [
        ({"path": "a", "size": True, "sha256": "0" * 64}, TypeError),
        ({"path": "a", "size": -1, "sha256": "0" * 64}, ValueError),
        ({"path": "a", "size": 0, "sha256": "invalid"}, ValueError),
    ],
)
def test_manifest_rejects_malformed_entry_metadata(tmp_path, entry, error):
    root = tmp_path / "root"
    root.mkdir()
    manifest = {"schema_version": "1.0", "algorithm": "sha256", "entries": [entry]}
    with pytest.raises(error):
        verify_manifest(manifest, root)


def test_manifest_rejects_nested_symlink_substitution(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    folder = root / "folder"
    folder.mkdir()
    (folder / "a.txt").write_text("alpha")
    manifest = create_manifest(root)

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.txt").write_text("alpha")
    folder.rename(root / "original-folder")
    (root / "folder").symlink_to(outside, target_is_directory=True)
    (root / "original-folder" / "a.txt").unlink()
    (root / "original-folder").rmdir()

    result = verify_manifest(manifest, root)
    assert result["missing"] == ["folder/a.txt"]
    assert result["changed"] == []


def test_manifest_size_mismatch_is_detected_even_with_matching_digest(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    manifest = create_manifest(root)
    manifest["entries"][0]["size"] += 1
    result = verify_manifest(manifest, root)
    assert result["changed"] == ["a.txt"]
