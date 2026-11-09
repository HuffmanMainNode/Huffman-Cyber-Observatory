from __future__ import annotations

import gzip
import io
import tarfile
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "normalize_sdist.py"
SPEC = spec_from_file_location("hco_normalize_sdist", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
normalize_sdist = MODULE.normalize_sdist


def _make_archive(path: Path, *, mtime: int, uid: int, uname: str) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="different-name.tar", mode="wb", fileobj=raw, mtime=mtime) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as archive:
                payload = b"stable package metadata"
                info = tarfile.TarInfo("package/PKG-INFO")
                info.size = len(payload)
                info.mtime = mtime
                info.uid = uid
                info.gid = uid
                info.uname = uname
                info.gname = uname
                archive.addfile(info, io.BytesIO(payload))


def test_sdist_normalization_removes_runner_metadata(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _make_archive(first, mtime=100, uid=1001, uname="runner-a")
    _make_archive(second, mtime=200, uid=1002, uname="runner-b")

    normalize_sdist(first, epoch=123456789)
    normalize_sdist(second, epoch=123456789)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        member = archive.getmember("package/PKG-INFO")
        assert member.mtime == 123456789
        assert member.uid == 0
        assert member.gid == 0
        assert member.uname == ""
        assert member.gname == ""
