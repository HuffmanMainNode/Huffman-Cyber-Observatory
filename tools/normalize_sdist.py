"""Normalize source-distribution archive metadata for reproducible builds."""

from __future__ import annotations

import argparse
import copy
import gzip
import os
import tarfile
from pathlib import Path


def normalize_sdist(path: Path, *, epoch: int) -> None:
    """Rewrite tar metadata deterministically without extracting archive members."""
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ValueError("epoch must be a non-negative integer")
    temporary = path.with_name(path.name + ".normalized")
    try:
        with tarfile.open(path, mode="r:gz") as source:
            members = sorted(source.getmembers(), key=lambda member: member.name)
            with temporary.open("wb") as raw_output:
                with gzip.GzipFile(
                    filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=0
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
                    ) as target:
                        for member in members:
                            normalized = copy.copy(member)
                            normalized.mtime = epoch
                            normalized.uid = 0
                            normalized.gid = 0
                            normalized.uname = ""
                            normalized.gname = ""
                            normalized.pax_headers = {}
                            if member.isfile():
                                stream = source.extractfile(member)
                                if stream is None:
                                    raise ValueError(f"cannot read archive member: {member.name}")
                                with stream:
                                    target.addfile(normalized, stream)
                            else:
                                target.addfile(normalized)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    normalize_sdist(args.archive, epoch=args.epoch)
    print(f"normalized source archive metadata: {args.archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
