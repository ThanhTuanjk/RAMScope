from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EvidenceHashes:
    md5: str
    sha256: str


def hash_file(path: Path, chunk_size: int = 1024 * 1024) -> EvidenceHashes:
    if not path.exists():
        raise FileNotFoundError(f"Evidence file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Evidence path is not a file: {path}")
    md5_hash = hashlib.md5(usedforsecurity=False)
    sha256_hash = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(chunk_size), b""):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    return EvidenceHashes(md5_hash.hexdigest(), sha256_hash.hexdigest())
