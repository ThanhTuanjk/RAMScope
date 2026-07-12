from pathlib import Path
from ramscope.case.evidence_hasher import hash_file


def test_hash_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"RAMScope")
    hashes = hash_file(sample)
    assert hashes.md5 == "f62b0643111e94f467409925ce495b6b"
    assert hashes.sha256 == "a0e3fb08878f1c39071faaae3268d2cbf3b0f17aee08fb1405ae87d2a89132e4"
