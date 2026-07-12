from pathlib import Path

import pytest

from ramscope.case.case_manager import CaseManager


def test_case_folder_creation(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory")
    case_dir, metadata = CaseManager(tmp_path / "cases").create_case("CASE001", evidence, "vol")
    assert case_dir.exists()
    assert (case_dir / "evidence" / "evidence_metadata.json").exists()
    assert metadata.case_id == "CASE001"


def test_case_id_cannot_escape_output_root(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory")
    with pytest.raises(ValueError):
        CaseManager(tmp_path / "cases").create_case("../escape", evidence, "vol")


def test_existing_case_is_not_silently_reused(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory")
    manager = CaseManager(tmp_path / "cases")
    manager.create_case("CASE001", evidence, "vol")
    with pytest.raises(FileExistsError):
        manager.create_case("CASE001", evidence, "vol")
