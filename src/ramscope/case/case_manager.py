from __future__ import annotations

import re
from dataclasses import fields, replace
from pathlib import Path

from ramscope.case.evidence_hasher import hash_file
from ramscope.case.metadata import build_evidence_metadata, utc_now_iso
from ramscope.models import EvidenceMetadata
from ramscope.utils.json_utils import read_json, write_json


CASE_DIRECTORIES = (
    "evidence", "raw/volatility/errors", "normalized", "dumps/suspicious_memory",
    "iocs", "reports", "logs",
)
CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class CaseManager:
    def __init__(self, output_root: Path) -> None:
        self.output_root = output_root

    def create_case(
        self,
        case_id: str,
        input_file: Path,
        volatility_command: str,
        analyst: str = "",
        *,
        resume: bool = False,
        config_sha256: str = "",
        analysis_profile: str = "triage",
    ) -> tuple[Path, EvidenceMetadata]:
        if not CASE_ID_PATTERN.fullmatch(case_id):
            raise ValueError("Case ID must be 1-64 characters using letters, numbers, dot, underscore, or hyphen.")
        input_file = input_file.resolve()
        if not input_file.is_file():
            raise FileNotFoundError(f"Input memory image does not exist: {input_file}")
        root = self.output_root.resolve()
        case_dir = (root / case_id).resolve()
        if root not in case_dir.parents:
            raise ValueError("Case path escapes the configured output directory.")
        metadata_path = case_dir / "evidence" / "evidence_metadata.json"
        current_hashes = hash_file(input_file)
        if metadata_path.exists():
            if not resume:
                raise FileExistsError(f"Case already exists. Use --resume only with the same evidence and configuration: {case_dir}")
            existing = _metadata_from_dict(read_json(metadata_path))
            if existing.sha256 != current_hashes.sha256 or existing.file_size_bytes != input_file.stat().st_size:
                raise ValueError("Resume rejected: evidence hash or size differs from the existing case.")
            if not existing.config_sha256 or not config_sha256:
                raise ValueError("Resume rejected: configuration hash is missing; rerun as a new case.")
            if existing.config_sha256 != config_sha256:
                raise ValueError("Resume rejected: configuration hash differs from the existing case.")
            if existing.analysis_profile and existing.analysis_profile != analysis_profile:
                raise ValueError("Resume rejected: analysis profile differs from the existing case.")
            return case_dir, replace(existing, analysis_finished="")
        for relative_dir in CASE_DIRECTORIES:
            (case_dir / relative_dir).mkdir(parents=True, exist_ok=True)
        metadata = build_evidence_metadata(case_id, input_file, current_hashes, volatility_command, analyst)
        metadata = replace(metadata, config_sha256=config_sha256, analysis_profile=analysis_profile)
        self.write_metadata(case_dir, metadata)
        return case_dir, metadata

    def write_metadata(self, case_dir: Path, metadata: EvidenceMetadata) -> Path:
        return write_json(case_dir / "evidence" / "evidence_metadata.json", metadata)

    def finish_case(self, case_dir: Path, metadata: EvidenceMetadata) -> EvidenceMetadata:
        evidence_path = Path(metadata.input_file)
        current_hashes = hash_file(evidence_path)
        if current_hashes.sha256 != metadata.sha256 or evidence_path.stat().st_size != metadata.file_size_bytes:
            raise ValueError("Analysis rejected: evidence changed after initial hashing.")
        finished = replace(metadata, analysis_finished=utc_now_iso())
        self.write_metadata(case_dir, finished)
        return finished


def _metadata_from_dict(data: object) -> EvidenceMetadata:
    if not isinstance(data, dict):
        raise ValueError("Existing evidence metadata is invalid.")
    allowed = {field.name for field in fields(EvidenceMetadata)}
    filtered = {key: value for key, value in data.items() if key in allowed}
    return EvidenceMetadata(**filtered)
