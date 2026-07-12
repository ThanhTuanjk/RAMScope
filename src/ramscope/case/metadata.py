from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ramscope import TOOL_NAME, __version__
from ramscope.case.evidence_hasher import EvidenceHashes
from ramscope.models import EvidenceMetadata


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_evidence_metadata(
    case_id: str,
    input_file: Path,
    hashes: EvidenceHashes,
    volatility_command: str,
    analyst: str = "",
) -> EvidenceMetadata:
    return EvidenceMetadata(
        case_id=case_id,
        input_file=str(input_file),
        file_size_bytes=input_file.stat().st_size,
        md5=hashes.md5,
        sha256=hashes.sha256,
        analysis_started=utc_now_iso(),
        analysis_finished="",
        tool_name=TOOL_NAME,
        tool_version=__version__,
        volatility_backend="Volatility3",
        volatility_command=volatility_command,
        analyst=analyst,
    )
