"""Stable evidence models used by RAMScope."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    return value


@dataclass
class EvidenceMetadata:
    case_id: str
    input_file: str
    file_size_bytes: int
    md5: str
    sha256: str
    analysis_started: str
    analysis_finished: str
    tool_name: str
    tool_version: str
    volatility_backend: str
    volatility_command: str
    analyst: str = ""
    notes: str = "RAMScope is a forensic triage tool. Findings require analyst validation."
    config_sha256: str = ""
    analysis_profile: str = "triage"


@dataclass
class TargetInfo:
    requested_profile: str = "auto"
    selected_profile: str = "unknown"
    family: str = "Windows"
    build: str = ""
    architecture: str = ""
    kernel: str = ""
    symbol_context: str = ""
    status: str = "unassessed"
    reason: str = "windows.info did not provide enough version information."


@dataclass
class NetworkArtifact:
    pid: int | None
    process_name: str
    protocol: str
    local_addr: str
    local_port: int | None
    remote_addr: str
    remote_port: int | None
    state: str
    source_plugin: str = "windows.netscan"
    process_key: str = ""


@dataclass
class MalfindArtifact:
    pid: int | None
    process_name: str
    vad_start: str
    vad_end: str
    protection: str
    tag: str
    has_pe_header: bool
    dump_file: str = ""
    source_plugin: str = "windows.malfind"
    eprocess_offset: str = ""
    process_key: str = ""


@dataclass
class IOC:
    type: str
    value: str
    source: str
    process_name: str = ""
    pid: int | None = None
    confidence: str = "medium"
    note: str = ""
    process_key: str = ""
    actionability: str = "actionable"
    occurrence_count: int = 1


@dataclass
class Finding:
    finding_id: str
    pid: int | None
    process_name: str
    title: str
    severity: str
    score: int
    confidence: str
    category: str = "general"
    evidence: list[dict[str, str]] = field(default_factory=list)
    recommendation: str = "Review related artifacts and validate with additional DFIR evidence."
    signal_groups: list[str] = field(default_factory=list)
    occurrence_count: int = 1
    process_key: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    disposition: str = "lead"
    suppressed_reason: str = ""
    provenance_ids: list[str] = field(default_factory=list)


@dataclass
class PluginStatus:
    plugin: str
    status: str
    return_code: int | None = None
    output_path: str = ""
    error_path: str = ""
    dump_files: list[str] = field(default_factory=list)
    resolved_plugin: str = ""
    reason: str = ""
    command: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    stdout_sha256: str = ""
    error_sha256: str = ""
    dump_hashes: dict[str, str] = field(default_factory=dict)
    lane: str = ""
    timeout_seconds: int = 0
    analysis_status: str = "unassessed"


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    pid: int | None
    process_name: str
    detail: str
    source: str
    process_key: str = ""


@dataclass
class ProcessProfile:
    pid: int
    ppid: int | None = None
    name: str = ""
    image_path: str = ""
    command_line: str = ""
    create_time: str = ""
    exit_time: str = ""
    parent_name: str = ""
    eprocess_offset: str = ""
    process_key: str = ""
    parent_process_key: str = ""
    identity_ambiguous: bool = False
    source_plugins: list[str] = field(default_factory=list)
    observed_in: list[str] = field(default_factory=list)
    dlls: list[dict[str, Any]] = field(default_factory=list)
    network_connections: list[NetworkArtifact] = field(default_factory=list)
    malfind_regions: list[MalfindArtifact] = field(default_factory=list)
    persistence_links: list[dict[str, Any]] = field(default_factory=list)
    artifact_context: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    iocs: list[IOC] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score_reasons: list[str] = field(default_factory=list)
    risk_score: int = 0
    severity: str = "Info"
