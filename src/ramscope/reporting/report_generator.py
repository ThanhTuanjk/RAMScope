from __future__ import annotations

from pathlib import Path
from typing import Any

from ramscope.models import Finding, IOC, MalfindArtifact, NetworkArtifact, PluginStatus, ProcessProfile, TargetInfo, TimelineEvent
from ramscope.reporting.reliable_report import write_reports
from ramscope.utils.json_utils import read_json


class ReportGenerator:
    """Render reports from already-normalized case data without rerunning analysis."""

    def generate(
        self,
        case_dir: Path,
        metadata: dict[str, object],
        profiles: list[ProcessProfile],
        findings: list[Finding],
        iocs: list[IOC],
        output_format: str,
        plugin_status: list[PluginStatus] | None = None,
        timeline: list[TimelineEvent] | None = None,
        *,
        target: TargetInfo | None = None,
        unresolved: list[dict[str, Any]] | None = None,
        enable_pdf: bool = True,
    ) -> list[Path]:
        del timeline  # Timeline is already persisted separately and is not recomputed here.
        return write_reports(
            case_dir,
            dict(metadata),
            profiles,
            findings,
            iocs,
            plugin_status or [],
            target or TargetInfo(),
            unresolved or [],
            output_format,
            enable_pdf,
        )

    def generate_from_case(self, case_dir: Path, output_format: str = "html", *, enable_pdf: bool = False) -> list[Path]:
        metadata = _mapping(_read_optional(case_dir / "evidence" / "evidence_metadata.json", {}))
        profiles = [_profile_from_dict(item) for item in _row_list(_read_optional(case_dir / "normalized" / "process_profiles.json", []))]
        findings_source = _read_optional(case_dir / "normalized" / "findings.json", None)
        if findings_source is None:
            risk = _mapping(_read_optional(case_dir / "normalized" / "risk_summary.json", {}))
            findings_source = risk.get("findings", [])
        findings = [_finding_from_dict(item) for item in _row_list(findings_source)]
        iocs = [_ioc_from_dict(item) for item in _row_list(_read_optional(case_dir / "iocs" / "iocs.json", []))]
        statuses = [_plugin_from_dict(item) for item in _row_list(_read_optional(case_dir / "normalized" / "plugin_status.json", []))]
        target = _target_from_dict(_mapping(_read_optional(case_dir / "normalized" / "target_info.json", {})))
        unresolved = _row_list(_read_optional(case_dir / "normalized" / "unresolved_artifacts.json", []))
        return self.generate(
            case_dir,
            metadata,
            profiles,
            findings,
            iocs,
            output_format,
            statuses,
            target=target,
            unresolved=unresolved,
            enable_pdf=enable_pdf,
        )


def _read_optional(path: Path, default: Any) -> Any:
    return read_json(path) if path.exists() else default


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _row_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _finding_from_dict(item: dict[str, Any]) -> Finding:
    return Finding(
        finding_id=str(item.get("finding_id", "")),
        pid=_optional_int(item.get("pid")),
        process_name=str(item.get("process_name", "")),
        title=str(item.get("title", "")),
        severity=str(item.get("severity", "Low")),
        score=int(item.get("score", 0)),
        confidence=str(item.get("confidence", "possible")),
        category=str(item.get("category", "general")),
        evidence=_row_list(item.get("evidence", [])),
        recommendation=str(item.get("recommendation", "Review related artifacts and validate with additional DFIR evidence.")),
        signal_groups=[str(value) for value in item.get("signal_groups", [])] if isinstance(item.get("signal_groups"), list) else [],
        occurrence_count=int(item.get("occurrence_count", 1)),
        process_key=str(item.get("process_key", "")),
        mitre_techniques=[str(value) for value in item.get("mitre_techniques", [])] if isinstance(item.get("mitre_techniques"), list) else [],
        disposition=str(item.get("disposition", "lead")),
        suppressed_reason=str(item.get("suppressed_reason", "")),
        provenance_ids=[str(value) for value in item.get("provenance_ids", [])] if isinstance(item.get("provenance_ids"), list) else [],
    )


def _ioc_from_dict(item: dict[str, Any]) -> IOC:
    return IOC(
        type=str(item.get("type", "")),
        value=str(item.get("value", "")),
        source=str(item.get("source", "")),
        process_name=str(item.get("process_name", "")),
        pid=_optional_int(item.get("pid")),
        confidence=str(item.get("confidence", "medium")),
        note=str(item.get("note", "")),
        process_key=str(item.get("process_key", "")),
        actionability=str(item.get("actionability", "candidate")),
        occurrence_count=int(item.get("occurrence_count", 1)),
    )


def _plugin_from_dict(item: dict[str, Any]) -> PluginStatus:
    return PluginStatus(
        plugin=str(item.get("plugin", "")),
        status=str(item.get("status", "unassessed")),
        return_code=_optional_int(item.get("return_code")),
        output_path=str(item.get("output_path", "")),
        error_path=str(item.get("error_path", "")),
        dump_files=[str(value) for value in item.get("dump_files", [])] if isinstance(item.get("dump_files"), list) else [],
        resolved_plugin=str(item.get("resolved_plugin", "")),
        reason=str(item.get("reason", "")),
        command=[str(value) for value in item.get("command", [])] if isinstance(item.get("command"), list) else [],
        started_at=str(item.get("started_at", "")),
        finished_at=str(item.get("finished_at", "")),
        duration_seconds=float(item.get("duration_seconds", 0.0)),
        stdout_sha256=str(item.get("stdout_sha256", "")),
        error_sha256=str(item.get("error_sha256", "")),
        dump_hashes={str(key): str(value) for key, value in _mapping(item.get("dump_hashes")).items()},
        lane=str(item.get("lane", "")),
        timeout_seconds=int(item.get("timeout_seconds", 0)),
        analysis_status=str(item.get("analysis_status", "unassessed")),
    )


def _target_from_dict(item: dict[str, Any]) -> TargetInfo:
    return TargetInfo(
        requested_profile=str(item.get("requested_profile", "auto")),
        selected_profile=str(item.get("selected_profile", "unknown")),
        family=str(item.get("family", "Windows")),
        build=str(item.get("build", "")),
        architecture=str(item.get("architecture", "")),
        kernel=str(item.get("kernel", "")),
        symbol_context=str(item.get("symbol_context", "")),
        status=str(item.get("status", "unassessed")),
        reason=str(item.get("reason", "")),
    )


def _timeline_from_dict(item: dict[str, Any]) -> TimelineEvent:
    return TimelineEvent(
        timestamp=str(item.get("timestamp", "")),
        event_type=str(item.get("event_type", "")),
        pid=_optional_int(item.get("pid")),
        process_name=str(item.get("process_name", "")),
        detail=str(item.get("detail", "")),
        source=str(item.get("source", "")),
        process_key=str(item.get("process_key", "")),
    )


def _profile_from_dict(item: dict[str, Any]) -> ProcessProfile:
    profile = ProcessProfile(pid=int(item.get("pid", 0)))
    scalar_fields = {
        "ppid",
        "name",
        "image_path",
        "command_line",
        "create_time",
        "exit_time",
        "parent_name",
        "eprocess_offset",
        "process_key",
        "parent_process_key",
        "identity_ambiguous",
        "source_plugins",
        "observed_in",
        "dlls",
        "persistence_links",
        "artifact_context",
        "score_reasons",
        "risk_score",
        "severity",
    }
    for key in scalar_fields:
        if key in item:
            setattr(profile, key, item[key])
    profile.network_connections = [
        NetworkArtifact(
            pid=_optional_int(entry.get("pid")),
            process_name=str(entry.get("process_name", "")),
            protocol=str(entry.get("protocol", "")),
            local_addr=str(entry.get("local_addr", "")),
            local_port=_optional_int(entry.get("local_port")),
            remote_addr=str(entry.get("remote_addr", "")),
            remote_port=_optional_int(entry.get("remote_port")),
            state=str(entry.get("state", "")),
            source_plugin=str(entry.get("source_plugin", "windows.netscan")),
            process_key=str(entry.get("process_key", "")),
        )
        for entry in _row_list(item.get("network_connections", []))
    ]
    profile.malfind_regions = [
        MalfindArtifact(
            pid=_optional_int(entry.get("pid")),
            process_name=str(entry.get("process_name", "")),
            vad_start=str(entry.get("vad_start", "")),
            vad_end=str(entry.get("vad_end", "")),
            protection=str(entry.get("protection", "")),
            tag=str(entry.get("tag", "")),
            has_pe_header=bool(entry.get("has_pe_header", False)),
            dump_file=str(entry.get("dump_file", "")),
            source_plugin=str(entry.get("source_plugin", "windows.malfind")),
            eprocess_offset=str(entry.get("eprocess_offset", "")),
            process_key=str(entry.get("process_key", "")),
        )
        for entry in _row_list(item.get("malfind_regions", []))
    ]
    profile.iocs = [_ioc_from_dict(entry) for entry in _row_list(item.get("iocs", []))]
    profile.findings = [_finding_from_dict(entry) for entry in _row_list(item.get("findings", []))]
    return profile


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
