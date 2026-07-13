from __future__ import annotations

import re
import hashlib
import importlib.metadata
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ramscope.analyzers.external_tools import ExternalToolAnalyzer
from ramscope.analyzers.yara_scanner import YaraScanner
from ramscope.models import Finding, IOC, MalfindArtifact, NetworkArtifact, PluginStatus, ProcessProfile, TargetInfo, TimelineEvent
from ramscope.parsers.cmdline_parser import CmdlineParser
from ramscope.parsers.deep_parser import GenericDeepParser, LdrModulesParser, ProcessCrossViewParser, ProcessSignalParser, VadInfoParser
from ramscope.parsers.dll_parser import DllParser
from ramscope.parsers.full_parser import GenericFullParser, ScheduledTaskParser, TimelineParser
from ramscope.parsers.malfind_parser import MalfindParser
from ramscope.parsers.network_parser import NetworkParser
from ramscope.parsers.process_parser import ProcessParser
from ramscope.parsers.pstree_parser import PstreeParser
from ramscope.parsers.registry_parser import RegistryParser
from ramscope.parsers.service_parser import ServiceParser
from ramscope.utils.forensic import boolish, canonical_windows_path, is_absolute_windows_path, is_public_ip, is_security_or_jit_process, is_system_path, optional, text
from ramscope.utils.json_utils import write_json
from ramscope.scoring.rules import severity_for_score


SYSTEM_NAMES = {"smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe"}
DEFAULT_USER_WRITABLE = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\")
LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
URL = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![\w.-])", re.IGNORECASE)
MUTEX_TOKEN = re.compile(r"\b(?:global\\msse|remcos|asyncrat|cobalt(?:strike)?|njrat|sliver|meterpreter)\b", re.IGNORECASE)
NEGATIVE_SIGNAL_TOKENS = ("not found", "not detected", "clean", "unmodified", "no suspicious")


@dataclass
class AnalysisResult:
    profiles: list[ProcessProfile]
    findings: list[Finding]
    iocs: list[IOC]
    timeline: list[TimelineEvent]
    target: TargetInfo
    unresolved: list[dict[str, Any]]
    observed_artifacts: list[dict[str, Any]]


def analyze_case(
    case_dir: Path,
    plugin_status: list[PluginStatus],
    cfg: dict[str, Any],
    *,
    target_profile: str = "auto",
    yara_rules: list[Path] | None = None,
    compiled_yara_path: Path | None = None,
    external_tools: dict[str, Any] | None = None,
) -> AnalysisResult:
    raw_dir = case_dir / "raw" / "volatility"
    parsers: dict[str, tuple[str, Any]] = {
        "info": ("windows.info", GenericDeepParser("windows.info")),
        "processes": ("windows.pslist", ProcessParser()),
        "pstree": ("windows.pstree", PstreeParser()),
        "psscan": ("windows.psscan", ProcessCrossViewParser("windows.psscan")),
        "psxview": ("windows.psxview", ProcessCrossViewParser("windows.psxview")),
        "cmdline": ("windows.cmdline", CmdlineParser()),
        "dlls": ("windows.dlllist", DllParser()),
        "network": ("windows.netscan", NetworkParser()),
        "malfind": ("windows.malfind", MalfindParser()),
        "ldrmodules": ("windows.ldrmodules", LdrModulesParser()),
        "vadinfo": ("windows.vadinfo", VadInfoParser()),
        "pebmasquerade": ("windows.pebmasquerade", ProcessSignalParser("windows.pebmasquerade")),
        "suspicious_threads": ("windows.suspicious_threads", ProcessSignalParser("windows.suspicious_threads")),
        "hollowprocesses": ("windows.hollowprocesses", ProcessSignalParser("windows.hollowprocesses")),
        "processghosting": ("windows.processghosting", ProcessSignalParser("windows.processghosting")),
        "services": ("windows.svcscan", ServiceParser()),
        "registry_run": ("windows.registry.printkey_run", RegistryParser()),
        "registry_runonce": ("windows.registry.printkey_runonce", RegistryParser()),
        "registry_wow64_run": ("windows.registry.printkey_wow64_run", RegistryParser()),
        "registry_wow64_runonce": ("windows.registry.printkey_wow64_runonce", RegistryParser()),
        "scheduled_tasks": ("windows.registry.scheduled_tasks", ScheduledTaskParser()),
        "timeliner": ("timeliner", TimelineParser("timeliner")),
    }
    generic_plugins = (
        "windows.handles",
        "windows.threads",
        "windows.privs",
        "windows.envars",
        "windows.getsids",
        "windows.filescan",
        "windows.dumpfiles",
        "windows.mutantscan",
        "windows.modules",
        "windows.modscan",
        "windows.driverscan",
        "windows.drivermodule",
        "windows.driverirp",
        "windows.callbacks",
        "windows.ssdt",
        "windows.timers",
        "windows.devicetree",
        "windows.symlinkscan",
        "windows.unloadedmodules",
        "windows.svcdiff",
        "windows.etwpatch",
        "windows.unhooked_system_calls",
        "windows.skeleton_key_check",
        "windows.vadyarascan",
        "windows.iat",
        "windows.memmap",
        "windows.suspended_threads",
        "windows.registry.hivelist",
        "windows.registry.printkey",
    )
    for plugin in generic_plugins:
        key = plugin.replace("windows.", "").replace(".", "_")
        parsers.setdefault(key, (plugin, GenericFullParser(plugin)))

    statuses = {item.plugin: item for item in plugin_status}
    parser_warnings: list[dict[str, str]] = []
    semantic_plugins = {plugin for plugin, _ in parsers.values()} - set(generic_plugins)
    parsed: dict[str, list[Any]] = {}

    for name, (plugin, parser) in parsers.items():
        path = raw_dir / f"{plugin}.json"
        status = statuses.get(plugin)
        if status is not None and status.status not in {"success", "cached", "partial"}:
            parsed[name] = []
            status.analysis_status = "unassessed"
            write_json(case_dir / "normalized" / f"{name}.json", parsed[name])
            continue
        if status is not None and not path.is_file():
            parsed[name] = []
            status.status = "partial"
            status.analysis_status = "unassessed"
            status.reason = "Volatility reported completed collection but the raw output file is missing."
            write_json(case_dir / "normalized" / f"{name}.json", parsed[name])
            continue
        try:
            rows = parser.parse_file(path) if path.is_file() else []
            parsed[name] = [_sanitize(item) for item in rows]
            if status is not None:
                status.analysis_status = "analyzed" if plugin in semantic_plugins else "observed"
        except (OSError, RecursionError, TypeError, ValueError) as exc:
            parsed[name] = []
            message = f"{type(exc).__name__}: {exc}"
            parser_warnings.append({"artifact": name, "plugin": plugin, "warning": f"Could not parse output: {message}", "error": message})
            if status is not None:
                status.status = "partial"
                status.analysis_status = "unassessed"
                status.reason = f"Parser rejected output: {message}"
        write_json(case_dir / "normalized" / f"{name}.json", parsed[name])

    for status in plugin_status:
        if status.plugin.startswith("windows.malfind.targeted.") or status.plugin == "windows.malfind.dumpall":
            if status.status in {"success", "cached"}:
                status.analysis_status = "observed"
        elif status.analysis_status == "unassessed" and status.status in {"timeout", "failed", "unsupported", "skipped"}:
            status.analysis_status = "unassessed"

    observed = _generic_observations(parsed, parsers, semantic_plugins)
    write_json(case_dir / "normalized" / "parser_warnings.json", parser_warnings)
    write_json(
        case_dir / "normalized" / "analysis_coverage.json",
        [
            {
                "plugin": item.plugin,
                "collection_status": item.status,
                "analysis_status": item.analysis_status,
                "reason": item.reason,
            }
            for item in plugin_status
        ],
    )

    target = _target_info(parsed.get("info", []), target_profile)
    profiles, unresolved = _correlate(parsed)
    analysis_cfg = cfg.get("analysis", {}) if isinstance(cfg, dict) else {}
    baseline = analysis_cfg.get("baseline", {}) if isinstance(analysis_cfg, dict) else {}
    findings, process_observed = _derive_findings(profiles, baseline if isinstance(baseline, dict) else {})
    observed.extend(process_observed)
    findings.extend(_generic_findings(parsed, baseline if isinstance(baseline, dict) else {}))

    if bool(analysis_cfg.get("enable_yara", True)) and (yara_rules or compiled_yara_path):
        findings.extend(
            _scan_yara(
                case_dir,
                yara_rules or [],
                compiled_yara_path,
                profiles,
                int(analysis_cfg.get("yara_timeout_seconds", 60)),
            )
        )
    findings.extend(_scan_external_tools(case_dir, external_tools or {}, profiles))

    if bool(analysis_cfg.get("enable_risk_scoring", True)):
        _attach_and_score(profiles, findings, cfg)
    else:
        _attach_without_scoring(profiles, findings)

    iocs = _extract_iocs(profiles, baseline if isinstance(baseline, dict) else {}) if bool(analysis_cfg.get("enable_ioc_extraction", True)) else []
    timeline = _timeline(profiles, findings, parsed)
    _persist(case_dir, profiles, findings, iocs, timeline, target, unresolved, observed)
    return AnalysisResult(profiles, findings, iocs, timeline, target, unresolved, observed)


def candidate_pids(result: AnalysisResult, limit: int, forced: list[int] | None = None) -> list[int]:
    selected = list(forced or [])
    for profile in result.profiles:
        memory = any(item.category in {"memory", "thread"} and item.disposition != "observed" for item in profile.findings)
        strong_region = any(region.has_pe_header or "execute_readwrite" in text(region.protection).casefold() for region in profile.malfind_regions)
        if memory and (strong_region or not is_security_or_jit_process(profile.name)):
            selected.append(profile.pid)
    return list(dict.fromkeys(selected))[: max(0, limit)]


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return optional(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        for key in value.__dataclass_fields__:
            setattr(value, key, _sanitize(getattr(value, key)))
    return value


def _target_info(rows: list[dict[str, Any]], requested: str) -> TargetInfo:
    blob = " ".join(str(value) for row in rows for value in row.values() if value is not None)
    build_match = re.search(r"(?:build|version)[^0-9]{0,8}(\d{4,5})", blob, re.IGNORECASE) or re.search(r"\b(1\d{4}|2\d{4})\b", blob)
    build = build_match.group(1) if build_match else ""
    if requested != "auto":
        selected = requested
        reason = "Target profile was explicitly selected by the analyst."
    elif build and int(build) >= 22000:
        selected = "windows-11"
        reason = "Build number is in the Windows 11 range."
    elif build:
        selected = "windows-10"
        reason = "Build number is below the Windows 11 threshold."
    else:
        selected = "unknown"
        reason = "windows.info did not provide a recoverable build number."
    architecture = "x64" if re.search(r"(?:amd64|x64)", blob, re.IGNORECASE) else ("x86" if re.search(r"(?:x86|i386)", blob, re.IGNORECASE) else "")
    return TargetInfo(requested, selected, "Windows", build, architecture, "", "", "assessed" if selected != "unknown" else "unassessed", reason)


def _correlate(parsed: dict[str, list[Any]]) -> tuple[list[ProcessProfile], list[dict[str, Any]]]:
    profiles: dict[str, ProcessProfile] = {}
    by_pid: dict[int, list[ProcessProfile]] = {}
    unresolved: list[dict[str, Any]] = []

    def add_process(row: dict[str, Any], source: str) -> ProcessProfile | None:
        pid = row.get("pid")
        if pid is None:
            return None
        offset = text(row.get("eprocess_offset"))
        created = text(row.get("create_time"))
        stable = bool(offset or created)
        key = f"eprocess:{offset.casefold()}" if offset else (f"pid:{pid}|created:{created}" if created else f"ambiguous:{source}:{pid}:{len(profiles)}")
        profile = profiles.get(key)
        if profile is None:
            profile = ProcessProfile(pid=int(pid), process_key=key, eprocess_offset=offset, identity_ambiguous=not stable)
            profiles[key] = profile
            by_pid.setdefault(int(pid), []).append(profile)
        profile.name = text(row.get("name") or row.get("process_name")) or profile.name
        profile.ppid = row.get("ppid") if row.get("ppid") is not None else profile.ppid
        profile.create_time = text(row.get("create_time")) or profile.create_time
        profile.exit_time = text(row.get("exit_time")) or profile.exit_time
        path = text(row.get("image_path") or row.get("path"))
        profile.image_path = path or profile.image_path
        profile.observed_in.append(source)
        return profile

    for source in ("processes", "pstree", "psscan", "psxview"):
        for row in parsed.get(source, []):
            add_process(row, f"windows.{source}" if source != "processes" else "windows.pslist")

    def resolve(pid: int | None, name: str = "", offset: str = "") -> ProcessProfile | None:
        if offset:
            exact = profiles.get(f"eprocess:{offset.casefold()}")
            if exact is not None:
                return exact
        candidates = list(by_pid.get(int(pid), [])) if pid is not None else []
        named = [item for item in candidates if name and item.name.casefold() == name.casefold()]
        candidates = named or candidates
        candidates = [item for item in candidates if not item.identity_ambiguous]
        active = [item for item in candidates if not item.exit_time]
        candidates = active or candidates
        return candidates[0] if len(candidates) == 1 else None

    def attach(row: Any, kind: str) -> None:
        is_mapping = isinstance(row, dict)
        pid = row.get("pid") if is_mapping else getattr(row, "pid", None)
        name = text((row.get("process_name") or row.get("name")) if is_mapping else getattr(row, "process_name", ""))
        offset = text(row.get("eprocess_offset") if is_mapping else getattr(row, "eprocess_offset", ""))
        profile = resolve(pid, name, offset)
        if profile is None:
            unresolved.append({"artifact": kind, "pid": pid, "process_name": name, "reason": "No unique EPROCESS or PID/create-time identity was available."})
            return
        if isinstance(row, NetworkArtifact):
            row.process_key = profile.process_key
            profile.network_connections.append(row)
        elif isinstance(row, MalfindArtifact):
            row.process_key = profile.process_key
            profile.malfind_regions.append(row)
        elif kind == "cmdline" and isinstance(row, dict):
            profile.command_line = text(row.get("command_line"))
        elif kind == "dll" and isinstance(row, dict):
            profile.dlls.append(row)
        elif isinstance(row, dict):
            profile.artifact_context.setdefault(kind, []).append(row)

    for row in parsed.get("cmdline", []):
        attach(row, "cmdline")
    for row in parsed.get("dlls", []):
        attach(row, "dll")
    for row in parsed.get("network", []):
        attach(row, "network")
    for row in parsed.get("malfind", []):
        attach(row, "malfind")
    for kind in ("ldrmodules", "vadinfo", "pebmasquerade", "suspicious_threads", "hollowprocesses", "processghosting"):
        for row in parsed.get(kind, []):
            attach(row, kind)

    for profile in profiles.values():
        profile.observed_in = sorted(set(profile.observed_in))
    for profile in profiles.values():
        parents = [item for item in by_pid.get(profile.ppid or -1, []) if not item.identity_ambiguous and _parent_precedes(item, profile)]
        if len(parents) == 1:
            profile.parent_process_key = parents[0].process_key
            profile.parent_name = parents[0].name
        elif profile.ppid is not None:
            unresolved.append({"artifact": "process_parent", "pid": profile.pid, "process_name": profile.name, "reason": "Parent PID was absent, time-inconsistent, or identity-ambiguous; no parent relationship was asserted."})
    return sorted(profiles.values(), key=lambda item: (item.pid, item.create_time, item.process_key)), unresolved


def _parent_precedes(parent: ProcessProfile, child: ProcessProfile) -> bool:
    if not parent.create_time or not child.create_time:
        return True
    return parent.create_time <= child.create_time


def _generic_observations(parsed: dict[str, list[Any]], parsers: dict[str, tuple[str, Any]], semantic_plugins: set[str]) -> list[dict[str, Any]]:
    observed: list[dict[str, Any]] = []
    for name, (plugin, _) in parsers.items():
        if plugin in semantic_plugins or not parsed.get(name):
            continue
        observed.append({"type": "plugin_artifact", "plugin": plugin, "count": len(parsed[name]), "reason": "Collected and normalized for analyst review; row presence alone is not treated as malicious evidence."})
    return observed


def _global_finding(title: str, severity: str, score: int, category: str, group: str, detail: str, provenance: str = "") -> Finding:
    return Finding(
        "",
        None,
        "",
        title,
        severity,
        score,
        "possible",
        category,
        [{"source": "RAMScope correlation", "detail": detail[:1000]}],
        "Validate the raw artifact and obtain an independent signal before escalation.",
        [group],
        1,
        "",
        [],
        "lead",
        "",
        [provenance] if provenance else [],
    )


def _generic_findings(parsed: dict[str, list[Any]], baseline: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    writable = _user_writable_tokens(baseline)
    for name in ("registry_run", "registry_runonce", "registry_wow64_run", "registry_wow64_runonce"):
        for index, row in enumerate(parsed.get(name, [])):
            key = canonical_windows_path(row.get("key"))
            data = text(row.get("value_data"))
            exact_run = bool(re.search(r"(?:^|\\)currentversion\\run(?:once)?$", key))
            suspicious_data = any(token in canonical_windows_path(data) for token in writable) or bool(re.search(r"\b(?:rundll32|regsvr32|mshta|powershell|pwsh|wscript|cscript)\.exe\b", data, re.IGNORECASE))
            if exact_run and suspicious_data:
                findings.append(_global_finding("Run-key value points to a user-writable path or LOLBin", "Medium", 20, "persistence", "persistence", data, f"{name}:{index}"))
    for index, row in enumerate(parsed.get("services", [])):
        binary = text(row.get("binary"))
        if binary and any(token in canonical_windows_path(binary) for token in writable):
            findings.append(_global_finding("Service binary points to a user-writable location", "Medium", 20, "persistence", "persistence", binary, f"service:{index}"))
    for index, row in enumerate(parsed.get("scheduled_tasks", [])):
        command = " ".join(text(row.get(key)) for key in ("action", "arguments", "working_directory"))
        suspicious = any(token in canonical_windows_path(command) for token in writable) or bool(re.search(r"\b(?:powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32)(?:\.exe)?\b", command, re.IGNORECASE))
        if suspicious:
            findings.append(_global_finding("Scheduled task action uses a LOLBin or user-writable path", "Medium", 20, "persistence", "persistence", command, f"scheduled-task:{index}"))
    for index, row in enumerate(parsed.get("mutantscan", [])):
        detail = text(row.get("details"))
        if MUTEX_TOKEN.search(detail):
            findings.append(_global_finding("Known-tool mutex token requires validation", "Low", 10, "signature", "signature", detail, f"mutex:{index}"))
    for name in ("etwpatch", "unhooked_system_calls", "skeleton_key_check", "svcdiff"):
        rows = parsed.get(name, [])
        positive = [row for row in rows if not _is_negative_signal(text(row.get("details")))]
        if positive:
            findings.append(_global_finding(f"{parsers_label(name)} returned candidate artifacts", "Medium", 20, "evasion", "execution", f"{len(positive)} candidate row(s)", f"{name}:rows"))
    if parsed.get("vadyarascan"):
        findings.append(_global_finding("VAD YARA matches require process-level corroboration", "Low", 15, "signature", "signature", f"{len(parsed['vadyarascan'])} row(s)", "vadyarascan:rows"))
    return _dedupe_findings(findings)


def parsers_label(name: str) -> str:
    return name.replace("_", ".")


def _derive_findings(profiles: list[ProcessProfile], baseline: dict[str, Any]) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    observed: list[dict[str, Any]] = []
    writable = _user_writable_tokens(baseline)
    for profile in profiles:
        name = profile.name.casefold()
        if name in SYSTEM_NAMES and profile.image_path and is_absolute_windows_path(profile.image_path) and not is_system_path(profile.image_path):
            findings.append(_finding(profile, "System-like process has a verified non-system path", "Medium", 25, "process", "process", "lead", profile.image_path, f"process-path:{canonical_windows_path(profile.image_path)}"))
        elif name in SYSTEM_NAMES and profile.image_path:
            observed.append({"type": "system_path", "pid": profile.pid, "value": profile.image_path, "reason": "Path was unavailable, non-absolute, or a normal system path."})

        if profile.parent_name.casefold() in OFFICE and name in LOLBINS:
            findings.append(_finding(profile, "Office process spawned a script-capable child", "Medium", 25, "process", "execution", "lead", f"parent={profile.parent_name}; command={profile.command_line}", f"ancestry:{profile.parent_process_key}->{profile.process_key}"))
        if name in {"powershell.exe", "pwsh.exe"} and _suspicious_powershell(profile.command_line):
            findings.append(_finding(profile, "PowerShell command line contains encoded or dynamic execution indicators", "Medium", 25, "process", "execution", "lead", profile.command_line[:1000], f"cmdline:{profile.process_key}"))

        for dll in profile.dlls:
            path = text(dll.get("path"))
            if path and any(token in canonical_windows_path(path) for token in writable):
                findings.append(_finding(profile, "Module observed in a user-writable location", "Low", 10, "module", "module", "lead", path, f"module:{canonical_windows_path(path)}"))

        for region in profile.malfind_regions:
            protection = text(region.protection).casefold()
            if region.has_pe_header or "execute_readwrite" in protection:
                provenance = _vad_provenance(profile, region.vad_start, region.vad_end)
                findings.append(_finding(profile, "Malfind reported an executable memory indicator", "Medium", 35, "memory", "memory", "lead", f"{region.vad_start}-{region.vad_end} {region.protection}", provenance))

        for row in profile.artifact_context.get("vadinfo", []):
            protection = text(row.get("protection")).casefold()
            backing = optional(row.get("file_output"))
            private = boolish(row.get("private_memory"))
            rwx = "execute_readwrite" in protection
            if rwx and private is True and backing is None:
                severity = "Low" if is_security_or_jit_process(profile.name) else "Medium"
                provenance = _vad_provenance(profile, text(row.get("vad_start")), text(row.get("vad_end")))
                findings.append(_finding(profile, "Private RWX VAD without recovered backing file", severity, 20, "memory", "memory", "lead", f"{row.get('vad_start')}-{row.get('vad_end')}", provenance))
            elif "execute_writecopy" in protection:
                observed.append({"type": "vad", "pid": profile.pid, "value": protection, "reason": "EXECUTE_WRITECOPY is common for mapped images and is not an injection finding by itself."})

        for row in profile.artifact_context.get("ldrmodules", []):
            flags = [row.get("in_load"), row.get("in_init"), row.get("in_mem")]
            path = text(row.get("path"))
            if flags and all(flag is False for flag in flags) and (path or row.get("base")):
                findings.append(_finding(profile, "Loader-list discrepancy requires correlation", "Low", 10, "module", "module", "lead", path, f"ldr:{profile.process_key}:{text(row.get('base'))}:{canonical_windows_path(path)}"))

        for row in profile.artifact_context.get("pebmasquerade", []):
            raw = row.get("raw_fields", {}) if isinstance(row.get("raw_fields"), dict) else {}
            command_spoofed = boolish(row.get("peb_commandline_spoofed")) or boolish(raw.get("peb_commandline_spoofed"))
            path_spoofed = boolish(row.get("peb_imagefilepath_spoofed")) or boolish(raw.get("peb_imagefilepath_spoofed"))
            if command_spoofed is True or path_spoofed is True:
                findings.append(_finding(profile, "PEB spoofing flag requires validation", "Medium", 25, "process", "process", "lead", text(row.get("details"))[:500], f"peb:{profile.process_key}"))

        for row in profile.artifact_context.get("hollowprocesses", []):
            details = text(row.get("details") or row.get("notes"))
            if details and not _is_negative_signal(details):
                findings.append(_finding(profile, "Possible process hollowing candidate requires validation", "Medium", 25, "process", "execution", "lead", details[:500], f"hollow:{profile.process_key}:{text(row.get('address'))}"))

        for row in profile.artifact_context.get("processghosting", []):
            details = text(row.get("details") or row.get("notes"))
            deletion = boolish(row.get("delete_pending")) is True or boolish(row.get("delete_on_close")) is True
            file_context = bool(text(row.get("file_object")) or text(row.get("path")))
            if (deletion or file_context) and not _is_negative_signal(details):
                findings.append(_finding(profile, "Possible process ghosting candidate requires validation", "Medium", 25, "process", "execution", "lead", details[:500], f"ghost:{profile.process_key}:{text(row.get('address'))}:{text(row.get('file_object'))}"))

        for row in profile.artifact_context.get("suspicious_threads", []):
            details = text(row.get("details"))
            if "non-file backed" in details.casefold() or "private" in details.casefold():
                severity = "Low" if is_security_or_jit_process(profile.name) else "Medium"
                findings.append(_finding(profile, "Thread start in a non-file-backed region requires validation", severity, 25, "thread", "thread", "lead", details[:500], f"thread:{profile.process_key}:{text(row.get('address'))}"))

        has_memory_or_thread = any(item.process_key == profile.process_key and item.category in {"memory", "thread"} for item in findings)
        for conn in profile.network_connections:
            if is_public_ip(text(conn.remote_addr)) and has_memory_or_thread:
                findings.append(_finding(profile, "Public network endpoint correlated with memory lead", "Medium", 20, "network", "network", "lead", f"{conn.remote_addr}:{conn.remote_port}", f"network:{profile.process_key}:{conn.remote_addr}:{conn.remote_port}"))
    return findings, observed


def _finding(
    profile: ProcessProfile,
    title: str,
    severity: str,
    score: int,
    category: str,
    group: str,
    disposition: str,
    detail: str = "",
    provenance: str = "",
) -> Finding:
    return Finding(
        "",
        profile.pid,
        profile.name,
        title,
        severity,
        score,
        "possible",
        category,
        [{"source": "RAMScope correlation", "detail": detail or title}],
        "Review the raw Volatility artifact and obtain an independent corroborating signal before escalation.",
        [group],
        1,
        profile.process_key,
        [],
        disposition,
        "",
        [provenance] if provenance else [],
    )


def _scan_yara(case_dir: Path, rules: list[Path], compiled: Path | None, profiles: list[ProcessProfile], timeout: int) -> list[Finding]:
    scanner = YaraScanner(rules, compiled_path=compiled, timeout_seconds=timeout)
    findings = scanner.scan_directory(case_dir / "dumps" / "suspicious_memory")
    by_pid: dict[int, list[ProcessProfile]] = {}
    for profile in profiles:
        by_pid.setdefault(profile.pid, []).append(profile)
    for finding in findings:
        finding.severity, finding.score, finding.confidence, finding.disposition = "Low", 15, "unverified", "lead"
        finding.category = "signature"
        finding.signal_groups = ["signature"]
        detail = " ".join(item.get("detail", "") for item in finding.evidence)
        dump_hash = _extract_dump_hash(detail)
        finding.provenance_ids = [f"dump:{dump_hash}"] if dump_hash else []
        match = re.search(r"pid[._:= -]+(\d+)", detail, re.IGNORECASE)
        if match and len(by_pid.get(int(match.group(1)), [])) == 1:
            profile = by_pid[int(match.group(1))][0]
            finding.pid, finding.process_name, finding.process_key = profile.pid, profile.name, profile.process_key
            if is_security_or_jit_process(profile.name):
                finding.suppressed_reason = "Signature match belongs to a security/JIT-heavy process and needs stronger corroboration."
    write_json(case_dir / "normalized" / "yara" / "scan_status.json", scanner.last_status)
    return findings


def _scan_external_tools(case_dir: Path, settings: dict[str, Any], profiles: list[ProcessProfile]) -> list[Finding]:
    try:
        findings, status, _ = ExternalToolAnalyzer(**settings).analyze(case_dir / "dumps" / "suspicious_memory", case_dir / "normalized" / "external_tools")
    except Exception as exc:  # noqa: BLE001 - external tools must not stop forensic collection.
        write_json(case_dir / "normalized" / "external_tools" / "status.json", [{"tool": "external-tools", "status": "error", "detail": f"{type(exc).__name__}: {exc}"}])
        return []
    write_json(case_dir / "normalized" / "external_tool_status.json", status)
    by_pid: dict[int, list[ProcessProfile]] = {}
    for profile in profiles:
        by_pid.setdefault(profile.pid, []).append(profile)
    for finding in findings:
        finding.severity, finding.score, finding.confidence, finding.disposition = "Low", min(15, finding.score), "unverified", "lead"
        finding.category = "signature"
        finding.signal_groups = ["signature"]
        detail = " ".join(item.get("detail", "") for item in finding.evidence)
        dump_hash = _hash_from_external_detail(detail, status)
        finding.provenance_ids = [f"dump:{dump_hash}"] if dump_hash else []
        match = re.search(r"pid[._:= -]+(\d+)", detail, re.IGNORECASE)
        if match and len(by_pid.get(int(match.group(1)), [])) == 1:
            profile = by_pid[int(match.group(1))][0]
            finding.pid, finding.process_name, finding.process_key = profile.pid, profile.name, profile.process_key
            if is_security_or_jit_process(profile.name):
                finding.suppressed_reason = "External-tool signal belongs to a security/JIT-heavy process and needs stronger corroboration."
    return findings


def _attach_without_scoring(profiles: list[ProcessProfile], findings: list[Finding]) -> None:
    findings[:] = _dedupe_findings(findings)
    by_key = {profile.process_key: profile for profile in profiles}
    for profile in profiles:
        profile.findings = []
        profile.risk_score = 0
        profile.severity = "Info"
        profile.score_reasons = []
    for finding in findings:
        attached_profile = by_key.get(finding.process_key)
        if attached_profile is not None:
            attached_profile.findings.append(finding)


def _attach_and_score(profiles: list[ProcessProfile], findings: list[Finding], cfg: dict[str, Any] | None = None) -> None:
    findings[:] = _dedupe_findings(findings)
    by_key = {profile.process_key: profile for profile in profiles}
    for profile in profiles:
        profile.findings = []
    for finding in findings:
        attached_profile = by_key.get(finding.process_key)
        if attached_profile is not None:
            attached_profile.findings.append(finding)

    correlation_findings: list[Finding] = []
    for profile in profiles:
        active = [item for item in profile.findings if item.disposition == "lead" and not item.suppressed_reason]
        group_provenance: dict[str, set[str]] = {}
        for item in active:
            provenances = set(item.provenance_ids) or {f"finding:{item.category}:{item.title}"}
            for group in item.signal_groups:
                group_provenance.setdefault(group, set()).update(provenances)
        groups = set(group_provenance)
        independent = set().union(*group_provenance.values()) if group_provenance else set()
        has_strong = bool(groups.intersection({"memory", "signature", "thread", "kernel", "hook", "evasion", "lsass"}))
        severity = ""
        if len(groups) >= 3 and len(independent) >= 3 and has_strong and groups.intersection({"network", "persistence"}):
            severity = "Critical"
        elif len(groups) >= 2 and len(independent) >= 2 and has_strong:
            severity = "High"
        if severity:
            correlation = _finding(
                profile,
                "Multiple independent suspicious indicators require priority review",
                severity,
                30 if severity == "High" else 45,
                "correlation",
                "correlation",
                "corroborated",
                f"signal_groups={sorted(groups)}; independent_provenance={len(independent)}",
                f"correlation:{profile.process_key}:{'|'.join(sorted(independent))}",
            )
            correlation.confidence = "corroborated"
            correlation.signal_groups = sorted(groups)
            correlation.provenance_ids = sorted(independent)
            profile.findings.append(correlation)
            correlation_findings.append(correlation)

        category_totals: dict[str, int] = {}
        configured_caps = (cfg or {}).get("risk_category_caps", {})
        category_caps = {
            "memory": 40,
            "thread": 30,
            "signature": 25,
            "network": 20,
            "persistence": 25,
            "module": 20,
            "process": 25,
            "execution": 25,
            "correlation": 45,
            **{str(key): int(value) for key, value in configured_caps.items()},
        }
        weights = (cfg or {}).get("risk_weights", {})
        for item in profile.findings:
            if item.disposition == "observed" or item.suppressed_reason:
                continue
            weighted = round(item.score * float(weights.get(item.category, 1.0)))
            category_totals[item.category] = min(category_caps.get(item.category, 20), category_totals.get(item.category, 0) + weighted)
        profile.risk_score = min(int((cfg or {}).get("risk_total_score_cap", 100)), sum(category_totals.values()))
        profile.severity = severity_for_score(profile.risk_score) if profile.findings else "Info"
        profile.score_reasons = [f"{item.severity}: {item.title}" for item in profile.findings]
    findings.extend(correlation_findings)
    findings[:] = _dedupe_findings(findings)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[Any, ...], Finding] = {}
    for item in findings:
        evidence = tuple(sorted(text(entry.get("detail")) for entry in item.evidence))
        key = (item.process_key, item.pid, item.title, item.category, evidence)
        existing = unique.get(key)
        if existing is None:
            unique[key] = item
            continue
        existing.occurrence_count += item.occurrence_count
        existing.evidence.extend(entry for entry in item.evidence if entry not in existing.evidence)
        existing.signal_groups = sorted(set(existing.signal_groups + item.signal_groups))
        existing.provenance_ids = sorted(set(existing.provenance_ids + item.provenance_ids))
        existing.score = max(existing.score, item.score)
    return list(unique.values())


def _extract_iocs(profiles: list[ProcessProfile], baseline: dict[str, Any]) -> list[IOC]:
    result: dict[tuple[str, str], IOC] = {}
    benign_suffixes = tuple(str(item).casefold().lstrip(".") for item in baseline.get("benign_domain_suffixes", []) if str(item).strip())
    for profile in profiles:
        corroborated = any(item.disposition == "corroborated" for item in profile.findings)
        for conn in profile.network_connections:
            remote = text(conn.remote_addr)
            if is_public_ip(remote):
                _add_ioc(result, IOC("ip", remote, "network", profile.name, profile.pid, "medium" if corroborated else "low", "Public remote endpoint recovered from netscan.", profile.process_key, "actionable" if corroborated else "candidate"))
        for value in URL.findall(profile.command_line):
            _add_ioc(result, IOC("url", value.rstrip(".,;)]}"), "cmdline", profile.name, profile.pid, "medium", "URL recovered from command line.", profile.process_key, "candidate"))
        for value in DOMAIN.findall(profile.command_line):
            normalized = value.casefold().rstrip(".")
            if normalized in {"microsoft.net", "system.core", "system.xml"} or any(normalized == suffix or normalized.endswith("." + suffix) for suffix in benign_suffixes):
                continue
            _add_ioc(result, IOC("domain", normalized, "cmdline", profile.name, profile.pid, "low", "Domain-shaped value recovered from command line.", profile.process_key, "candidate"))
    return list(result.values())


def _add_ioc(items: dict[tuple[str, str], IOC], candidate: IOC) -> None:
    key = (candidate.type, candidate.value.casefold())
    if key in items:
        items[key].occurrence_count += 1
        if candidate.actionability == "actionable":
            items[key].actionability = "actionable"
        return
    items[key] = candidate


def _timeline(profiles: list[ProcessProfile], findings: list[Finding], parsed: dict[str, list[Any]] | None = None) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for profile in profiles:
        if profile.create_time:
            events.append(TimelineEvent(profile.create_time, "process_start", profile.pid, profile.name, profile.command_line or profile.image_path, "process correlation", profile.process_key))
        if profile.exit_time:
            events.append(TimelineEvent(profile.exit_time, "process_exit", profile.pid, profile.name, "Exit time recovered from process artifact.", "process correlation", profile.process_key))
        for conn in profile.network_connections:
            events.append(TimelineEvent("", "network", profile.pid, profile.name, f"{conn.protocol} {conn.remote_addr}:{conn.remote_port} {conn.state}", conn.source_plugin, profile.process_key))
    for row in (parsed or {}).get("timeliner", []):
        events.append(TimelineEvent(text(row.get("timestamp")), text(row.get("event_type")) or "timeliner", row.get("pid"), text(row.get("process_name")), text(row.get("description") or row.get("details")), "timeliner", text(row.get("process_key"))))
    for row in (parsed or {}).get("scheduled_tasks", []):
        timestamp = text(row.get("last_run_time") or row.get("next_run_time"))
        detail = " ".join(text(row.get(key)) for key in ("task_name", "action", "arguments") if text(row.get(key)))
        events.append(TimelineEvent(timestamp, "scheduled_task", row.get("pid"), text(row.get("process_name")), detail, "windows.registry.scheduled_tasks", text(row.get("process_key"))))
    for finding in findings:
        if finding.disposition != "observed":
            events.append(TimelineEvent("", "finding", finding.pid, finding.process_name, finding.title, finding.evidence[0].get("source", "RAMScope") if finding.evidence else "RAMScope", finding.process_key))
    return _dedupe_timeline(events)


def _dedupe_timeline(events: list[TimelineEvent]) -> list[TimelineEvent]:
    unique: dict[tuple[Any, ...], TimelineEvent] = {}
    for event in events:
        key = (event.timestamp, event.event_type, event.pid, event.process_name, event.detail, event.source)
        unique.setdefault(key, event)
    return sorted(unique.values(), key=lambda item: (not bool(item.timestamp), item.timestamp, item.event_type, item.pid or -1))


def _persist(case_dir: Path, profiles: list[ProcessProfile], findings: list[Finding], iocs: list[IOC], timeline: list[TimelineEvent], target: TargetInfo, unresolved: list[dict[str, Any]], observed: list[dict[str, Any]]) -> None:
    normalized = case_dir / "normalized"
    write_json(normalized / "process_profiles.json", profiles)
    write_json(normalized / "findings.json", findings)
    write_json(normalized / "risk_summary.json", {"findings": findings, "corroborated": sum(item.disposition == "corroborated" for item in findings), "leads": sum(item.disposition == "lead" for item in findings)})
    write_json(normalized / "timeline.json", timeline)
    write_json(normalized / "undated_events.json", [item for item in timeline if not item.timestamp])
    write_json(normalized / "target_info.json", target)
    write_json(normalized / "unresolved_artifacts.json", unresolved)
    write_json(normalized / "observed_artifacts.json", observed)
    write_json(case_dir / "iocs" / "iocs.json", iocs)
    write_json(case_dir / "iocs" / "candidate_iocs.json", [item for item in iocs if item.actionability == "candidate"])
    write_json(case_dir / "iocs" / "actionable_iocs.json", [item for item in iocs if item.actionability == "actionable"])
    _write_normalized_manifest(case_dir)


def _write_normalized_manifest(case_dir: Path) -> None:
    root = case_dir.resolve()
    entries: list[dict[str, str]] = []
    for path in sorted((root / "normalized").rglob("*")):
        if not path.is_file() or path.name == "normalized_manifest.json":
            continue
        entries.append({"path": str(path.relative_to(root)).replace("\\", "/"), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    try:
        version = importlib.metadata.version("ramscope")
    except importlib.metadata.PackageNotFoundError:
        version = "source"
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False, timeout=3).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        commit = "unknown"
    write_json(root / "normalized" / "normalized_manifest.json", {"schema_version": 1, "engine_version": version, "git_commit": commit, "files": entries})


def refresh_normalized_manifest(case_dir: Path) -> None:
    """Refresh the normalized ledger after the final plugin-status write."""
    _write_normalized_manifest(case_dir)


def _user_writable_tokens(baseline: dict[str, Any]) -> tuple[str, ...]:
    configured = baseline.get("user_writable_tokens", DEFAULT_USER_WRITABLE)
    values = configured if isinstance(configured, (list, tuple)) else DEFAULT_USER_WRITABLE
    return tuple(canonical_windows_path(value) if not str(value).startswith("\\") else str(value).casefold() for value in values)


def _suspicious_powershell(command: str) -> bool:
    lowered = command.casefold()
    return any(token in lowered for token in (" -enc", "-encodedcommand", "frombase64string", "invoke-expression", " iex", "iex "))


def _is_negative_signal(value: str) -> bool:
    lowered = value.casefold().strip()
    if not lowered:
        return True
    if lowered in {"false", "0", "none", "disabled", "n/a", "no"}:
        return True
    if any(token in lowered for token in NEGATIVE_SIGNAL_TOKENS):
        return True
    boolean_values = re.findall(r"(?:^|\s)[a-z0-9_.-]+=(true|false|yes|no|1|0)(?=\s|$)", lowered)
    return bool(boolean_values) and all(item in {"false", "no", "0"} for item in boolean_values)


def _vad_provenance(profile: ProcessProfile, start: str, end: str) -> str:
    return f"vad:{profile.process_key}:{start}:{end}"


def _extract_dump_hash(detail: str) -> str:
    match = re.search(r"dump_sha256=([a-f0-9]{64})", detail, re.IGNORECASE)
    return match.group(1).casefold() if match else ""


def _hash_from_external_detail(detail: str, status: list[dict[str, Any]]) -> str:
    name_match = re.search(r"(?:for|in)\s+([^;]+?)(?:;|$)", detail)
    if not name_match:
        return ""
    target_name = Path(name_match.group(1).strip()).name
    for row in status:
        file_value = text(row.get("file"))
        if file_value and Path(file_value).name == target_name:
            path = Path(file_value)
            if path.is_file():
                import hashlib

                digest = hashlib.sha256()
                with path.open("rb") as file_obj:
                    for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                        digest.update(chunk)
                return digest.hexdigest()
    return ""
