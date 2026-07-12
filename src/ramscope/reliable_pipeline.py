from __future__ import annotations

import re
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
            unresolved.append({"artifact": kind, "pid": pid, "process_name": name, "reason": "No unique EPROCESS or PID/create-time identiãÞ|¶‰žËkºwµçA™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}¹…µ”°™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}­•ä€ôÁÉ½™¥±”¹Á¥°ÁÉ½™¥±”¹¹…µ”°ÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•ä(€€€€€€€€€€€¥˜¥Í}Í•ÕÉ¥Ñå}½É}©¥Ñ}ÁÉ½•ÍÌ¡ÁÉ½™¥±”¹¹…µ”¤è(€€€€€€€€€€€€€€€™¥¹‘¥¹œ¹ÍÕÁÁÉ•ÍÍ•‘}É•…Í½¸€ô€‰M¥¹…ÑÕÉ”µ…Ñ ‰•±½¹ÌÑ¼„Í•ÕÉ¥Ñä½)%Pµ¡•…ÙäÁÉ½•ÍÌ…¹¹••‘ÌÍÑÉ½¹•È½ÉÉ½‰½É…Ñ¥½¸¸ˆ(€€€ÝÉ¥Ñ•}©Í½¸¡…Í•}‘¥È€¼€‰¹½Éµ…±¥é•ˆ€¼€‰å…É„ˆ€¼€‰Í…¹}ÍÑ…ÑÕÌ¹©Í½¸ˆ°Í…¹¹•È¹±…ÍÑ}ÍÑ…ÑÕÌ¤(€€€É•ÑÕÉ¸™¥¹‘¥¹Ì(()‘•˜}Í…¹}•áÑ•É¹…±}Ñ½½±Ì¡…Í•}‘¥ÈèA…Ñ °Í•ÑÑ¥¹Ìè‘¥ÑmÍÑÈ°¹åt°ÁÉ½™¥±•Ìè±¥ÍÑmAÉ½•ÍÍAÉ½™¥±•t¤€´ø±¥ÍÑm¥¹‘¥¹tè(€€€ÑÉäè(€€€€€€€™¥¹‘¥¹Ì°ÍÑ…ÑÕÌ°|€ôáÑ•É¹…±Q½½±¹…±åé•È ¨©Í•ÑÑ¥¹Ì¤¹…¹…±åé”¡…Í•}‘¥È€¼€‰‘ÕµÁÌˆ€¼€‰ÍÕÍÁ¥¥½ÕÍ}µ•µ½Éäˆ°…Í•}‘¥È€¼€‰¹½Éµ…±¥é•ˆ€¼€‰•áÑ•É¹…±}Ñ½½±Ìˆ¤(€€€•á•ÁÐá•ÁÑ¥½¸…Ì•áŒè€€Œ¹½Å„è	1ÀÀÄ€´•áÑ•É¹…°Ñ½½±ÌµÕÍÐ¹½ÐÍÑ½À™½É•¹Í¥Œ½±±•Ñ¥½¸¸(€€€€€€€ÝÉ¥Ñ•}©Í½¸¡…Í•}‘¥È€¼€‰¹½Éµ…±¥é•ˆ€¼€‰•áÑ•É¹…±}Ñ½½±Ìˆ€¼€‰ÍÑ…ÑÕÌ¹©Í½¸ˆ°mì‰Ñ½½°ˆè€‰•áÑ•É¹…°µÑ½½±Ìˆ°€‰ÍÑ…ÑÕÌˆè€‰•ÉÉ½Èˆ°€‰‘•Ñ…¥°ˆè˜‰íÑåÁ”¡•áŒ¤¹}}¹…µ•}}ôèí•áô‰õt¤(€€€€€€€É•ÑÕÉ¸mt(€€€ÝÉ¥Ñ•}©Í½¸¡…Í•}‘¥È€¼€‰¹½Éµ…±¥é•ˆ€¼€‰•áÑ•É¹…±}Ñ½½±}ÍÑ…ÑÕÌ¹©Í½¸ˆ°ÍÑ…ÑÕÌ¤(€€€‰å}Á¥è‘¥Ñm¥¹Ð°±¥ÍÑmAÉ½•ÍÍAÉ½™¥±•ut€ôíô(€€€™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Ìè(€€€€€€€‰å}Á¥¹Í•Ñ‘•™…Õ±Ð¡ÁÉ½™¥±”¹Á¥°mt¤¹…ÁÁ•¹¡ÁÉ½™¥±”¤(€€€™½È™¥¹‘¥¹œ¥¸™¥¹‘¥¹Ìè(€€€€€€€™¥¹‘¥¹œ¹Í•Ù•É¥Ñä°™¥¹‘¥¹œ¹Í½É”°™¥¹‘¥¹œ¹½¹™¥‘•¹”°™¥¹‘¥¹œ¹‘¥ÍÁ½Í¥Ñ¥½¸€ô€‰1½Üˆ°µ¥¸ ÄÔ°™¥¹‘¥¹œ¹Í½É”¤°€‰Õ¹Ù•É¥™¥•ˆ°€‰±•…ˆ(€€€€€€€™¥¹‘¥¹œ¹…Ñ•½Éä€ô€‰Í¥¹…ÑÕÉ”ˆ(€€€€€€€™¥¹‘¥¹œ¹Í¥¹…±}É½ÕÁÌ€ôl‰Í¥¹…ÑÕÉ”‰t(€€€€€€€‘•Ñ…¥°€ô€ˆ€ˆ¹©½¥¸¡¥Ñ•´¹•Ð ‰‘•Ñ…¥°ˆ°€ˆˆ¤™½È¥Ñ•´¥¸™¥¹‘¥¹œ¹•Ù¥‘•¹”¤(€€€€€€€‘ÕµÁ}¡…Í €ô}¡…Í¡}™É½µ}•áÑ•É¹…±}‘•Ñ…¥°¡‘•Ñ…¥°°ÍÑ…ÑÕÌ¤(€€€€€€€™¥¹‘¥¹œ¹ÁÉ½Ù•¹…¹•}¥‘Ì€ôm˜‰‘ÕµÀéí‘ÕµÁ}¡…Í¡ô‰t¥˜‘ÕµÁ}¡…Í •±Í”mt(€€€€€€€µ…Ñ €ôÉ”¹Í•…É ¡È‰Á¥‘l¹|èô€µt¬¡q¬¤ˆ°‘•Ñ…¥°°É”¹%9=IM¤(€€€€€€€¥˜µ…Ñ …¹±•¸¡‰å}Á¥¹•Ð¡¥¹Ð¡µ…Ñ ¹É½ÕÀ Ä¤¤°mt¤¤€ôô€Äè(€€€€€€€€€€€ÁÉ½™¥±”€ô‰å}Á¥‘m¥¹Ð¡µ…Ñ ¹É½ÕÀ Ä¤¥ulÁt(€€€€€€€€€€€™¥¹‘¥¹œ¹Á¥°™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}¹…µ”°™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}­•ä€ôÁÉ½™¥±”¹Á¥°ÁÉ½™¥±”¹¹…µ”°ÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•ä(€€€€€€€€€€€¥˜¥Í}Í•ÕÉ¥Ñå}½É}©¥Ñ}ÁÉ½•ÍÌ¡ÁÉ½™¥±”¹¹…µ”¤è(€€€€€€€€€€€€€€€™¥¹‘¥¹œ¹ÍÕÁÁÉ•ÍÍ•‘}É•…Í½¸€ô€‰áÑ•É¹…°µÑ½½°Í¥¹…°‰•±½¹ÌÑ¼„Í•ÕÉ¥Ñä½)%Pµ¡•…ÙäÁÉ½•ÍÌ…¹¹••‘ÌÍÑÉ½¹•È½ÉÉ½‰½É…Ñ¥½¸¸ˆ(€€€É•ÑÕÉ¸™¥¹‘¥¹Ì(()‘•˜}…ÑÑ…¡}Ý¥Ñ¡½ÕÑ}Í½É¥¹œ¡ÁÉ½™¥±•Ìè±¥ÍÑmAÉ½•ÍÍAÉ½™¥±•t°™¥¹‘¥¹Ìè±¥ÍÑm¥¹‘¥¹t¤€´ø9½¹”è(€€€™¥¹‘¥¹Ílét€ô}‘•‘ÕÁ•}™¥¹‘¥¹Ì¡™¥¹‘¥¹Ì¤(€€€‰å}­•ä€ôíÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•äèÁÉ½™¥±”™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Íô(€€€™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Ìè(€€€€€€€ÁÉ½™¥±”¹™¥¹‘¥¹Ì€ômt(€€€€€€€ÁÉ½™¥±”¹É¥Í­}Í½É”€ô€À(€€€€€€€ÁÉ½™¥±”¹Í•Ù•É¥Ñä€ô€‰%¹™¼ˆ(€€€€€€€ÁÉ½™¥±”¹Í½É•}É•…Í½¹Ì€ômt(€€€™½È™¥¹‘¥¹œ¥¸™¥¹‘¥¹Ìè(€€€€€€€…ÑÑ…¡•‘}ÁÉ½™¥±”€ô‰å}­•ä¹•Ð¡™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}­•ä¤(€€€€€€€¥˜…ÑÑ…¡•‘}ÁÉ½™¥±”¥Ì¹½Ð9½¹”è(€€€€€€€€€€€…ÑÑ…¡•‘}ÁÉ½™¥±”¹™¥¹‘¥¹Ì¹…ÁÁ•¹¡™¥¹‘¥¹œ¤(()‘•˜}…ÑÑ…¡}…¹‘}Í½É”¡ÁÉ½™¥±•Ìè±¥ÍÑmAÉ½•ÍÍAÉ½™¥±•t°™¥¹‘¥¹Ìè±¥ÍÑm¥¹‘¥¹t°™œè‘¥ÑmÍÑÈ°¹åtð9½¹”€ô9½¹”¤€´ø9½¹”è(€€€™¥¹‘¥¹Ílét€ô}‘•‘ÕÁ•}™¥¹‘¥¹Ì¡™¥¹‘¥¹Ì¤(€€€‰å}­•ä€ôíÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•äèÁÉ½™¥±”™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Íô(€€€™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Ìè(€€€€€€€ÁÉ½™¥±”¹™¥¹‘¥¹Ì€ômt(€€€™½È™¥¹‘¥¹œ¥¸™¥¹‘¥¹Ìè(€€€€€€€…ÑÑ…¡•‘}ÁÉ½™¥±”€ô‰å}­•ä¹•Ð¡™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}­•ä¤(€€€€€€€¥˜…ÑÑ…¡•‘}ÁÉ½™¥±”¥Ì¹½Ð9½¹”è(€€€€€€€€€€€…ÑÑ…¡•‘}ÁÉ½™¥±”¹™¥¹‘¥¹Ì¹…ÁÁ•¹¡™¥¹‘¥¹œ¤((€€€½ÉÉ•±…Ñ¥½¹}™¥¹‘¥¹Ìè±¥ÍÑm¥¹‘¥¹t€ômt(€€€™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Ìè(€€€€€€€…Ñ¥Ù”€ôm¥Ñ•´™½È¥Ñ•´¥¸ÁÉ½™¥±”¹™¥¹‘¥¹Ì¥˜¥Ñ•´¹‘¥ÍÁ½Í¥Ñ¥½¸€ôô€‰±•…ˆ…¹¹½Ð¥Ñ•´¹ÍÕÁÁÉ•ÍÍ•‘}É•…Í½¹t(€€€€€€€É½ÕÁ}ÁÉ½Ù•¹…¹”è‘¥ÑmÍÑÈ°Í•ÑmÍÑÉut€ôíô(€€€€€€€™½È¥Ñ•´¥¸…Ñ¥Ù”è(€€€€€€€€€€€ÁÉ½Ù•¹…¹•Ì€ôÍ•Ð¡¥Ñ•´¹ÁÉ½Ù•¹…¹•}¥‘Ì¤½Èí˜‰™¥¹‘¥¹œéí¥Ñ•´¹…Ñ•½Éåôéí¥Ñ•´¹Ñ¥Ñ±•ô‰ô(€€€€€€€€€€€™½ÈÉ½ÕÀ¥¸¥Ñ•´¹Í¥¹…±}É½ÕÁÌè(€€€€€€€€€€€€€€€É½ÕÁ}ÁÉ½Ù•¹…¹”¹Í•Ñ‘•™…Õ±Ð¡É½ÕÀ°Í•Ð ¤¤¹ÕÁ‘…Ñ”¡ÁÉ½Ù•¹…¹•Ì¤(€€€€€€€É½ÕÁÌ€ôÍ•Ð¡É½ÕÁ}ÁÉ½Ù•¹…¹”¤(€€€€€€€¥¹‘•Á•¹‘•¹Ð€ôÍ•Ð ¤¹Õ¹¥½¸ ©É½ÕÁ}ÁÉ½Ù•¹…¹”¹Ù…±Õ•Ì ¤¤¥˜É½ÕÁ}ÁÉ½Ù•¹…¹”•±Í”Í•Ð ¤(€€€€€€€¡…Í}ÍÑÉ½¹œ€ô‰½½°¡É½ÕÁÌ¹¥¹Ñ•ÉÍ•Ñ¥½¸¡ì‰µ•µ½Éäˆ°€‰Í¥¹…ÑÕÉ”ˆ°€‰Ñ¡É•…‰ô¤¤(€€€€€€€Í•Ù•É¥Ñä€ô€ˆˆ(€€€€€€€¥˜±•¸¡É½ÕÁÌ¤€øô€Ì…¹±•¸¡¥¹‘•Á•¹‘•¹Ð¤€øô€Ì…¹¡…Í}ÍÑÉ½¹œ…¹É½ÕÁÌ¹¥¹Ñ•ÉÍ•Ñ¥½¸¡ì‰¹•ÑÝ½É¬ˆ°€‰Á•ÉÍ¥ÍÑ•¹”‰ô¤è(€€€€€€€€€€€Í•Ù•É¥Ñä€ô€‰É¥Ñ¥…°ˆ(€€€€€€€•±¥˜±•¸¡É½ÕÁÌ¤€øô€È…¹±•¸¡¥¹‘•Á•¹‘•¹Ð¤€øô€È…¹¡…Í}ÍÑÉ½¹œè(€€€€€€€€€€€Í•Ù•É¥Ñä€ô€‰!¥ ˆ(€€€€€€€¥˜Í•Ù•É¥Ñäè(€€€€€€€€€€€½ÉÉ•±…Ñ¥½¸€ô}™¥¹‘¥¹œ (€€€€€€€€€€€€€€€ÁÉ½™¥±”°(€€€€€€€€€€€€€€€€‰5Õ±Ñ¥Á±”¥¹‘•Á•¹‘•¹ÐÍÕÍÁ¥¥½ÕÌ¥¹‘¥…Ñ½ÉÌÉ•ÅÕ¥É”ÁÉ¥½É¥ÑäÉ•Ù¥•Üˆ°(€€€€€€€€€€€€€€€Í•Ù•É¥Ñä°(€€€€€€€€€€€€€€€€ÌÀ¥˜Í•Ù•É¥Ñä€ôô€‰!¥ ˆ•±Í”€ÐÔ°(€€€€€€€€€€€€€€€€‰½ÉÉ•±…Ñ¥½¸ˆ°(€€€€€€€€€€€€€€€€‰½ÉÉ•±…Ñ¥½¸ˆ°(€€€€€€€€€€€€€€€€‰½ÉÉ½‰½É…Ñ•ˆ°(€€€€€€€€€€€€€€€˜‰Í¥¹…±}É½ÕÁÌõíÍ½ÉÑ•¡É½ÕÁÌ¥ôì¥¹‘•Á•¹‘•¹Ñ}ÁÉ½Ù•¹…¹”õí±•¸¡¥¹‘•Á•¹‘•¹Ð¥ôˆ°(€€€€€€€€€€€€€€€˜‰½ÉÉ•±…Ñ¥½¸éíÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•åôéìðœ¹©½¥¸¡Í½ÉÑ•¡¥¹‘•Á•¹‘•¹Ð¤¥ôˆ°(€€€€€€€€€€€€¤(€€€€€€€€€€€½ÉÉ•±…Ñ¥½¸¹½¹™¥‘•¹”€ô€‰½ÉÉ½‰½É…Ñ•ˆ(€€€€€€€€€€€½ÉÉ•±…Ñ¥½¸¹Í¥¹…±}É½ÕÁÌ€ôÍ½ÉÑ•¡É½ÕÁÌ¤(€€€€€€€€€€€½ÉÉ•±…Ñ¥½¸¹ÁÉ½Ù•¹…¹•}¥‘Ì€ôÍ½ÉÑ•¡¥¹‘•Á•¹‘•¹Ð¤(€€€€€€€€€€€ÁÉ½™¥±”¹™¥¹‘¥¹Ì¹…ÁÁ•¹¡½ÉÉ•±…Ñ¥½¸¤(€€€€€€€€€€€½ÉÉ•±…Ñ¥½¹}™¥¹‘¥¹Ì¹…ÁÁ•¹¡½ÉÉ•±…Ñ¥½¸¤((€€€€€€€…Ñ•½Éå}Ñ½Ñ…±Ìè‘¥ÑmÍÑÈ°¥¹Ñt€ôíô(€€€€€€€½¹™¥ÕÉ•‘}…ÁÌ€ô€¡™œ½Èíô¤¹•Ð ‰É¥Í­}…Ñ•½Éå}…ÁÌˆ°íô¤(€€€€€€€…Ñ•½Éå}…ÁÌ€ôì(€€€€€€€€€€€€‰µ•µ½Éäˆè€ÐÀ°(€€€€€€€€€€€€‰Ñ¡É•…ˆè€ÌÀ°(€€€€€€€€€€€€‰Í¥¹…ÑÕÉ”ˆè€ÈÔ°(€€€€€€€€€€€€‰¹•ÑÝ½É¬ˆè€ÈÀ°(€€€€€€€€€€€€‰Á•ÉÍ¥ÍÑ•¹”ˆè€ÈÔ°(€€€€€€€€€€€€‰µ½‘Õ±”ˆè€ÈÀ°(€€€€€€€€€€€€‰ÁÉ½•ÍÌˆè€ÈÔ°(€€€€€€€€€€€€‰•á•ÕÑ¥½¸ˆè€ÈÔ°(€€€€€€€€€€€€‰½ÉÉ•±…Ñ¥½¸ˆè€ÐÔ°(€€€€€€€€€€€€¨©íÍÑÈ¡­•ä¤è¥¹Ð¡Ù…±Õ”¤™½È­•ä°Ù…±Õ”¥¸½¹™¥ÕÉ•‘}…ÁÌ¹¥Ñ•µÌ ¥ô°(€€€€€€€ô(€€€€€€€Ý•¥¡ÑÌ€ô€¡™œ½Èíô¤¹•Ð ‰É¥Í­}Ý•¥¡ÑÌˆ°íô¤(€€€€€€€™½È¥Ñ•´¥¸ÁÉ½™¥±”¹™¥¹‘¥¹Ìè(€€€€€€€€€€€¥˜¥Ñ•´¹‘¥ÍÁ½Í¥Ñ¥½¸€ôô€‰½‰Í•ÉÙ•ˆ½È¥Ñ•´¹ÍÕÁÁÉ•ÍÍ•‘}É•…Í½¸è(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€Ý•¥¡Ñ•€ôÉ½Õ¹¡¥Ñ•´¹Í½É”€¨™±½…Ð¡Ý•¥¡ÑÌ¹•Ð¡¥Ñ•´¹…Ñ•½Éä°€Ä¸À¤¤¤(€€€€€€€€€€€…Ñ•½Éå}Ñ½Ñ…±Ím¥Ñ•´¹…Ñ•½Éåt€ôµ¥¸¡…Ñ•½Éå}…ÁÌ¹•Ð¡¥Ñ•´¹…Ñ•½Éä°€ÈÀ¤°…Ñ•½Éå}Ñ½Ñ…±Ì¹•Ð¡¥Ñ•´¹…Ñ•½Éä°€À¤€¬Ý•¥¡Ñ•¤(€€€€€€€ÁÉ½™¥±”¹É¥Í­}Í½É”€ôµ¥¸¡¥¹Ð ¡™œ½Èíô¤¹•Ð ‰É¥Í­}Ñ½Ñ…±}Í½É•}…Àˆ°€ÄÀÀ¤¤°ÍÕ´¡…Ñ•½Éå}Ñ½Ñ…±Ì¹Ù…±Õ•Ì ¤¤¤(€€€€€€€ÁÉ½™¥±”¹Í•Ù•É¥Ñä€ô€‰É¥Ñ¥…°ˆ¥˜…¹ä¡¥Ñ•´¹Í•Ù•É¥Ñä€ôô€‰É¥Ñ¥…°ˆ™½È¥Ñ•´¥¸ÁÉ½™¥±”¹™¥¹‘¥¹Ì¤•±Í”€ ‰!¥ ˆ¥˜…¹ä¡¥Ñ•´¹Í•Ù•É¥Ñä€ôô€‰!¥ ˆ™½È¥Ñ•´¥¸ÁÉ½™¥±”¹™¥¹‘¥¹Ì¤•±Í”€ ‰5•‘¥Õ´ˆ¥˜…¹ä¡¥Ñ•´¹Í•Ù•É¥Ñä€ôô€‰5•‘¥Õ´ˆ™½È¥Ñ•´¥¸ÁÉ½™¥±”¹™¥¹‘¥¹Ì¤•±Í”€ ‰1½Üˆ¥˜ÁÉ½™¥±”¹™¥¹‘¥¹Ì•±Í”€‰%¹™¼ˆ¤¤¤(€€€€€€€ÁÉ½™¥±”¹Í½É•}É•…Í½¹Ì€ôm˜‰í¥Ñ•´¹Í•Ù•É¥Ñåôèí¥Ñ•´¹Ñ¥Ñ±•ôˆ™½È¥Ñ•´¥¸ÁÉ½™¥±”¹™¥¹‘¥¹Ít(€€€™¥¹‘¥¹Ì¹•áÑ•¹¡½ÉÉ•±…Ñ¥½¹}™¥¹‘¥¹Ì¤(€€€™¥¹‘¥¹Ílét€ô}‘•‘ÕÁ•}™¥¹‘¥¹Ì¡™¥¹‘¥¹Ì¤(()‘•˜}‘•‘ÕÁ•}™¥¹‘¥¹Ì¡™¥¹‘¥¹Ìè±¥ÍÑm¥¹‘¥¹t¤€´ø±¥ÍÑm¥¹‘¥¹tè(€€€Õ¹¥ÅÕ”è‘¥ÑmÑÕÁ±•m¹ä°€¸¸¹t°¥¹‘¥¹t€ôíô(€€€™½È¥Ñ•´¥¸™¥¹‘¥¹Ìè(€€€€€€€•Ù¥‘•¹”€ôÑÕÁ±”¡Í½ÉÑ•¡Ñ•áÐ¡•¹ÑÉä¹•Ð ‰‘•Ñ…¥°ˆ¤¤™½È•¹ÑÉä¥¸¥Ñ•´¹•Ù¥‘•¹”¤¤(€€€€€€€­•ä€ô€¡¥Ñ•´¹ÁÉ½•ÍÍ}­•ä°¥Ñ•´¹Á¥°¥Ñ•´¹Ñ¥Ñ±”°¥Ñ•´¹…Ñ•½Éä°•Ù¥‘•¹”¤(€€€€€€€•á¥ÍÑ¥¹œ€ôÕ¹¥ÅÕ”¹•Ð¡­•ä¤(€€€€€€€¥˜•á¥ÍÑ¥¹œ¥Ì9½¹”è(€€€€€€€€€€€Õ¹¥ÅÕ•m­•åt€ô¥Ñ•´(€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€•á¥ÍÑ¥¹œ¹½ÕÉÉ•¹•}½Õ¹Ð€¬ô¥Ñ•´¹½ÕÉÉ•¹•}½Õ¹Ð(€€€€€€€•á¥ÍÑ¥¹œ¹•Ù¥‘•¹”¹•áÑ•¹¡•¹ÑÉä™½È•¹ÑÉä¥¸¥Ñ•´¹•Ù¥‘•¹”¥˜•¹ÑÉä¹½Ð¥¸•á¥ÍÑ¥¹œ¹•Ù¥‘•¹”¤(€€€€€€€•á¥ÍÑ¥¹œ¹Í¥¹…±}É½ÕÁÌ€ôÍ½ÉÑ•¡Í•Ð¡•á¥ÍÑ¥¹œ¹Í¥¹…±}É½ÕÁÌ€¬¥Ñ•´¹Í¥¹…±}É½ÕÁÌ¤¤(€€€€€€€•á¥ÍÑ¥¹œ¹ÁÉ½Ù•¹…¹•}¥‘Ì€ôÍ½ÉÑ•¡Í•Ð¡•á¥ÍÑ¥¹œ¹ÁÉ½Ù•¹…¹•}¥‘Ì€¬¥Ñ•´¹ÁÉ½Ù•¹…¹•}¥‘Ì¤¤(€€€€€€€•á¥ÍÑ¥¹œ¹Í½É”€ôµ…à¡•á¥ÍÑ¥¹œ¹Í½É”°¥Ñ•´¹Í½É”¤(€€€É•ÑÕÉ¸±¥ÍÐ¡Õ¹¥ÅÕ”¹Ù…±Õ•Ì ¤¤(()‘•˜}•áÑÉ…Ñ}¥½Ì¡ÁÉ½™¥±•Ìè±¥ÍÑmAÉ½•ÍÍAÉ½™¥±•t°‰…Í•±¥¹”è‘¥ÑmÍÑÈ°¹åt¤€´ø±¥ÍÑm%=tè(€€€É•ÍÕ±Ðè‘¥ÑmÑÕÁ±•mÍÑÈ°ÍÑÉt°%=t€ôíô(€€€‰•¹¥¹}ÍÕ™™¥á•Ì€ôÑÕÁ±”¡ÍÑÈ¡¥Ñ•´¤¹…Í•™½± ¤¹±ÍÑÉ¥À ˆ¸ˆ¤™½È¥Ñ•´¥¸‰…Í•±¥¹”¹•Ð ‰‰•¹¥¹}‘½µ…¥¹}ÍÕ™™¥á•Ìˆ°mt¤¥˜ÍÑÈ¡¥Ñ•´¤¹ÍÑÉ¥À ¤¤(€€€™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Ìè(€€€€€€€½ÉÉ½‰½É…Ñ•€ô…¹ä¡¥Ñ•´¹‘¥ÍÁ½Í¥Ñ¥½¸€ôô€‰½ÉÉ½‰½É…Ñ•ˆ™½È¥Ñ•´¥¸ÁÉ½™¥±”¹™¥¹‘¥¹Ì¤(€€€€€€€™½È½¹¸¥¸ÁÉ½™¥±”¹¹•ÑÝ½É­}½¹¹•Ñ¥½¹Ìè(€€€€€€€€€€€É•µ½Ñ”€ôÑ•áÐ¡½¹¸¹É•µ½Ñ•}…‘‘È¤(€€€€€€€€€€€¥˜¥Í}ÁÕ‰±¥}¥À¡É•µ½Ñ”¤è(€€€€€€€€€€€€€€€}…‘‘}¥½Œ¡É•ÍÕ±Ð°%= ‰¥Àˆ°É•µ½Ñ”°€‰¹•ÑÝ½É¬ˆ°ÁÉ½™¥±”¹¹…µ”°ÁÉ½™¥±”¹Á¥°€‰µ•‘¥Õ´ˆ¥˜½ÉÉ½‰½É…Ñ••±Í”€‰±½Üˆ°€‰AÕ‰±¥ŒÉ•µ½Ñ”•¹‘Á½¥¹ÐÉ•½Ù•É•™É½´¹•ÑÍ…¸¸ˆ°ÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•ä°€‰…Ñ¥½¹…‰±”ˆ¥˜½ÉÉ½‰½É…Ñ••±Í”€‰…¹‘¥‘…Ñ”ˆ¤¤(€€€€€€€™½ÈÙ…±Õ”¥¸UI0¹™¥¹‘…±°¡ÁÉ½™¥±”¹½µµ…¹‘}±¥¹”¤è(€€€€€€€€€€€}…‘‘}¥½Œ¡É•ÍÕ±Ð°%= ‰ÕÉ°ˆ°Ù…±Õ”¹ÉÍÑÉ¥À ˆ¸°ì¥uôˆ¤°€‰µ‘±¥¹”ˆ°ÁÉ½™¥±”¹¹…µ”°ÁÉ½™¥±”¹Á¥°€‰µ•‘¥Õ´ˆ°€‰UI0É•½Ù•É•™É½´½µµ…¹±¥¹”¸ˆ°ÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•ä°€‰…¹‘¥‘…Ñ”ˆ¤¤(€€€€€€€™½ÈÙ…±Õ”¥¸=5%8¹™¥¹‘…±°¡ÁÉ½™¥±”¹½µµ…¹‘}±¥¹”¤è(€€€€€€€€€€€¹½Éµ…±¥é•€ôÙ…±Õ”¹…Í•™½± ¤¹ÉÍÑÉ¥À ˆ¸ˆ¤(€€€€€€€€€€€¥˜¹½Éµ…±¥é•¥¸ì‰µ¥É½Í½™Ð¹¹•Ðˆ°€‰ÍåÍÑ•´¹½É”ˆ°€‰ÍåÍÑ•´¹áµ°‰ô½È…¹ä¡¹½Éµ…±¥é•€ôôÍÕ™™¥à½È¹½Éµ…±¥é•¹•¹‘ÍÝ¥Ñ  ˆ¸ˆ€¬ÍÕ™™¥à¤™½ÈÍÕ™™¥à¥¸‰•¹¥¹}ÍÕ™™¥á•Ì¤è(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€}…‘‘}¥½Œ¡É•ÍÕ±Ð°%= ‰‘½µ…¥¸ˆ°¹½Éµ…±¥é•°€‰µ‘±¥¹”ˆ°ÁÉ½™¥±”¹¹…µ”°ÁÉ½™¥±”¹Á¥°€‰±½Üˆ°€‰½µ…¥¸µÍ¡…Á•Ù…±Õ”É•½Ù•É•™É½´½µµ…¹±¥¹”¸ˆ°ÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•ä°€‰…¹‘¥‘…Ñ”ˆ¤¤(€€€É•ÑÕÉ¸±¥ÍÐ¡É•ÍÕ±Ð¹Ù…±Õ•Ì ¤¤(()‘•˜}…‘‘}¥½Œ¡¥Ñ•µÌè‘¥ÑmÑÕÁ±•mÍÑÈ°ÍÑÉt°%=t°…¹‘¥‘…Ñ”è%=¤€´ø9½¹”è(€€€­•ä€ô€¡…¹‘¥‘…Ñ”¹ÑåÁ”°…¹‘¥‘…Ñ”¹Ù…±Õ”¹…Í•™½± ¤¤(€€€¥˜­•ä¥¸¥Ñ•µÌè(€€€€€€€¥Ñ•µÍm­•åt¹½ÕÉÉ•¹•}½Õ¹Ð€¬ô€Ä(€€€€€€€¥˜…¹‘¥‘…Ñ”¹…Ñ¥½¹…‰¥±¥Ñä€ôô€‰…Ñ¥½¹…‰±”ˆè(€€€€€€€€€€€¥Ñ•µÍm­•åt¹…Ñ¥½¹…‰¥±¥Ñä€ô€‰…Ñ¥½¹…‰±”ˆ(€€€€€€€É•ÑÕÉ¸(€€€¥Ñ•µÍm­•åt€ô…¹‘¥‘…Ñ”(()‘•˜}Ñ¥µ•±¥¹”¡ÁÉ½™¥±•Ìè±¥ÍÑmAÉ½•ÍÍAÉ½™¥±•t°™¥¹‘¥¹Ìè±¥ÍÑm¥¹‘¥¹t°Á…ÉÍ•è‘¥ÑmÍÑÈ°±¥ÍÑm¹åutð9½¹”€ô9½¹”¤€´ø±¥ÍÑmQ¥µ•±¥¹•Ù•¹Ñtè(€€€•Ù•¹ÑÌè±¥ÍÑmQ¥µ•±¥¹•Ù•¹Ñt€ômt(€€€™½ÈÁÉ½™¥±”¥¸ÁÉ½™¥±•Ìè(€€€€€€€¥˜ÁÉ½™¥±”¹É•…Ñ•}Ñ¥µ”è(€€€€€€€€€€€•Ù•¹ÑÌ¹…ÁÁ•¹¡Q¥µ•±¥¹•Ù•¹Ð¡ÁÉ½™¥±”¹É•…Ñ•}Ñ¥µ”°€‰ÁÉ½•ÍÍ}ÍÑ…ÉÐˆ°ÁÉ½™¥±”¹Á¥°ÁÉ½™¥±”¹¹…µ”°ÁÉ½™¥±”¹½µµ…¹‘}±¥¹”½ÈÁÉ½™¥±”¹¥µ…•}Á…Ñ °€‰ÁÉ½•ÍÌ½ÉÉ•±…Ñ¥½¸ˆ°ÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•ä¤¤(€€€€€€€¥˜ÁÉ½™¥±”¹•á¥Ñ}Ñ¥µ”è(€€€€€€€€€€€•Ù•¹ÑÌ¹…ÁÁ•¹¡Q¥µ•±¥¹•Ù•¹Ð¡ÁÉ½™¥±”¹•á¥Ñ}Ñ¥µ”°€‰ÁÉ½•ÍÍ}•á¥Ðˆ°ÁÉ½™¥±”¹Á¥°ÁÉ½™¥±”¹¹…µ”°€‰á¥ÐÑ¥µ”É•½Ù•É•™É½´ÁÉ½•ÍÌ…ÉÑ¥™…Ð¸ˆ°€‰ÁÉ½•ÍÌ½ÉÉ•±…Ñ¥½¸ˆ°ÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•ä¤¤(€€€€€€€™½È½¹¸¥¸ÁÉ½™¥±”¹¹•ÑÝ½É­}½¹¹•Ñ¥½¹Ìè(€€€€€€€€€€€•Ù•¹ÑÌ¹…ÁÁ•¹¡Q¥µ•±¥¹•Ù•¹Ð ˆˆ°€‰¹•ÑÝ½É¬ˆ°ÁÉ½™¥±”¹Á¥°ÁÉ½™¥±”¹¹…µ”°˜‰í½¹¸¹ÁÉ½Ñ½½±ôí½¹¸¹É•µ½Ñ•}…‘‘Éôéí½¹¸¹É•µ½Ñ•}Á½ÉÑôí½¹¸¹ÍÑ…Ñ•ôˆ°½¹¸¹Í½ÕÉ•}Á±Õ¥¸°ÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•ä¤¤(€€€™½ÈÉ½Ü¥¸€¡Á…ÉÍ•½Èíô¤¹•Ð ‰Ñ¥µ•±¥¹•Èˆ°mt¤è(€€€€€€€•Ù•¹ÑÌ¹…ÁÁ•¹¡Q¥µ•±¥¹•Ù•¹Ð¡Ñ•áÐ¡É½Ü¹•Ð ‰Ñ¥µ•ÍÑ…µÀˆ¤¤°Ñ•áÐ¡É½Ü¹•Ð ‰•Ù•¹Ñ}ÑåÁ”ˆ¤¤½È€‰Ñ¥µ•±¥¹•Èˆ°É½Ü¹•Ð ‰Á¥ˆ¤°Ñ•áÐ¡É½Ü¹•Ð ‰ÁÉ½•ÍÍ}¹…µ”ˆ¤¤°Ñ•áÐ¡É½Ü¹•Ð ‰‘•ÍÉ¥ÁÑ¥½¸ˆ¤½ÈÉ½Ü¹•Ð ‰‘•Ñ…¥±Ìˆ¤¤°€‰Ñ¥µ•±¥¹•Èˆ°Ñ•áÐ¡É½Ü¹•Ð ‰ÁÉ½•ÍÍ}­•äˆ¤¤¤¤(€€€™½ÈÉ½Ü¥¸€¡Á…ÉÍ•½Èíô¤¹•Ð ‰Í¡•‘Õ±•‘}Ñ…Í­Ìˆ°mt¤è(€€€€€€€Ñ¥µ•ÍÑ…µÀ€ôÑ•áÐ¡É½Ü¹•Ð ‰±…ÍÑ}ÉÕ¹}Ñ¥µ”ˆ¤½ÈÉ½Ü¹•Ð ‰¹•áÑ}ÉÕ¹}Ñ¥µ”ˆ¤¤(€€€€€€€‘•Ñ…¥°€ô€ˆ€ˆ¹©½¥¸¡Ñ•áÐ¡É½Ü¹•Ð¡­•ä¤¤™½È­•ä¥¸€ ‰Ñ…Í­}¹…µ”ˆ°€‰…Ñ¥½¸ˆ°€‰…ÉÕµ•¹ÑÌˆ¤¥˜Ñ•áÐ¡É½Ü¹•Ð¡­•ä¤¤¤(€€€€€€€•Ù•¹ÑÌ¹…ÁÁ•¹¡Q¥µ•±¥¹•Ù•¹Ð¡Ñ¥µ•ÍÑ…µÀ°€‰Í¡•‘Õ±•‘}Ñ…Í¬ˆ°É½Ü¹•Ð ‰Á¥ˆ¤°Ñ•áÐ¡É½Ü¹•Ð ‰ÁÉ½•ÍÍ}¹…µ”ˆ¤¤°‘•Ñ…¥°°€‰Ý¥¹‘½ÝÌ¹É•¥ÍÑÉä¹Í¡•‘Õ±•‘}Ñ…Í­Ìˆ°Ñ•áÐ¡É½Ü¹•Ð ‰ÁÉ½•ÍÍ}­•äˆ¤¤¤¤(€€€™½È™¥¹‘¥¹œ¥¸™¥¹‘¥¹Ìè(€€€€€€€¥˜™¥¹‘¥¹œ¹‘¥ÍÁ½Í¥Ñ¥½¸€„ô€‰½‰Í•ÉÙ•ˆè(€€€€€€€€€€€•Ù•¹ÑÌ¹…ÁÁ•¹¡Q¥µ•±¥¹•Ù•¹Ð ˆˆ°€‰™¥¹‘¥¹œˆ°™¥¹‘¥¹œ¹Á¥°™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}¹…µ”°™¥¹‘¥¹œ¹Ñ¥Ñ±”°™¥¹‘¥¹œ¹•Ù¥‘•¹•lÁt¹•Ð ‰Í½ÕÉ”ˆ°€‰I5M½Á”ˆ¤¥˜™¥¹‘¥¹œ¹•Ù¥‘•¹”•±Í”€‰I5M½Á”ˆ°™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}­•ä¤¤(€€€É•ÑÕÉ¸}‘•‘ÕÁ•}Ñ¥µ•±¥¹”¡•Ù•¹ÑÌ¤(()‘•˜}‘•‘ÕÁ•}Ñ¥µ•±¥¹”¡•Ù•¹ÑÌè±¥ÍÑmQ¥µ•±¥¹•Ù•¹Ñt¤€´ø±¥ÍÑmQ¥µ•±¥¹•Ù•¹Ñtè(€€€Õ¹¥ÅÕ”è‘¥ÑmÑÕÁ±•m¹ä°€¸¸¹t°Q¥µ•±¥¹•Ù•¹Ñt€ôíô(€€€™½È•Ù•¹Ð¥¸•Ù•¹ÑÌè(€€€€€€€­•ä€ô€¡•Ù•¹Ð¹Ñ¥µ•ÍÑ…µÀ°•Ù•¹Ð¹•Ù•¹Ñ}ÑåÁ”°•Ù•¹Ð¹Á¥°•Ù•¹Ð¹ÁÉ½•ÍÍ}¹…µ”°•Ù•¹Ð¹‘•Ñ…¥°°•Ù•¹Ð¹Í½ÕÉ”¤(€€€€€€€Õ¹¥ÅÕ”¹Í•Ñ‘•™…Õ±Ð¡­•ä°•Ù•¹Ð¤(€€€É•ÑÕÉ¸Í½ÉÑ•¡Õ¹¥ÅÕ”¹Ù…±Õ•Ì ¤°­•äõ±…µ‰‘„¥Ñ•´è€¡¹½Ð‰½½°¡¥Ñ•´¹Ñ¥µ•ÍÑ…µÀ¤°¥Ñ•´¹Ñ¥µ•ÍÑ…µÀ°¥Ñ•´¹•Ù•¹Ñ}ÑåÁ”°¥Ñ•´¹Á¥½È€´Ä¤¤(()‘•˜}Á•ÉÍ¥ÍÐ¡…Í•}‘¥ÈèA…Ñ °ÁÉ½™¥±•Ìè±¥ÍÑmAÉ½•ÍÍAÉ½™¥±•t°™¥¹‘¥¹Ìè±¥ÍÑm¥¹‘¥¹t°¥½Ìè±¥ÍÑm%=t°Ñ¥µ•±¥¹”è±¥ÍÑmQ¥µ•±¥¹•Ù•¹Ñt°Ñ…É•ÐèQ…É•Ñ%¹™¼°Õ¹É•Í½±Ù•è±¥ÍÑm‘¥ÑmÍÑÈ°¹åut°½‰Í•ÉÙ•è±¥ÍÑm‘¥ÑmÍÑÈ°¹åut¤€´ø9½¹”è(€€€¹½Éµ…±¥é•€ô…Í•}‘¥È€¼€‰¹½Éµ…±¥é•ˆ(€€€ÝÉ¥Ñ•}©Í½¸¡¹½Éµ…±¥é•€¼€‰ÁÉ½•ÍÍ}ÁÉ½™¥±•Ì¹©Í½¸ˆ°ÁÉ½™¥±•Ì¤(€€€ÝÉ¥Ñ•}©Í½¸¡¹½Éµ…±¥é•€¼€‰™¥¹‘¥¹Ì¹©Í½¸ˆ°™¥¹‘¥¹Ì¤(€€€ÝÉ¥Ñ•}©Í½¸¡¹½Éµ…±¥é•€¼€‰É¥Í­}ÍÕµµ…Éä¹©Í½¸ˆ°ì‰™¥¹‘¥¹Ìˆè™¥¹‘¥¹Ì°€‰½ÉÉ½‰½É…Ñ•ˆèÍÕ´¡¥Ñ•´¹‘¥ÍÁ½Í¥Ñ¥½¸€ôô€‰½ÉÉ½‰½É…Ñ•ˆ™½È¥Ñ•´¥¸™¥¹‘¥¹Ì¤°€‰±•…‘ÌˆèÍÕ´¡¥Ñ•´¹‘¥ÍÁ½Í¥Ñ¥½¸€ôô€‰±•…ˆ™½È¥Ñ•´¥¸™¥¹‘¥¹Ì¥ô¤(€€€ÝÉ¥Ñ•}©Í½¸¡¹½Éµ…±¥é•€¼€‰Ñ¥µ•±¥¹”¹©Í½¸ˆ°Ñ¥µ•±¥¹”¤(€€€ÝÉ¥Ñ•}©Í½¸¡¹½Éµ…±¥é•€¼€‰Õ¹‘…Ñ•‘}•Ù•¹ÑÌ¹©Í½¸ˆ°m¥Ñ•´™½È¥Ñ•´¥¸Ñ¥µ•±¥¹”¥˜¹½Ð¥Ñ•´¹Ñ¥µ•ÍÑ…µÁt¤(€€€ÝÉ¥Ñ•}©Í½¸¡¹½Éµ…±¥é•€¼€‰Ñ…É•Ñ}¥¹™¼¹©Í½¸ˆ°Ñ…É•Ð¤(€€€ÝÉ¥Ñ•}©Í½¸¡¹½Éµ…±¥é•€¼€‰Õ¹É•Í½±Ù•‘}…ÉÑ¥™…ÑÌ¹©Í½¸ˆ°Õ¹É•Í½±Ù•¤(€€€ÝÉ¥Ñ•}©Í½¸¡¹½Éµ…±¥é•€¼€‰½‰Í•ÉÙ•‘}…ÉÑ¥™…ÑÌ¹©Í½¸ˆ°½‰Í•ÉÙ•¤(€€€ÝÉ¥Ñ•}©Í½¸¡…Í•}‘¥È€¼€‰¥½Ìˆ€¼€‰¥½Ì¹©Í½¸ˆ°¥½Ì¤(€€€ÝÉ¥Ñ•}©Í½¸¡…Í•}‘¥È€¼€‰¥½Ìˆ€¼€‰…¹‘¥‘…Ñ•}¥½Ì¹©Í½¸ˆ°m¥Ñ•´™½È¥Ñ•´¥¸¥½Ì¥˜¥Ñ•´¹…Ñ¥½¹…‰¥±¥Ñä€ôô€‰…¹‘¥‘…Ñ”‰t¤(€€€ÝÉ¥Ñ•}©Í½¸¡…Í•}‘¥È€¼€‰¥½Ìˆ€¼€‰…Ñ¥½¹…‰±•}¥½Ì¹©Í½¸ˆ°m¥Ñ•´™½È¥Ñ•´¥¸¥½Ì¥˜¥Ñ•´¹…Ñ¥½¹…‰¥±¥Ñä€ôô€‰…Ñ¥½¹…‰±”‰t¤(()‘•˜}ÕÍ•É}ÝÉ¥Ñ…‰±•}Ñ½­•¹Ì¡‰…Í•±¥¹”è‘¥ÑmÍÑÈ°¹åt¤€´øÑÕÁ±•mÍÑÈ°€¸¸¹tè(€€€½¹™¥ÕÉ•€ô‰…Í•±¥¹”¹•Ð ‰ÕÍ•É}ÝÉ¥Ñ…‰±•}Ñ½­•¹Ìˆ°U1Q}UMI}]I%Q	1¤(€€€Ù…±Õ•Ì€ô½¹™¥ÕÉ•¥˜¥Í¥¹ÍÑ…¹”¡½¹™¥ÕÉ•°€¡±¥ÍÐ°ÑÕÁ±”¤¤•±Í”U1Q}UMI}]I%Q	1(€€€É•ÑÕÉ¸ÑÕÁ±”¡…¹½¹¥…±}Ý¥¹‘½ÝÍ}Á…Ñ ¡Ù…±Õ”¤¥˜¹½ÐÍÑÈ¡Ù…±Õ”¤¹ÍÑ…ÉÑÍÝ¥Ñ  ‰qpˆ¤•±Í”ÍÑÈ¡Ù…±Õ”¤¹…Í•™½± ¤™½ÈÙ…±Õ”¥¸Ù…±Õ•Ì¤(()‘•˜}ÍÕÍÁ¥¥½ÕÍ}Á½Ý•ÉÍ¡•±°¡½µµ…¹èÍÑÈ¤€´ø‰½½°è(€€€±½Ý•É•€ô½µµ…¹¹…Í•™½± ¤(€€€É•ÑÕÉ¸…¹ä¡Ñ½­•¸¥¸±½Ý•É•™½ÈÑ½­•¸¥¸€ ˆ€µ•¹Œˆ°€ˆµ•¹½‘•‘½µµ…¹ˆ°€‰™É½µ‰…Í”ØÑÍÑÉ¥¹œˆ°€‰¥¹Ù½­”µ•áÁÉ•ÍÍ¥½¸ˆ°€ˆ¥•àˆ°€‰¥•à€ˆ¤¤(()‘•˜}¥Í}¹•…Ñ¥Ù•}Í¥¹…°¡Ù…±Õ”èÍÑÈ¤€´ø‰½½°è(€€€±½Ý•É•€ôÙ…±Õ”¹…Í•™½± ¤¹ÍÑÉ¥À ¤(€€€¥˜¹½Ð±½Ý•É•è(€€€€€€€É•ÑÕÉ¸QÉÕ”(€€€¥˜±½Ý•É•¥¸ì‰™…±Í”ˆ°€ˆÀˆ°€‰¹½¹”ˆ°€‰‘¥Í…‰±•ˆ°€‰¸½„ˆ°€‰¹¼‰ôè(€€€€€€€É•ÑÕÉ¸QÉÕ”(€€€¥˜…¹ä¡Ñ½­•¸¥¸±½Ý•É•™½ÈÑ½­•¸¥¸9Q%Y}M%91}Q=-9L¤è(€€€€€€€É•ÑÕÉ¸QÉÕ”(€€€‰½½±•…¹}Ù…±Õ•Ì€ôÉ”¹™¥¹‘…±°¡Èˆ üéyñqÌ¥m„µèÀ´å|¸µt¬ô¡ÑÉÕ•ñ™…±Í•ñå•Íñ¹½ðÅðÀ¤ üõqÍð¤ˆ°±½Ý•É•¤(€€€É•ÑÕÉ¸‰½½°¡‰½½±•…¹}Ù…±Õ•Ì¤…¹…±°¡¥Ñ•´¥¸ì‰™…±Í”ˆ°€‰¹¼ˆ°€ˆÀ‰ô™½È¥Ñ•´¥¸‰½½±•…¹}Ù…±Õ•Ì¤(()‘•˜}Ù…‘}ÁÉ½Ù•¹…¹”¡ÁÉ½™¥±”èAÉ½•ÍÍAÉ½™¥±”°ÍÑ…ÉÐèÍÑÈ°•¹èÍÑÈ¤€´øÍÑÈè(€€€É•ÑÕÉ¸˜‰Ù…éíÁÉ½™¥±”¹ÁÉ½•ÍÍ}­•åôéíÍÑ…ÉÑôéí•¹‘ôˆ(()‘•˜}•áÑÉ…Ñ}‘ÕµÁ}¡…Í ¡‘•Ñ…¥°èÍÑÈ¤€´øÍÑÈè(€€€µ…Ñ €ôÉ”¹Í•…É ¡È‰‘ÕµÁ}Í¡„ÈÔØô¡m„µ˜À´åuìØÑô¤ˆ°‘•Ñ…¥°°É”¹%9=IM¤(€€€É•ÑÕÉ¸µ…Ñ ¹É½ÕÀ Ä¤¹…Í•™½± ¤¥˜µ…Ñ •±Í”€ˆˆ(()‘•˜}¡…Í¡}™É½µ}•áÑ•É¹…±}‘•Ñ…¥°¡‘•Ñ…¥°èÍÑÈ°ÍÑ…ÑÕÌè±¥ÍÑm‘¥ÑmÍÑÈ°¹åut¤€´øÍÑÈè(€€€¹…µ•}µ…Ñ €ôÉ”¹Í•…É ¡Èˆ üé™½Éñ¥¸¥qÌ¬¡mxít¬ü¤ üèíð¤ˆ°‘•Ñ…¥°¤(€€€¥˜¹½Ð¹…µ•}µ…Ñ è(€€€€€€€É•ÑÕÉ¸€ˆˆ(€€€Ñ…É•Ñ}¹…µ”€ôA…Ñ ¡¹…µ•}µ…Ñ ¹É½ÕÀ Ä¤¹ÍÑÉ¥À ¤¤¹¹…µ”(€€€™½ÈÉ½Ü¥¸ÍÑ…ÑÕÌè(€€€€€€€™¥±•}Ù…±Õ”€ôÑ•áÐ¡É½Ü¹•Ð ‰™¥±”ˆ¤¤(€€€€€€€¥˜™¥±•}Ù…±Õ”…¹A…Ñ ¡™¥±•}Ù…±Õ”¤¹¹…µ”€ôôÑ…É•Ñ}¹…µ”è(€€€€€€€€€€€Á…Ñ €ôA…Ñ ¡™¥±•}Ù…±Õ”¤(€€€€€€€€€€€¥˜Á…Ñ ¹¥Í}™¥±” ¤è(€€€€€€€€€€€€€€€¥µÁ½ÉÐ¡…Í¡±¥ˆ((€€€€€€€€€€€€€€€‘¥•ÍÐ€ô¡…Í¡±¥ˆ¹Í¡„ÈÔØ ¤(€€€€€€€€€€€€€€€Ý¥Ñ Á…Ñ ¹½Á•¸ ‰Éˆˆ¤…Ì™¥±•}½‰¨è(€€€€€€€€€€€€€€€€€€€™½È¡Õ¹¬¥¸¥Ñ•È¡±…µ‰‘„è™¥±•}½‰¨¹É•… ÄÀÈÐ€¨€ÄÀÈÐ¤°ˆˆˆ¤è(€€€€€€€€€€€€€€€€€€€€€€€‘¥•ÍÐ¹ÕÁ‘…Ñ”¡¡Õ¹¬¤(€€€€€€€€€€€€€€€É•ÑÕÉ¸‘¥•ÍÐ¹¡•á‘¥•ÍÐ ¤(€€€É•ÑÕÉ¸€ˆˆ(