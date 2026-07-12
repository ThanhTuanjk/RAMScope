from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import platform
import shutil
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import typer

from ramscope.analyzers.yara_scanner import prepare_yara_rule_pack
from ramscope.case.case_manager import CaseManager
from ramscope.case.evidence_hasher import hash_file
from ramscope.community_sources import COMMUNITY_SOURCES
from ramscope.config import enabled_plugins, load_config, plugin_args_for, plugin_dump_args_for
from ramscope.execution import lane, run_jobs, workers
from ramscope.models import Finding, PluginStatus, to_jsonable
from ramscope.reliable_pipeline import analyze_case, candidate_pids
from ramscope.reporting.reliable_report import VALID_FORMATS, write_reports
from ramscope.reporting.report_generator import ReportGenerator
from ramscope.utils.json_utils import read_json, write_json
from ramscope.volatility.command_builder import VolatilityCommandBuilder
from ramscope.volatility.plugin_plan import CORE_PLUGINS, DEEP_PLUGINS, EXTENDED_PLUGINS, FULL_DUMP_PLUGINS, FULL_PLUGINS, resolve_plugin
from ramscope.volatility.runner import VolatilityRunner


app = typer.Typer(help="RAMScope: defensive Windows memory-forensics triage above Volatility3.", no_args_is_help=True)


@app.command()
def doctor(config: Annotated[Path | None, typer.Option("--config")] = None) -> None:
    cfg = load_config(config)
    vol = cfg["volatility"]
    runner = VolatilityRunner(VolatilityCommandBuilder(str(vol["command"]), str(vol["renderer"]), bool(vol["quiet"])), int(vol["timeout_seconds"]))
    available = runner.available_plugins() if runner.is_available() else set()
    execution = cfg.get("execution", {})
    typer.echo(f"Python: {platform.python_version()}")
    typer.echo(f"Volatility available: {runner.is_available()}")
    typer.echo(f"Volatility version: {runner.version_text()}")
    typer.echo(f"Volatility plugins discovered: {len(available)}")
    typer.echo(f"yara-python installed: {bool(importlib.util.find_spec('yara'))}")
    typer.echo(f"Execution workers: {workers(execution.get('workers', 'auto'), execution)}")
    typer.echo("Target OS is identified from windows.info during analysis.")


@app.command()
def validate(input: Annotated[Path, typer.Option("--input", "-i")]) -> None:
    path = input.resolve()
    if not path.is_file():
        raise typer.BadParameter(f"Input memory image does not exist: {path}")
    hashes = hash_file(path)
    typer.echo(f"Input: {path}\nSize: {path.stat().st_size} bytes\nMD5: {hashes.md5}\nSHA256: {hashes.sha256}")


@app.command()
def plugins() -> None:
    for title, items in (("Core", CORE_PLUGINS), ("Extended", EXTENDED_PLUGINS), ("Deep", DEEP_PLUGINS), ("Full", FULL_PLUGINS), ("Full dump", FULL_DUMP_PLUGINS)):
        typer.echo(f"{title} plugins:")
        for item in items:
            typer.echo(f"  - {item}")


@app.command("rule-sources")
def rule_sources() -> None:
    for name, info in COMMUNITY_SOURCES.items():
        typer.echo(f"{name}: {info['url']}")


@app.command("rules-count")
def rules_count(rules: Annotated[Path | None, typer.Option("--rules")] = None) -> None:
    root = rules or _builtin_yara_rules_dir()
    files = _enumerate_rule_files([root])
    declarations = sum(path.read_text(encoding="utf-8", errors="ignore").count("rule ") for path in files if path.suffix.casefold() in {".yar", ".yara"})
    typer.echo(f"Rule files: {len(files)}\nRule declarations: {declarations}")


@app.command("fetch-rules")
def fetch_rules(source: Annotated[str, typer.Option("--source")], destination: Annotated[Path, typer.Option("--destination", "-d")]) -> None:
    if source not in COMMUNITY_SOURCES:
        raise typer.BadParameter(f"Unknown source: {source}")
    if not shutil.which("git"):
        raise typer.BadParameter("git is required to fetch community rule repositories.")
    info = COMMUNITY_SOURCES[source]
    destination = destination.resolve()
    command = ["git", "-C", str(destination), "pull", "--ff-only"] if (destination / ".git").is_dir() else ["git", "clone", "--depth", "1", info["url"], str(destination)]
    completed = subprocess.run(command, check=False)
    if completed.returncode:
        raise typer.Exit(completed.returncode)
    typer.echo(f"Fetched {source}: {destination}")


@app.command()
def analyze(
    input: Annotated[Path, typer.Option("--input", "-i")],
    case: Annotated[str, typer.Option("--case", "-c")],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("cases"),
    format: Annotated[str, typer.Option("--format")] = "html",
    config: Annotated[Path | None, typer.Option("--config")] = None,
    yara_rules: Annotated[Path | None, typer.Option("--yara-rules")] = None,
    no_yara: Annotated[bool, typer.Option("--no-yara")] = False,
    no_builtin_yara: Annotated[bool, typer.Option("--no-builtin-yara")] = False,
    deep: Annotated[bool, typer.Option("--deep")] = False,
    full: Annotated[bool, typer.Option("--full")] = False,
    dump_artifacts: Annotated[bool, typer.Option("--dump-artifacts")] = False,
    workers_option: Annotated[str | None, typer.Option("--workers", help="auto, 1, or 2")] = None,
    malfind_dumps: Annotated[str | None, typer.Option("--malfind-dumps", help="targeted, all, or none")] = None,
    malfind_pid: Annotated[list[int] | None, typer.Option("--malfind-pid", help="Force a PID into targeted malfind dumping.")] = None,
    target_profile: Annotated[str, typer.Option("--target-profile", help="auto, windows-10, or windows-11")] = "auto",
    resume: Annotated[bool, typer.Option("--resume")] = False,
    analyst: Annotated[str, typer.Option("--analyst")] = "",
    no_malfind_dump: Annotated[bool, typer.Option("--no-malfind-dump", help="Legacy alias for --malfind-dumps none.")] = False,
    no_floss: Annotated[bool, typer.Option("--no-floss")] = False,
    no_capa: Annotated[bool, typer.Option("--no-capa")] = False,
    no_clamav: Annotated[bool, typer.Option("--no-clamav")] = False,
    no_die: Annotated[bool, typer.Option("--no-die")] = False,
    no_pefile: Annotated[bool, typer.Option("--no-pefile")] = False,
) -> None:
    normalized_format = _validate_format(format)
    if target_profile not in {"auto", "windows-10", "windows-11"}:
        raise typer.BadParameter("--target-profile must be auto, windows-10, or windows-11")

    cfg = load_config(config)
    analysis_cfg = cfg.get("analysis", {})
    _validate_report_configuration(normalized_format, analysis_cfg)
    execution = cfg.get("execution", {})
    configured_dump_mode = str(execution.get("malfind", {}).get("dump_mode", "targeted"))
    selected_dump_mode = "none" if no_malfind_dump else (malfind_dumps or configured_dump_mode)
    if selected_dump_mode not in {"targeted", "all", "none"}:
        raise typer.BadParameter("--malfind-dumps must be targeted, all, or none")
    if workers_option is not None:
        if workers_option not in {"auto", "1", "2"}:
            raise typer.BadParameter("--workers must be auto, 1, or 2")
        execution["workers"] = workers_option

    external_tools = _external_tool_settings(cfg, no_floss, no_capa, no_clamav, no_die, no_pefile)
    vol = cfg["volatility"]
    builder = VolatilityCommandBuilder(str(vol["command"]), str(vol["renderer"]), bool(vol["quiet"]))
    runner = VolatilityRunner(builder, int(vol["timeout_seconds"]))
    include_dumps = dump_artifacts or bool(analysis_cfg.get("enable_full_artifact_dumps", False))
    profile = "full" if full else ("deep" if deep else "triage")
    planned = enabled_plugins(cfg, include_deep=deep, include_full=full, include_dump_artifacts=include_dumps)

    yara_enabled = bool(analysis_cfg.get("enable_yara", True)) and not no_yara
    requested_rule_roots = _rule_paths(yara_rules, not no_builtin_yara) if yara_enabled else []
    rule_inventory = _rule_inventory(requested_rule_roots)
    available = runner.available_plugins() if runner.is_available() else set()
    plugin_resolution = [{"requested": plugin, "resolved": resolve_plugin(plugin, available) or ""} for plugin in planned]
    tool_manifest = _collect_tool_manifest(builder.command, runner, external_tools)
    runtime_options: dict[str, Any] = {
        "profile": profile,
        "target_profile": target_profile,
        "format": normalized_format,
        "yara_enabled": yara_enabled,
        "no_builtin_yara": no_builtin_yara,
        "malfind_dumps": selected_dump_mode,
        "malfind_pid": list(malfind_pid or []),
        "workers": execution.get("workers"),
        "dump_artifacts": include_dumps,
        "external_tools": external_tools,
        "planned_plugins": planned,
        "plugin_resolution": plugin_resolution,
        "yara_rules": rule_inventory,
        "tool_manifest": tool_manifest,
    }
    config_hash = _config_hash(cfg, runtime_options)

    manager = CaseManager(output)
    try:
        case_dir, metadata = manager.create_case(case, input, builder.command, analyst, resume=resume, config_sha256=config_hash, analysis_profile=profile)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    snapshot_rules, yara_manifest = _snapshot_yara_rules(case_dir, requested_rule_roots, yara_enabled)
    compiled: Path | None = None
    if snapshot_rules:
        compiled, compile_status = prepare_yara_rule_pack(snapshot_rules, case_dir / "normalized" / "yara")
        yara_manifest["compile_status"] = compile_status
    write_json(case_dir / "evidence" / "analysis_config.json", cfg)
    write_json(case_dir / "evidence" / "runtime_options.json", runtime_options)
    write_json(case_dir / "evidence" / "tool_manifest.json", tool_manifest)
    write_json(case_dir / "evidence" / "yara_manifest.json", yara_manifest)
    write_json(case_dir / "evidence" / "plugin_resolution.json", plugin_resolution)

    statuses = _execute_plan(
        case_dir,
        input.resolve(),
        planned,
        runner,
        cfg,
        resume,
        workers(execution.get("workers", "auto"), execution),
        compiled,
        include_dumps,
    )
    write_json(case_dir / "normalized" / "plugin_status.json", statuses)
    result = analyze_case(case_dir, statuses, cfg, target_profile=target_profile, yara_rules=snapshot_rules, compiled_yara_path=compiled, external_tools=external_tools)
    write_json(case_dir / "normalized" / "plugin_status.json", statuses)

    if runner.is_available() and selected_dump_mode != "none" and "windows.malfind" in planned:
        targets = candidate_pids(result, int(execution.get("malfind", {}).get("max_targets", 12)), list(malfind_pid or []))
        if selected_dump_mode == "all":
            targets = []
        extra = _run_malfind_dumps(case_dir, input.resolve(), runner, cfg, targets, selected_dump_mode)
        if extra:
            statuses.extend(extra)
            write_json(case_dir / "normalized" / "plugin_status.json", statuses)
            result = analyze_case(case_dir, statuses, cfg, target_profile=target_profile, yara_rules=snapshot_rules, compiled_yara_path=compiled, external_tools=external_tools)
            write_json(case_dir / "normalized" / "plugin_status.json", statuses)

    metadata = manager.finish_case(case_dir, metadata)
    outputs = write_reports(case_dir, to_jsonable(metadata), result.profiles, result.findings, result.iocs, statuses, result.target, result.unresolved, normalized_format, bool(analysis_cfg.get("enable_pdf_report", False)))
    for path in outputs:
        typer.echo(path)


@app.command()
def reassess(
    case: Annotated[Path, typer.Option("--case")],
    format: Annotated[str, typer.Option("--format")] = "html",
    target_profile: Annotated[str | None, typer.Option("--target-profile")] = None,
) -> None:
    normalized_format = _validate_format(format)
    case_dir = case.resolve()
    statuses = [_status(item) for item in _row_list(_read(case_dir / "normalized" / "plugin_status.json", []))]
    metadata = _mapping(_read(case_dir / "evidence" / "evidence_metadata.json", {}))
    cfg = _mapping(_read(case_dir / "evidence" / "analysis_config.json", {}))
    runtime = _mapping(_read(case_dir / "evidence" / "runtime_options.json", {}))
    if not cfg or not runtime:
        raise typer.BadParameter("The case does not contain analysis_config.json and runtime_options.json required for reproducible reassessment.")
    _validate_report_configuration(normalized_format, _mapping(cfg.get("analysis", {})))
    selected_target = target_profile or str(runtime.get("target_profile", "auto"))
    if selected_target not in {"auto", "windows-10", "windows-11"}:
        raise typer.BadParameter("--target-profile must be auto, windows-10, or windows-11")
    try:
        integrity = _verify_case_artifacts(case_dir, statuses, metadata)
        yara_integrity = _verify_yara_manifest(case_dir, _read(case_dir / "evidence" / "yara_manifest.json", {}))
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"Reassessment integrity verification failed: {exc}") from exc

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination = case_dir / "reassessments" / stamp
    shutil.copytree(case_dir / "raw", destination / "raw")
    if (case_dir / "dumps").is_dir():
        shutil.copytree(case_dir / "dumps", destination / "dumps")
    (destination / "normalized").mkdir(parents=True, exist_ok=True)
    (destination / "iocs").mkdir(parents=True, exist_ok=True)
    (destination / "evidence").mkdir(parents=True, exist_ok=True)
    for name in ("evidence_metadata.json", "analysis_config.json", "runtime_options.json", "tool_manifest.json", "yara_manifest.json", "plugin_resolution.json"):
        source = case_dir / "evidence" / name
        if source.is_file():
            shutil.copy2(source, destination / "evidence" / name)
    if (case_dir / "evidence" / "yara_rules").is_dir():
        shutil.copytree(case_dir / "evidence" / "yara_rules", destination / "evidence" / "yara_rules")

    snapshot_rules = _manifest_rule_paths(destination, _read(destination / "evidence" / "yara_manifest.json", {}))
    compiled: Path | None = None
    if snapshot_rules and bool(_mapping(cfg.get("analysis", {})).get("enable_yara", True)):
        compiled, _ = prepare_yara_rule_pack(snapshot_rules, destination / "normalized" / "yara")
    external_tools = _mapping(runtime.get("external_tools", {}))
    current_tool_manifest = _collect_tool_manifest(str(_mapping(cfg.get("volatility", {})).get("command", "vol")), _runner_from_config(cfg), external_tools)
    result = analyze_case(destination, statuses, cfg, target_profile=selected_target, yara_rules=snapshot_rules, compiled_yara_path=compiled, external_tools=external_tools)
    write_json(destination / "normalized" / "plugin_status.json", statuses)
    outputs = write_reports(destination, metadata, result.profiles, result.findings, result.iocs, statuses, result.target, result.unresolved, normalized_format, bool(_mapping(cfg.get("analysis", {})).get("enable_pdf_report", False)))
    write_json(
        destination / "reassessment_manifest.json",
        {
            "source_case": str(case_dir),
            "created": stamp,
            "raw_outputs_reused": True,
            "dump_files_reused": (destination / "dumps").is_dir(),
            "integrity_verified": True,
            "original_runtime_options": runtime,
            "original_tool_manifest": _read(case_dir / "evidence" / "tool_manifest.json", {}),
            "current_tool_manifest": current_tool_manifest,
            **integrity,
            **yara_integrity,
        },
    )
    for path in outputs:
        typer.echo(path)


@app.command()
def report(case: Annotated[Path, typer.Option("--case")], format: Annotated[str, typer.Option("--format")] = "html") -> None:
    normalized_format = _validate_format(format)
    case_dir = case.resolve()
    cfg = _mapping(_read(case_dir / "evidence" / "analysis_config.json", {}))
    analysis_cfg = _mapping(cfg.get("analysis", {})) if cfg else {}
    _validate_report_configuration(normalized_format, analysis_cfg)
    try:
        outputs = ReportGenerator().generate_from_case(case_dir, normalized_format, enable_pdf=bool(analysis_cfg.get("enable_pdf_report", False)))
    except (OSError, TypeError, ValueError) as exc:
        raise typer.BadParameter(f"Could not render report from normalized case data: {exc}") from exc
    for path in outputs:
        typer.echo(path)


def _execute_plan(
    case_dir: Path,
    input_file: Path,
    planned: list[str],
    runner: VolatilityRunner,
    cfg: dict[str, Any],
    resume: bool,
    worker_count: int,
    compiled: Path | None,
    include_dumps: bool,
) -> list[PluginStatus]:
    previous = {item.plugin: item for item in [_status(row) for row in _row_list(_read(case_dir / "normalized" / "plugin_status.json", []))]} if resume else {}
    available = runner.available_plugins() if runner.is_available() else set()
    raw_dir = case_dir / "raw" / "volatility"
    timeouts = _mapping(_mapping(cfg.get("execution", {})).get("timeouts", {}))

    def one(plugin: str) -> PluginStatus:
        prior = previous.get(plugin)
        raw = raw_dir / f"{plugin}.json"
        if prior and prior.status in {"success", "cached"} and _cache_output_valid(prior, raw, case_dir):
            return replace(prior, status="cached", reason="Verified raw output reused.")
        resolved = resolve_plugin(plugin, available)
        if not resolved:
            return PluginStatus(plugin, "unsupported" if available else "skipped", reason="Volatility plugin unavailable.", lane=lane(plugin))
        args = _runtime_plugin_args(cfg, plugin, compiled)
        skip_reason = _plugin_skip_reason(plugin, args)
        if skip_reason:
            return PluginStatus(plugin, "skipped", resolved_plugin=resolved, reason=skip_reason, lane=lane(plugin))
        current_lane = lane(plugin)
        timeout = int(timeouts.get(plugin, timeouts.get("heavy" if current_lane == "heavy" else "standard", 600)))
        dump = include_dumps and plugin in {"windows.dumpfiles", "windows.dlllist", "windows.memmap"}
        run = runner.run_plugin(
            input_file,
            plugin,
            raw_dir,
            plugin_args=args,
            dump=dump,
            dump_args=plugin_dump_args_for(cfg, plugin) if dump else None,
            dump_dir=case_dir / "dumps" / plugin.replace("windows.", "").replace(".", "_"),
            resolved_plugin=resolved,
            timeout_seconds=timeout,
        )
        return PluginStatus(
            plugin=plugin,
            status="success" if run.succeeded else ("timeout" if run.timed_out else "failed"),
            return_code=run.return_code,
            output_path=str(run.output_path or ""),
            error_path=str(run.error_path or ""),
            dump_files=[str(path) for path in run.dump_files],
            resolved_plugin=resolved,
            reason="" if run.succeeded else "Inspect saved error output.",
            command=run.command,
            started_at=run.started_at,
            finished_at=run.finished_at,
            duration_seconds=run.duration_seconds,
            stdout_sha256=run.stdout_sha256,
            error_sha256=run.error_sha256,
            dump_hashes=run.dump_hashes,
            lane=current_lane,
            timeout_seconds=timeout,
        )

    if not runner.is_available():
        return [PluginStatus(plugin, "skipped", reason="Volatility command unavailable", lane=lane(plugin)) for plugin in planned]
    bootstrap = [plugin for plugin in planned if plugin == "windows.info"]
    remaining = [plugin for plugin in planned if plugin not in bootstrap]
    completed = [(plugin, one(plugin)) for plugin in bootstrap] + run_jobs(remaining, worker_count, one)
    return [status for _, status in completed]


def _run_malfind_dumps(case_dir: Path, input_file: Path, runner: VolatilityRunner, cfg: dict[str, Any], pids: list[int], mode: str) -> list[PluginStatus]:
    available = runner.available_plugins()
    resolved = resolve_plugin("windows.malfind", available)
    if not resolved:
        return []
    timeout = int(_mapping(_mapping(cfg.get("execution", {})).get("timeouts", {})).get("dump", 3600))
    raw = case_dir / "raw" / "volatility"
    dump_dir = case_dir / "dumps" / "suspicious_memory"
    statuses: list[PluginStatus] = []
    jobs = [("windows.malfind.dumpall", [])] if mode == "all" else [(f"windows.malfind.targeted.{pid}", ["--pid", str(pid)]) for pid in pids]
    for identifier, args in jobs:
        run = runner.run_plugin(input_file, "windows.malfind", raw, plugin_args=args, dump=True, dump_args=["--dump"], dump_dir=dump_dir, resolved_plugin=resolved, timeout_seconds=timeout, output_id=identifier)
        statuses.append(
            PluginStatus(
                plugin=identifier,
                status="success" if run.succeeded else ("timeout" if run.timed_out else "failed"),
                return_code=run.return_code,
                output_path=str(run.output_path or ""),
                error_path=str(run.error_path or ""),
                dump_files=[str(path) for path in run.dump_files],
                resolved_plugin=resolved,
                reason="" if run.succeeded else "Targeted malfind dump did not complete.",
                command=run.command,
                started_at=run.started_at,
                finished_at=run.finished_at,
                duration_seconds=run.duration_seconds,
                stdout_sha256=run.stdout_sha256,
                error_sha256=run.error_sha256,
                dump_hashes=run.dump_hashes,
                lane="heavy",
                timeout_seconds=timeout,
            )
        )
    return statuses


def _rule_paths(external: Path | None, include_builtin: bool) -> list[Path]:
    paths = [_builtin_yara_rules_dir()] if include_builtin else []
    if external is not None:
        paths.append(external.resolve())
    return paths


def _config_hash(cfg: dict[str, Any], runtime: dict[str, Any]) -> str:
    payload = json.dumps({"config": cfg, "runtime": runtime}, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256_path(path: Path) -> str:
    if not path.is_file():
        return ""
    return _sha256(path)


def _read(path: Path, default: Any) -> Any:
    return read_json(path) if path.exists() else default


def _status(row: dict[str, Any]) -> PluginStatus:
    return PluginStatus(
        plugin=str(row.get("plugin", "")),
        status=str(row.get("status", "unassessed")),
        return_code=_optional_int(row.get("return_code")),
        output_path=str(row.get("output_path", "")),
        error_path=str(row.get("error_path", "")),
        dump_files=[str(value) for value in row.get("dump_files", [])] if isinstance(row.get("dump_files"), list) else [],
        resolved_plugin=str(row.get("resolved_plugin", "")),
        reason=str(row.get("reason", "")),
        command=[str(value) for value in row.get("command", [])] if isinstance(row.get("command"), list) else [],
        started_at=str(row.get("started_at", "")),
        finished_at=str(row.get("finished_at", "")),
        duration_seconds=float(row.get("duration_seconds", 0.0)),
        stdout_sha256=str(row.get("stdout_sha256", "")),
        error_sha256=str(row.get("error_sha256", "")),
        dump_hashes={str(key): str(value) for key, value in _mapping(row.get("dump_hashes", {})).items()},
        lane=str(row.get("lane", "")),
        timeout_seconds=int(row.get("timeout_seconds", 0)),
        analysis_status=str(row.get("analysis_status", "unassessed")),
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _builtin_yara_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


def _config_sha256(config: dict[str, Any], runtime: dict[str, Any]) -> str:
    return _config_hash(config, runtime)


def _cache_output_valid(status: PluginStatus, raw_path: Path, case_dir: Path | None = None) -> bool:
    if not raw_path.is_file() or not status.stdout_sha256:
        return False
    if _sha256(raw_path) != status.stdout_sha256:
        return False
    if status.dump_files and not status.dump_hashes:
        return False
    for path, expected in status.dump_hashes.items():
        target = _case_dump_path(case_dir, Path(path)) if case_dir is not None else Path(path)
        if not expected or target is None or not target.is_file() or _sha256(target) != expected:
            return False
    return True


def _case_dump_path(case_dir: Path | None, recorded: Path) -> Path | None:
    if case_dir is None:
        return recorded
    root = (case_dir / "dumps").resolve()
    if recorded.is_file():
        try:
            resolved = recorded.resolve()
            if root == resolved or root in resolved.parents:
                return recorded
        except OSError:
            pass
    matches = [path for path in root.rglob(recorded.name) if path.is_file()] if root.is_dir() else []
    return matches[0] if len(matches) == 1 else None


def _verify_case_artifacts(case_dir: Path, statuses: list[PluginStatus], metadata: dict[str, Any]) -> dict[str, Any]:
    if not metadata.get("sha256") or not metadata.get("file_size_bytes"):
        raise ValueError("evidence metadata is missing its SHA256 or size")
    if not statuses:
        raise ValueError("plugin status ledger is missing or empty")
    evidence_path = Path(str(metadata.get("input_file", "")))
    evidence_verified = False
    if evidence_path.is_file():
        current = hash_file(evidence_path)
        if current.sha256 != str(metadata["sha256"]) or evidence_path.stat().st_size != int(metadata["file_size_bytes"]):
            raise ValueError("source evidence changed after case creation")
        evidence_verified = True
    raw_dir = case_dir / "raw" / "volatility"
    verified_raw = 0
    verified_dumps = 0
    for status in statuses:
        if status.status not in {"success", "cached"}:
            continue
        name = Path(status.output_path).name if status.output_path else f"{status.plugin}.json"
        raw_path = raw_dir / name
        if not _cache_output_valid(status, raw_path, case_dir):
            raise ValueError(f"hash mismatch or missing hash for {status.plugin}")
        verified_raw += 1
        verified_dumps += len(status.dump_hashes)
    return {"verified_raw_outputs": verified_raw, "verified_dump_files": verified_dumps, "source_evidence_verified": evidence_verified, "hash_algorithm": "sha256"}


def _runtime_plugin_args(cfg: dict[str, Any], plugin: str, yara_source: Path | list[Path] | None) -> list[str]:
    args = plugin_args_for(cfg, plugin)
    if plugin == "windows.vadyarascan" and not any(item.startswith("--yara-") for item in args):
        candidates = [yara_source] if isinstance(yara_source, Path) else list(yara_source or [])
        for candidate in candidates:
            if candidate.is_file() and candidate.suffix.casefold() == ".yarac":
                return args + ["--yara-compiled-file", str(candidate)]
            if candidate.is_file() and candidate.suffix.casefold() in {".yar", ".yara"}:
                return args + ["--yara-file", str(candidate)]
            if candidate.is_dir():
                rule = next(iter(_enumerate_rule_files([candidate])), None)
                if rule:
                    return args + ["--yara-file", str(rule)]
    return args


def _plugin_skip_reason(plugin: str, args: list[str]) -> str:
    if plugin == "windows.vadyarascan" and not any(item.startswith("--yara-") for item in args):
        return "windows.vadyarascan requires an enabled YARA source."
    return ""


def _should_capture_dump(plugin: str, no_malfind_dump: bool, include_dump_artifacts: bool) -> bool:
    if plugin == "windows.malfind":
        return not no_malfind_dump
    return include_dump_artifacts and plugin in {"windows.dumpfiles", "windows.dlllist", "windows.memmap"}


def _external_tool_settings(cfg: dict[str, Any], no_floss: bool, no_capa: bool, no_clamav: bool, no_die: bool, no_pefile: bool) -> dict[str, Any]:
    configured = _mapping(_mapping(cfg.get("analysis", {})).get("external_tools", {}))
    return {
        "enable_floss": bool(configured.get("enable_floss", True)) and not no_floss,
        "enable_capa": bool(configured.get("enable_capa", True)) and not no_capa,
        "enable_clamav": bool(configured.get("enable_clamav", True)) and not no_clamav,
        "enable_die": bool(configured.get("enable_die", True)) and not no_die,
        "enable_pefile": bool(configured.get("enable_pefile", True)) and not no_pefile,
        "capa_rules": str(configured.get("capa_rules", "")),
        "timeout_seconds": int(configured.get("timeout_seconds", 120)),
        "max_file_size_mb": int(configured.get("max_file_size_mb", 100)),
        "max_output_mb": int(configured.get("max_output_mb", 32)),
    }


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple[str, int | None, str, str], Finding] = {}
    for finding in findings:
        key = (finding.process_key, finding.pid, finding.category, finding.title)
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        existing.score = max(existing.score, finding.score)
        order = {"unverified": 0, "low": 1, "possible": 2, "likely": 3, "high": 4, "corroborated": 5}
        if order.get(finding.confidence, 0) > order.get(existing.confidence, 0):
            existing.confidence = finding.confidence
        existing.occurrence_count += finding.occurrence_count
        existing.evidence.extend(item for item in finding.evidence if item not in existing.evidence)
        existing.provenance_ids = sorted(set(existing.provenance_ids + finding.provenance_ids))
    return list(merged.values())


def _validate_format(value: str) -> str:
    normalized = value.casefold()
    if normalized not in VALID_FORMATS:
        # Keep the actionable message visible across Typer stderr behavior.
        typer.echo("--format must be md, markdown, html, pdf, or all")
        raise typer.Exit(code=2)
    return normalized


def _validate_report_configuration(output_format: str, analysis_cfg: dict[str, Any]) -> None:
    if output_format in {"html", "all"} and not bool(analysis_cfg.get("enable_html_report", True)):
        raise typer.BadParameter("HTML reporting is disabled by the effective configuration.")
    if output_format in {"pdf", "all"} and not bool(analysis_cfg.get("enable_pdf_report", False)):
        raise typer.BadParameter("PDF reporting is disabled by the effective configuration.")


def _enumerate_rule_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix.casefold() in {".yar", ".yara", ".yarac"}:
            files.append(path.resolve())
        elif path.is_dir():
            files.extend(candidate.resolve() for candidate in path.rglob("*") if candidate.is_file() and candidate.suffix.casefold() in {".yar", ".yara", ".yarac"})
    return sorted(dict.fromkeys(files))


def _rule_inventory(paths: list[Path]) -> list[dict[str, Any]]:
    return [{"path": str(path), "sha256": _sha256(path), "size": path.stat().st_size} for path in _enumerate_rule_files(paths)]


def _snapshot_yara_rules(case_dir: Path, paths: list[Path], enabled: bool) -> tuple[list[Path], dict[str, Any]]:
    manifest: dict[str, Any] = {"enabled": enabled, "files": [], "compile_status": {}}
    if not enabled:
        return [], manifest
    destination = case_dir / "evidence" / "yara_rules"
    destination.mkdir(parents=True, exist_ok=True)
    snapshots: list[Path] = []
    builtin_root = _builtin_yara_rules_dir().resolve()
    for source in _enumerate_rule_files(paths):
        digest = _sha256(source)
        target = destination / f"{digest[:12]}_{source.name}"
        shutil.copy2(source, target)
        snapshots.append(target)
        manifest["files"].append(
            {
                "original_path": str(source),
                "snapshot_path": str(target.relative_to(case_dir)),
                "sha256": digest,
                "size": source.stat().st_size,
                "built_in": builtin_root == source.parent or builtin_root in source.parents,
                "compiled": source.suffix.casefold() == ".yarac",
            }
        )
    return snapshots, manifest


def _manifest_rule_paths(case_dir: Path, manifest_value: Any) -> list[Path]:
    manifest = _mapping(manifest_value)
    files = manifest.get("files", [])
    result: list[Path] = []
    if isinstance(files, list):
        for row in files:
            if not isinstance(row, dict):
                continue
            path = case_dir / str(row.get("snapshot_path", ""))
            if path.is_file():
                result.append(path)
    return result


def _verify_yara_manifest(case_dir: Path, manifest_value: Any) -> dict[str, Any]:
    manifest = _mapping(manifest_value)
    if not bool(manifest.get("enabled", False)):
        return {"verified_yara_rules": 0, "yara_enabled": False}
    paths = _manifest_rule_paths(case_dir, manifest)
    expected_rows = [row for row in manifest.get("files", []) if isinstance(row, dict)] if isinstance(manifest.get("files"), list) else []
    if len(paths) != len(expected_rows):
        raise ValueError("one or more snapshotted YARA rules are missing")
    for path, row in zip(paths, expected_rows, strict=True):
        if _sha256(path) != str(row.get("sha256", "")):
            raise ValueError(f"YARA rule hash mismatch: {path.name}")
    return {"verified_yara_rules": len(paths), "yara_enabled": True}


def _collect_tool_manifest(volatility_command: str, runner: VolatilityRunner, external_settings: dict[str, Any]) -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    vol_path = shutil.which(volatility_command) or volatility_command
    tools.append(_tool_entry("volatility3", vol_path, runner.version_text(), runner.is_available(), True))
    optional = {
        "floss": ("floss", bool(external_settings.get("enable_floss", False))),
        "capa": ("capa", bool(external_settings.get("enable_capa", False))),
        "clamav": ("clamscan", bool(external_settings.get("enable_clamav", False))),
        "detect-it-easy": ("diec", bool(external_settings.get("enable_die", False))),
    }
    for name, (command, enabled) in optional.items():
        path = shutil.which(command) or ""
        tools.append(_tool_entry(name, path, _command_version(path) if path else "unavailable", bool(path), enabled))
    for package, enabled in (("pefile", bool(external_settings.get("enable_pefile", False))), ("yara-python", True)):
        try:
            version = importlib.metadata.version(package)
            available = True
        except importlib.metadata.PackageNotFoundError:
            version = "unavailable"
            available = False
        tools.append({"tool": package, "enabled": enabled, "available": available, "version": version, "binary_path": "", "sha256": ""})
    return {"captured_at": datetime.now(timezone.utc).isoformat(), "tools": tools}


def _tool_entry(name: str, path_value: str, version: str, available: bool, enabled: bool) -> dict[str, Any]:
    path = Path(path_value) if path_value else None
    return {
        "tool": name,
        "enabled": enabled,
        "available": available,
        "version": version,
        "binary_path": path_value,
        "sha256": _sha256(path) if path is not None and path.is_file() else "",
    }


def _command_version(path: str) -> str:
    try:
        completed = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return "version unavailable"
    value = (completed.stdout or completed.stderr or "").strip().splitlines()
    return value[0][:300] if value else f"return_code={completed.returncode}"


def _runner_from_config(cfg: dict[str, Any]) -> VolatilityRunner:
    vol = _mapping(cfg.get("volatility", {}))
    builder = VolatilityCommandBuilder(str(vol.get("command", "vol")), str(vol.get("renderer", "json")), bool(vol.get("quiet", True)))
    return VolatilityRunner(builder, int(vol.get("timeout_seconds", 600)))


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _row_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_and_analyze(
    case_dir: Path,
    dump_files: list[str],
    statuses: list[PluginStatus],
    *,
    external_tools: dict[str, Any] | None = None,
):
    """Compatibility wrapper for integrations that previously invoked normalization directly."""
    del dump_files
    return analyze_case(case_dir, statuses, load_config(), external_tools=external_tools or {})
