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
    outputs = write_reports(destination, metadata, result.profiles, rÛŽ}¶‰žËkºwµçEÑ ¤€´øÍÑÈè(€€€¥˜¹½ÐÁ…Ñ ¹¥Í}™¥±” ¤è(€€€€€€€É•ÑÕÉ¸€ˆˆ(€€€É•ÑÕÉ¸}Í¡„ÈÔØ¡Á…Ñ ¤(()‘•˜}É•…¡Á…Ñ èA…Ñ °‘•™…Õ±Ðè¹ä¤€´ø¹äè(€€€É•ÑÕÉ¸É•…‘}©Í½¸¡Á…Ñ ¤¥˜Á…Ñ ¹•á¥ÍÑÌ ¤•±Í”‘•™…Õ±Ð(()‘•˜}ÍÑ…ÑÕÌ¡É½Üè‘¥ÑmÍÑÈ°¹åt¤€´øA±Õ¥¹MÑ…ÑÕÌè(€€€É•ÑÕÉ¸A±Õ¥¹MÑ…ÑÕÌ (€€€€€€€Á±Õ¥¸õÍÑÈ¡É½Ü¹•Ð ‰Á±Õ¥¸ˆ°€ˆˆ¤¤°(€€€€€€€ÍÑ…ÑÕÌõÍÑÈ¡É½Ü¹•Ð ‰ÍÑ…ÑÕÌˆ°€‰Õ¹…ÍÍ•ÍÍ•ˆ¤¤°(€€€€€€€É•ÑÕÉ¹}½‘”õ}½ÁÑ¥½¹…±}¥¹Ð¡É½Ü¹•Ð ‰É•ÑÕÉ¹}½‘”ˆ¤¤°(€€€€€€€½ÕÑÁÕÑ}Á…Ñ õÍÑÈ¡É½Ü¹•Ð ‰½ÕÑÁÕÑ}Á…Ñ ˆ°€ˆˆ¤¤°(€€€€€€€•ÉÉ½É}Á…Ñ õÍÑÈ¡É½Ü¹•Ð ‰•ÉÉ½É}Á…Ñ ˆ°€ˆˆ¤¤°(€€€€€€€‘ÕµÁ}™¥±•ÌõmÍÑÈ¡Ù…±Õ”¤™½ÈÙ…±Õ”¥¸É½Ü¹•Ð ‰‘ÕµÁ}™¥±•Ìˆ°mt¥t¥˜¥Í¥¹ÍÑ…¹”¡É½Ü¹•Ð ‰‘ÕµÁ}™¥±•Ìˆ¤°±¥ÍÐ¤•±Í”mt°(€€€€€€€É•Í½±Ù•‘}Á±Õ¥¸õÍÑÈ¡É½Ü¹•Ð ‰É•Í½±Ù•‘}Á±Õ¥¸ˆ°€ˆˆ¤¤°(€€€€€€€É•…Í½¸õÍÑÈ¡É½Ü¹•Ð ‰É•…Í½¸ˆ°€ˆˆ¤¤°(€€€€€€€½µµ…¹õmÍÑÈ¡Ù…±Õ”¤™½ÈÙ…±Õ”¥¸É½Ü¹•Ð ‰½µµ…¹ˆ°mt¥t¥˜¥Í¥¹ÍÑ…¹”¡É½Ü¹•Ð ‰½µµ…¹ˆ¤°±¥ÍÐ¤•±Í”mt°(€€€€€€€ÍÑ…ÉÑ•‘}…ÐõÍÑÈ¡É½Ü¹•Ð ‰ÍÑ…ÉÑ•‘}…Ðˆ°€ˆˆ¤¤°(€€€€€€€™¥¹¥Í¡•‘}…ÐõÍÑÈ¡É½Ü¹•Ð ‰™¥¹¥Í¡•‘}…Ðˆ°€ˆˆ¤¤°(€€€€€€€‘ÕÉ…Ñ¥½¹}Í•½¹‘Ìõ™±½…Ð¡É½Ü¹•Ð ‰‘ÕÉ…Ñ¥½¹}Í•½¹‘Ìˆ°€À¸À¤¤°(€€€€€€€ÍÑ‘½ÕÑ}Í¡„ÈÔØõÍÑÈ¡É½Ü¹•Ð ‰ÍÑ‘½ÕÑ}Í¡„ÈÔØˆ°€ˆˆ¤¤°(€€€€€€€•ÉÉ½É}Í¡„ÈÔØõÍÑÈ¡É½Ü¹•Ð ‰•ÉÉ½É}Í¡„ÈÔØˆ°€ˆˆ¤¤°(€€€€€€€‘ÕµÁ}¡…Í¡•ÌõíÍÑÈ¡­•ä¤èÍÑÈ¡Ù…±Õ”¤™½È­•ä°Ù…±Õ”¥¸}µ…ÁÁ¥¹œ¡É½Ü¹•Ð ‰‘ÕµÁ}¡…Í¡•Ìˆ°íô¤¤¹¥Ñ•µÌ ¥ô°(€€€€€€€±…¹”õÍÑÈ¡É½Ü¹•Ð ‰±…¹”ˆ°€ˆˆ¤¤°(€€€€€€€Ñ¥µ•½ÕÑ}Í•½¹‘Ìõ¥¹Ð¡É½Ü¹•Ð ‰Ñ¥µ•½ÕÑ}Í•½¹‘Ìˆ°€À¤¤°(€€€€€€€…¹…±åÍ¥Í}ÍÑ…ÑÕÌõÍÑÈ¡É½Ü¹•Ð ‰…¹…±åÍ¥Í}ÍÑ…ÑÕÌˆ°€‰Õ¹…ÍÍ•ÍÍ•ˆ¤¤°(€€€€¤(()‘•˜}Í¡„ÈÔØ¡Á…Ñ èA…Ñ ¤€´øÍÑÈè(€€€‘¥•ÍÐ€ô¡…Í¡±¥ˆ¹Í¡„ÈÔØ ¤(€€€Ý¥Ñ Á…Ñ ¹½Á•¸ ‰Éˆˆ¤…Ì™¥±•}½‰¨è(€€€€€€€™½È¡Õ¹¬¥¸¥Ñ•È¡±…µ‰‘„è™¥±•}½‰¨¹É•… ÄÀÈÐ€¨€ÄÀÈÐ¤°ˆˆˆ¤è(€€€€€€€€€€€‘¥•ÍÐ¹ÕÁ‘…Ñ”¡¡Õ¹¬¤(€€€É•ÑÕÉ¸‘¥•ÍÐ¹¡•á‘¥•ÍÐ ¤(()‘•˜}‰Õ¥±Ñ¥¹}å…É…}ÉÕ±•Í}‘¥È ¤€´øA…Ñ è(€€€É•ÑÕÉ¸A…Ñ ¡}}™¥±•}|¤¹É•Í½±Ù” ¤¹Á…É•¹Ð€¼€‰ÉÕ±•Ìˆ(()‘•˜}½¹™¥}Í¡„ÈÔØ¡½¹™¥œè‘¥ÑmÍÑÈ°¹åt°ÉÕ¹Ñ¥µ”è‘¥ÑmÍÑÈ°¹åt¤€´øÍÑÈè(€€€É•ÑÕÉ¸}½¹™¥}¡…Í ¡½¹™¥œ°ÉÕ¹Ñ¥µ”¤(()‘•˜}…¡•}½ÕÑÁÕÑ}Ù…±¥¡ÍÑ…ÑÕÌèA±Õ¥¹MÑ…ÑÕÌ°É…Ý}Á…Ñ èA…Ñ °…Í•}‘¥ÈèA…Ñ ð9½¹”€ô9½¹”¤€´ø‰½½°è(€€€¥˜¹½ÐÉ…Ý}Á…Ñ ¹¥Í}™¥±” ¤½È¹½ÐÍÑ…ÑÕÌ¹ÍÑ‘½ÕÑ}Í¡„ÈÔØè(€€€€€€€É•ÑÕÉ¸…±Í”(€€€¥˜}Í¡„ÈÔØ¡É…Ý}Á…Ñ ¤€„ôÍÑ…ÑÕÌ¹ÍÑ‘½ÕÑ}Í¡„ÈÔØè(€€€€€€€É•ÑÕÉ¸…±Í”(€€€¥˜ÍÑ…ÑÕÌ¹‘ÕµÁ}™¥±•Ì…¹¹½ÐÍÑ…ÑÕÌ¹‘ÕµÁ}¡…Í¡•Ìè(€€€€€€€É•ÑÕÉ¸…±Í”(€€€™½ÈÁ…Ñ °•áÁ•Ñ•¥¸ÍÑ…ÑÕÌ¹‘ÕµÁ}¡…Í¡•Ì¹¥Ñ•µÌ ¤è(€€€€€€€Ñ…É•Ð€ô}…Í•}‘ÕµÁ}Á…Ñ ¡…Í•}‘¥È°A…Ñ ¡Á…Ñ ¤¤¥˜…Í•}‘¥È¥Ì¹½Ð9½¹”•±Í”A…Ñ ¡Á…Ñ ¤(€€€€€€€¥˜¹½Ð•áÁ•Ñ•½ÈÑ…É•Ð¥Ì9½¹”½È¹½ÐÑ…É•Ð¹¥Í}™¥±” ¤½È}Í¡„ÈÔØ¡Ñ…É•Ð¤€„ô•áÁ•Ñ•è(€€€€€€€€€€€É•ÑÕÉ¸…±Í”(€€€É•ÑÕÉ¸QÉÕ”(()‘•˜}…Í•}‘ÕµÁ}Á…Ñ ¡…Í•}‘¥ÈèA…Ñ ð9½¹”°É•½É‘•èA…Ñ ¤€´øA…Ñ ð9½¹”è(€€€¥˜…Í•}‘¥È¥Ì9½¹”è(€€€€€€€É•ÑÕÉ¸É•½É‘•(€€€É½½Ð€ô€¡…Í•}‘¥È€¼€‰‘ÕµÁÌˆ¤¹É•Í½±Ù” ¤(€€€¥˜É•½É‘•¹¥Í}™¥±” ¤è(€€€€€€€ÑÉäè(€€€€€€€€€€€É•Í½±Ù•€ôÉ•½É‘•¹É•Í½±Ù” ¤(€€€€€€€€€€€¥˜É½½Ð€ôôÉ•Í½±Ù•½ÈÉ½½Ð¥¸É•Í½±Ù•¹Á…É•¹ÑÌè(€€€€€€€€€€€€€€€É•ÑÕÉ¸É•½É‘•(€€€€€€€•á•ÁÐ=MÉÉ½Èè(€€€€€€€€€€€Á…ÍÌ(€€€µ…Ñ¡•Ì€ômÁ…Ñ ™½ÈÁ…Ñ ¥¸É½½Ð¹É±½ˆ¡É•½É‘•¹¹…µ”¤¥˜Á…Ñ ¹¥Í}™¥±” ¥t¥˜É½½Ð¹¥Í}‘¥È ¤•±Í”mt(€€€É•ÑÕÉ¸µ…Ñ¡•ÍlÁt¥˜±•¸¡µ…Ñ¡•Ì¤€ôô€Ä•±Í”9½¹”(()‘•˜}Ù•É¥™å}…Í•}…ÉÑ¥™…ÑÌ¡…Í•}‘¥ÈèA…Ñ °ÍÑ…ÑÕÍ•Ìè±¥ÍÑmA±Õ¥¹MÑ…ÑÕÍt°µ•Ñ…‘…Ñ„è‘¥ÑmÍÑÈ°¹åt¤€´ø‘¥ÑmÍÑÈ°¹åtè(€€€¥˜¹½Ðµ•Ñ…‘…Ñ„¹•Ð ‰Í¡„ÈÔØˆ¤½È¹½Ðµ•Ñ…‘…Ñ„¹•Ð ‰™¥±•}Í¥é•}‰åÑ•Ìˆ¤è(€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È ‰•Ù¥‘•¹”µ•Ñ…‘…Ñ„¥Ìµ¥ÍÍ¥¹œ¥ÑÌM!ÈÔØ½ÈÍ¥é”ˆ¤(€€€¥˜¹½ÐÍÑ…ÑÕÍ•Ìè(€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È ‰Á±Õ¥¸ÍÑ…ÑÕÌ±•‘•È¥Ìµ¥ÍÍ¥¹œ½È•µÁÑäˆ¤(€€€•Ù¥‘•¹•}Á…Ñ €ôA…Ñ ¡ÍÑÈ¡µ•Ñ…‘…Ñ„¹•Ð ‰¥¹ÁÕÑ}™¥±”ˆ°€ˆˆ¤¤¤(€€€•Ù¥‘•¹•}Ù•É¥™¥•€ô…±Í”(€€€¥˜•Ù¥‘•¹•}Á…Ñ ¹¥Í}™¥±” ¤è(€€€€€€€ÕÉÉ•¹Ð€ô¡…Í¡}™¥±”¡•Ù¥‘•¹•}Á…Ñ ¤(€€€€€€€¥˜ÕÉÉ•¹Ð¹Í¡„ÈÔØ€„ôÍÑÈ¡µ•Ñ…‘…Ñ…l‰Í¡„ÈÔØ‰t¤½È•Ù¥‘•¹•}Á…Ñ ¹ÍÑ…Ð ¤¹ÍÑ}Í¥é”€„ô¥¹Ð¡µ•Ñ…‘…Ñ…l‰™¥±•}Í¥é•}‰åÑ•Ì‰t¤è(€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È ‰Í½ÕÉ”•Ù¥‘•¹”¡…¹•…™Ñ•È…Í”É•…Ñ¥½¸ˆ¤(€€€€€€€•Ù¥‘•¹•}Ù•É¥™¥•€ôQÉÕ”(€€€É…Ý}‘¥È€ô…Í•}‘¥È€¼€‰É…Üˆ€¼€‰Ù½±…Ñ¥±¥Ñäˆ(€€€Ù•É¥™¥•‘}É…Ü€ô€À(€€€Ù•É¥™¥•‘}‘ÕµÁÌ€ô€À(€€€™½ÈÍÑ…ÑÕÌ¥¸ÍÑ…ÑÕÍ•Ìè(€€€€€€€¥˜ÍÑ…ÑÕÌ¹ÍÑ…ÑÕÌ¹½Ð¥¸ì‰ÍÕ•ÍÌˆ°€‰…¡•‰ôè(€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€¹…µ”€ôA…Ñ ¡ÍÑ…ÑÕÌ¹½ÕÑÁÕÑ}Á…Ñ ¤¹¹…µ”¥˜ÍÑ…ÑÕÌ¹½ÕÑÁÕÑ}Á…Ñ •±Í”˜‰íÍÑ…ÑÕÌ¹Á±Õ¥¹ô¹©Í½¸ˆ(€€€€€€€É…Ý}Á…Ñ €ôÉ…Ý}‘¥È€¼¹…µ”(€€€€€€€¥˜¹½Ð}…¡•}½ÕÑÁÕÑ}Ù…±¥¡ÍÑ…ÑÕÌ°É…Ý}Á…Ñ °…Í•}‘¥È¤è(€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È¡˜‰¡…Í µ¥Íµ…Ñ ½Èµ¥ÍÍ¥¹œ¡…Í ™½ÈíÍÑ…ÑÕÌ¹Á±Õ¥¹ôˆ¤(€€€€€€€Ù•É¥™¥•‘}É…Ü€¬ô€Ä(€€€€€€€Ù•É¥™¥•‘}‘ÕµÁÌ€¬ô±•¸¡ÍÑ…ÑÕÌ¹‘ÕµÁ}¡…Í¡•Ì¤(€€€É•ÑÕÉ¸ì‰Ù•É¥™¥•‘}É…Ý}½ÕÑÁÕÑÌˆèÙ•É¥™¥•‘}É…Ü°€‰Ù•É¥™¥•‘}‘ÕµÁ}™¥±•ÌˆèÙ•É¥™¥•‘}‘ÕµÁÌ°€‰Í½ÕÉ•}•Ù¥‘•¹•}Ù•É¥™¥•ˆè•Ù¥‘•¹•}Ù•É¥™¥•°€‰¡…Í¡}…±½É¥Ñ¡´ˆè€‰Í¡„ÈÔØ‰ô(()‘•˜}ÉÕ¹Ñ¥µ•}Á±Õ¥¹}…ÉÌ¡™œè‘¥ÑmÍÑÈ°¹åt°Á±Õ¥¸èÍÑÈ°å…É…}Í½ÕÉ”èA…Ñ ð±¥ÍÑmA…Ñ¡tð9½¹”¤€´ø±¥ÍÑmÍÑÉtè(€€€…ÉÌ€ôÁ±Õ¥¹}…ÉÍ}™½È¡™œ°Á±Õ¥¸¤(€€€¥˜Á±Õ¥¸€ôô€‰Ý¥¹‘½ÝÌ¹Ù…‘å…É…Í…¸ˆ…¹¹½Ð…¹ä¡¥Ñ•´¹ÍÑ…ÉÑÍÝ¥Ñ  ˆ´µå…É„´ˆ¤™½È¥Ñ•´¥¸…ÉÌ¤è(€€€€€€€…¹‘¥‘…Ñ•Ì€ômå…É…}Í½ÕÉ•t¥˜¥Í¥¹ÍÑ…¹”¡å…É…}Í½ÕÉ”°A…Ñ ¤•±Í”±¥ÍÐ¡å…É…}Í½ÕÉ”½Èmt¤(€€€€€€€™½È…¹‘¥‘…Ñ”¥¸…¹‘¥‘…Ñ•Ìè(€€€€€€€€€€€¥˜…¹‘¥‘…Ñ”¹¥Í}™¥±” ¤…¹…¹‘¥‘…Ñ”¹ÍÕ™™¥à¹…Í•™½± ¤€ôô€ˆ¹å…É…Œˆè(€€€€€€€€€€€€€€€É•ÑÕÉ¸…ÉÌ€¬lˆ´µå…É„µ½µÁ¥±•µ™¥±”ˆ°ÍÑÈ¡…¹‘¥‘…Ñ”¥t(€€€€€€€€€€€¥˜…¹‘¥‘…Ñ”¹¥Í}™¥±” ¤…¹…¹‘¥‘…Ñ”¹ÍÕ™™¥à¹…Í•™½± ¤¥¸ìˆ¹å…Èˆ°€ˆ¹å…É„‰ôè(€€€€€€€€€€€€€€€É•ÑÕÉ¸…ÉÌ€¬lˆ´µå…É„µ™¥±”ˆ°ÍÑÈ¡…¹‘¥‘…Ñ”¥t(€€€€€€€€€€€¥˜…¹‘¥‘…Ñ”¹¥Í}‘¥È ¤è(€€€€€€€€€€€€€€€ÉÕ±”€ô¹•áÐ¡¥Ñ•È¡}•¹Õµ•É…Ñ•}ÉÕ±•}™¥±•Ì¡m…¹‘¥‘…Ñ•t¤¤°9½¹”¤(€€€€€€€€€€€€€€€¥˜ÉÕ±”è(€€€€€€€€€€€€€€€€€€€É•ÑÕÉ¸…ÉÌ€¬lˆ´µå…É„µ™¥±”ˆ°ÍÑÈ¡ÉÕ±”¥t(€€€É•ÑÕÉ¸…ÉÌ(()‘•˜}Á±Õ¥¹}Í­¥Á}É•…Í½¸¡Á±Õ¥¸èÍÑÈ°…ÉÌè±¥ÍÑmÍÑÉt¤€´øÍÑÈè(€€€¥˜Á±Õ¥¸€ôô€‰Ý¥¹‘½ÝÌ¹Ù…‘å…É…Í…¸ˆ…¹¹½Ð…¹ä¡¥Ñ•´¹ÍÑ…ÉÑÍÝ¥Ñ  ˆ´µå…É„´ˆ¤™½È¥Ñ•´¥¸…ÉÌ¤è(€€€€€€€É•ÑÕÉ¸€‰Ý¥¹‘½ÝÌ¹Ù…‘å…É…Í…¸É•ÅÕ¥É•Ì…¸•¹…‰±•eIÍ½ÕÉ”¸ˆ(€€€É•ÑÕÉ¸€ˆˆ(()‘•˜}Í¡½Õ±‘}…ÁÑÕÉ•}‘ÕµÀ¡Á±Õ¥¸èÍÑÈ°¹½}µ…±™¥¹‘}‘ÕµÀè‰½½°°¥¹±Õ‘•}‘ÕµÁ}…ÉÑ¥™…ÑÌè‰½½°¤€´ø‰½½°è(€€€¥˜Á±Õ¥¸€ôô€‰Ý¥¹‘½ÝÌ¹µ…±™¥¹ˆè(€€€€€€€É•ÑÕÉ¸¹½Ð¹½}µ…±™¥¹‘}‘ÕµÀ(€€€É•ÑÕÉ¸¥¹±Õ‘•}‘ÕµÁ}…ÉÑ¥™…ÑÌ…¹Á±Õ¥¸¥¸ì‰Ý¥¹‘½ÝÌ¹‘ÕµÁ™¥±•Ìˆ°€‰Ý¥¹‘½ÝÌ¹‘±±±¥ÍÐˆ°€‰Ý¥¹‘½ÝÌ¹µ•µµ…À‰ô(()‘•˜}•áÑ•É¹…±}Ñ½½±}Í•ÑÑ¥¹Ì¡™œè‘¥ÑmÍÑÈ°¹åt°¹½}™±½ÍÌè‰½½°°¹½}…Á„è‰½½°°¹½}±…µ…Øè‰½½°°¹½}‘¥”è‰½½°°¹½}Á•™¥±”è‰½½°¤€´ø‘¥ÑmÍÑÈ°¹åtè(€€€½¹™¥ÕÉ•€ô}µ…ÁÁ¥¹œ¡}µ…ÁÁ¥¹œ¡™œ¹•Ð ‰…¹…±åÍ¥Ìˆ°íô¤¤¹•Ð ‰•áÑ•É¹…±}Ñ½½±Ìˆ°íô¤¤(€€€É•ÑÕÉ¸ì(€€€€€€€€‰•¹…‰±•}™±½ÍÌˆè‰½½°¡½¹™¥ÕÉ•¹•Ð ‰•¹…‰±•}™±½ÍÌˆ°QÉÕ”¤¤…¹¹½Ð¹½}™±½ÍÌ°(€€€€€€€€‰•¹…‰±•}…Á„ˆè‰½½°¡½¹™¥ÕÉ•¹•Ð ‰•¹…‰±•}…Á„ˆ°QÉÕ”¤¤…¹¹½Ð¹½}…Á„°(€€€€€€€€‰•¹…‰±•}±…µ…Øˆè‰½½°¡½¹™¥ÕÉ•¹•Ð ‰•¹…‰±•}±…µ…Øˆ°QÉÕ”¤¤…¹¹½Ð¹½}±…µ…Ø°(€€€€€€€€‰•¹…‰±•}‘¥”ˆè‰½½°¡½¹™¥ÕÉ•¹•Ð ‰•¹…‰±•}‘¥”ˆ°QÉÕ”¤¤…¹¹½Ð¹½}‘¥”°(€€€€€€€€‰•¹…‰±•}Á•™¥±”ˆè‰½½°¡½¹™¥ÕÉ•¹•Ð ‰•¹…‰±•}Á•™¥±”ˆ°QÉÕ”¤¤…¹¹½Ð¹½}Á•™¥±”°(€€€€€€€€‰…Á…}ÉÕ±•ÌˆèÍÑÈ¡½¹™¥ÕÉ•¹•Ð ‰…Á…}ÉÕ±•Ìˆ°€ˆˆ¤¤°(€€€€€€€€‰Ñ¥µ•½ÕÑ}Í•½¹‘Ìˆè¥¹Ð¡½¹™¥ÕÉ•¹•Ð ‰Ñ¥µ•½ÕÑ}Í•½¹‘Ìˆ°€ÄÈÀ¤¤°(€€€€€€€€‰µ…á}™¥±•}Í¥é•}µˆˆè¥¹Ð¡½¹™¥ÕÉ•¹•Ð ‰µ…á}™¥±•}Í¥é•}µˆˆ°€ÄÀÀ¤¤°(€€€€€€€€‰µ…á}½ÕÑÁÕÑ}µˆˆè¥¹Ð¡½¹™¥ÕÉ•¹•Ð ‰µ…á}½ÕÑÁÕÑ}µˆˆ°€ÌÈ¤¤°(€€€ô(()‘•˜}‘•‘ÕÁ•}™¥¹‘¥¹Ì¡™¥¹‘¥¹Ìè±¥ÍÑm¥¹‘¥¹t¤€´ø±¥ÍÑm¥¹‘¥¹tè(€€€µ•É•è‘¥ÑmÑÕÁ±•mÍÑÈ°¥¹Ðð9½¹”°ÍÑÈ°ÍÑÉt°¥¹‘¥¹t€ôíô(€€€™½È™¥¹‘¥¹œ¥¸™¥¹‘¥¹Ìè(€€€€€€€­•ä€ô€¡™¥¹‘¥¹œ¹ÁÉ½•ÍÍ}­•ä°™¥¹‘¥¹œ¹Á¥°™¥¹‘¥¹œ¹…Ñ•½Éä°™¥¹‘¥¹œ¹Ñ¥Ñ±”¤(€€€€€€€•á¥ÍÑ¥¹œ€ôµ•É•¹•Ð¡­•ä¤(€€€€€€€¥˜•á¥ÍÑ¥¹œ¥Ì9½¹”è(€€€€€€€€€€€µ•É•‘m­•åt€ô™¥¹‘¥¹œ(€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€•á¥ÍÑ¥¹œ¹Í½É”€ôµ…à¡•á¥ÍÑ¥¹œ¹Í½É”°™¥¹‘¥¹œ¹Í½É”¤(€€€€€€€½É‘•È€ôì‰Õ¹Ù•É¥™¥•ˆè€À°€‰±½Üˆè€Ä°€‰Á½ÍÍ¥‰±”ˆè€È°€‰±¥­•±äˆè€Ì°€‰¡¥ ˆè€Ð°€‰½ÉÉ½‰½É…Ñ•ˆè€Õô(€€€€€€€¥˜½É‘•È¹•Ð¡™¥¹‘¥¹œ¹½¹™¥‘•¹”°€À¤€ø½É‘•È¹•Ð¡•á¥ÍÑ¥¹œ¹½¹™¥‘•¹”°€À¤è(€€€€€€€€€€€•á¥ÍÑ¥¹œ¹½¹™¥‘•¹”€ô™¥¹‘¥¹œ¹½¹™¥‘•¹”(€€€€€€€•á¥ÍÑ¥¹œ¹½ÕÉÉ•¹•}½Õ¹Ð€¬ô™¥¹‘¥¹œ¹½ÕÉÉ•¹•}½Õ¹Ð(€€€€€€€•á¥ÍÑ¥¹œ¹•Ù¥‘•¹”¹•áÑ•¹¡¥Ñ•´™½È¥Ñ•´¥¸™¥¹‘¥¹œ¹•Ù¥‘•¹”¥˜¥Ñ•´¹½Ð¥¸•á¥ÍÑ¥¹œ¹•Ù¥‘•¹”¤(€€€€€€€•á¥ÍÑ¥¹œ¹ÁÉ½Ù•¹…¹•}¥‘Ì€ôÍ½ÉÑ•¡Í•Ð¡•á¥ÍÑ¥¹œ¹ÁÉ½Ù•¹…¹•}¥‘Ì€¬™¥¹‘¥¹œ¹ÁÉ½Ù•¹…¹•}¥‘Ì¤¤(€€€É•ÑÕÉ¸±¥ÍÐ¡µ•É•¹Ù…±Õ•Ì ¤¤(()‘•˜}Ù…±¥‘…Ñ•}™½Éµ…Ð¡Ù…±Õ”èÍÑÈ¤€´øÍÑÈè(€€€¹½Éµ…±¥é•€ôÙ…±Õ”¹…Í•™½± ¤(€€€¥˜¹½Éµ…±¥é•¹½Ð¥¸Y1%}=I5QLè(€€€€€€€É…¥Í”ÑåÁ•È¹	…‘A…É…µ•Ñ•È ˆ´µ™½Éµ…ÐµÕÍÐ‰”µ°µ…É­‘½Ý¸°¡Ñµ°°Á‘˜°½È…±°ˆ¤(€€€É•ÑÕÉ¸¹½Éµ…±¥é•(()‘•˜}Ù…±¥‘…Ñ•}É•Á½ÉÑ}½¹™¥ÕÉ…Ñ¥½¸¡½ÕÑÁÕÑ}™½Éµ…ÐèÍÑÈ°…¹…±åÍ¥Í}™œè‘¥ÑmÍÑÈ°¹åt¤€´ø9½¹”è(€€€¥˜½ÕÑÁÕÑ}™½Éµ…Ð¥¸ì‰¡Ñµ°ˆ°€‰…±°‰ô…¹¹½Ð‰½½°¡…¹…±åÍ¥Í}™œ¹•Ð ‰•¹…‰±•}¡Ñµ±}É•Á½ÉÐˆ°QÉÕ”¤¤è(€€€€€€€É…¥Í”ÑåÁ•È¹	…‘A…É…µ•Ñ•È ‰!Q50É•Á½ÉÑ¥¹œ¥Ì‘¥Í…‰±•‰äÑ¡”•™™•Ñ¥Ù”½¹™¥ÕÉ…Ñ¥½¸¸ˆ¤(€€€¥˜½ÕÑÁÕÑ}™½Éµ…Ð¥¸ì‰Á‘˜ˆ°€‰…±°‰ô…¹¹½Ð‰½½°¡…¹…±åÍ¥Í}™œ¹•Ð ‰•¹…‰±•}Á‘™}É•Á½ÉÐˆ°…±Í”¤¤è(€€€€€€€É…¥Í”ÑåÁ•È¹	…‘A…É…µ•Ñ•È ‰AÉ•Á½ÉÑ¥¹œ¥Ì‘¥Í…‰±•‰äÑ¡”•™™•Ñ¥Ù”½¹™¥ÕÉ…Ñ¥½¸¸ˆ¤(()‘•˜}•¹Õµ•É…Ñ•}ÉÕ±•}™¥±•Ì¡Á…Ñ¡Ìè±¥ÍÑmA…Ñ¡t¤€´ø±¥ÍÑmA…Ñ¡tè(€€€™¥±•Ìè±¥ÍÑmA…Ñ¡t€ômt(€€€™½ÈÁ…Ñ ¥¸Á…Ñ¡Ìè(€€€€€€€¥˜Á…Ñ ¹¥Í}™¥±” ¤…¹Á…Ñ ¹ÍÕ™™¥à¹…Í•™½± ¤¥¸ìˆ¹å…Èˆ°€ˆ¹å…É„ˆ°€ˆ¹å…É…Œ‰ôè(€€€€€€€€€€€™¥±•Ì¹…ÁÁ•¹¡Á…Ñ ¹É•Í½±Ù” ¤¤(€€€€€€€•±¥˜Á…Ñ ¹¥Í}‘¥È ¤è(€€€€€€€€€€€™¥±•Ì¹•áÑ•¹¡…¹‘¥‘…Ñ”¹É•Í½±Ù” ¤™½È…¹‘¥‘…Ñ”¥¸Á…Ñ ¹É±½ˆ ˆ¨ˆ¤¥˜…¹‘¥‘…Ñ”¹¥Í}™¥±” ¤…¹…¹‘¥‘…Ñ”¹ÍÕ™™¥à¹…Í•™½± ¤¥¸ìˆ¹å…Èˆ°€ˆ¹å…É„ˆ°€ˆ¹å…É…Œ‰ô¤(€€€É•ÑÕÉ¸Í½ÉÑ•¡‘¥Ð¹™É½µ­•åÌ¡™¥±•Ì¤¤(()‘•˜}ÉÕ±•}¥¹Ù•¹Ñ½Éä¡Á…Ñ¡Ìè±¥ÍÑmA…Ñ¡t¤€´ø±¥ÍÑm‘¥ÑmÍÑÈ°¹åutè(€€€É•ÑÕÉ¸mì‰Á…Ñ ˆèÍÑÈ¡Á…Ñ ¤°€‰Í¡„ÈÔØˆè}Í¡„ÈÔØ¡Á…Ñ ¤°€‰Í¥é”ˆèÁ…Ñ ¹ÍÑ…Ð ¤¹ÍÑ}Í¥é•ô™½ÈÁ…Ñ ¥¸}•¹Õµ•É…Ñ•}ÉÕ±•}™¥±•Ì¡Á…Ñ¡Ì¥t(()‘•˜}Í¹…ÁÍ¡½Ñ}å…É…}ÉÕ±•Ì¡…Í•}‘¥ÈèA…Ñ °Á…Ñ¡Ìè±¥ÍÑmA…Ñ¡t°•¹…‰±•è‰½½°¤€´øÑÕÁ±•m±¥ÍÑmA…Ñ¡t°‘¥ÑmÍÑÈ°¹åutè(€€€µ…¹¥™•ÍÐè‘¥ÑmÍÑÈ°¹åt€ôì‰•¹…‰±•ˆè•¹…‰±•°€‰™¥±•Ìˆèmt°€‰½µÁ¥±•}ÍÑ…ÑÕÌˆèíõô(€€€¥˜¹½Ð•¹…‰±•è(€€€€€€€É•ÑÕÉ¸mt°µ…¹¥™•ÍÐ(€€€‘•ÍÑ¥¹…Ñ¥½¸€ô…Í•}‘¥È€¼€‰•Ù¥‘•¹”ˆ€¼€‰å…É…}ÉÕ±•Ìˆ(€€€‘•ÍÑ¥¹…Ñ¥½¸¹µ­‘¥È¡Á…É•¹ÑÌõQÉÕ”°•á¥ÍÑ}½¬õQÉÕ”¤(€€€Í¹…ÁÍ¡½ÑÌè±¥ÍÑmA…Ñ¡t€ômt(€€€‰Õ¥±Ñ¥¹}É½½Ð€ô}‰Õ¥±Ñ¥¹}å…É…}ÉÕ±•Í}‘¥È ¤¹É•Í½±Ù” ¤(€€€™½ÈÍ½ÕÉ”¥¸}•¹Õµ•É…Ñ•}ÉÕ±•}™¥±•Ì¡Á…Ñ¡Ì¤è(€€€€€€€‘¥•ÍÐ€ô}Í¡„ÈÔØ¡Í½ÕÉ”¤(€€€€€€€Ñ…É•Ð€ô‘•ÍÑ¥¹…Ñ¥½¸€¼˜‰í‘¥•ÍÑlèÄÉuõ}íÍ½ÕÉ”¹¹…µ•ôˆ(€€€€€€€Í¡ÕÑ¥°¹½ÁäÈ¡Í½ÕÉ”°Ñ…É•Ð¤(€€€€€€€Í¹…ÁÍ¡½ÑÌ¹…ÁÁ•¹¡Ñ…É•Ð¤(€€€€€€€µ…¹¥™•ÍÑl‰™¥±•Ì‰t¹…ÁÁ•¹ (€€€€€€€€€€€ì(€€€€€€€€€€€€€€€€‰½É¥¥¹…±}Á…Ñ ˆèÍÑÈ¡Í½ÕÉ”¤°(€€€€€€€€€€€€€€€€‰Í¹…ÁÍ¡½Ñ}Á…Ñ ˆèÍÑÈ¡Ñ…É•Ð¹É•±…Ñ¥Ù•}Ñ¼¡…Í•}‘¥È¤¤°(€€€€€€€€€€€€€€€€‰Í¡„ÈÔØˆè‘¥•ÍÐ°(€€€€€€€€€€€€€€€€‰Í¥é”ˆèÍ½ÕÉ”¹ÍÑ…Ð ¤¹ÍÑ}Í¥é”°(€€€€€€€€€€€€€€€€‰‰Õ¥±Ñ}¥¸ˆè‰Õ¥±Ñ¥¹}É½½Ð€ôôÍ½ÕÉ”¹Á…É•¹Ð½È‰Õ¥±Ñ¥¹}É½½Ð¥¸Í½ÕÉ”¹Á…É•¹ÑÌ°(€€€€€€€€€€€€€€€€‰½µÁ¥±•ˆèÍ½ÕÉ”¹ÍÕ™™¥à¹…Í•™½± ¤€ôô€ˆ¹å…É…Œˆ°(€€€€€€€€€€€ô(€€€€€€€€¤(€€€É•ÑÕÉ¸Í¹…ÁÍ¡½ÑÌ°µ…¹¥™•ÍÐ(()‘•˜}µ…¹¥™•ÍÑ}ÉÕ±•}Á…Ñ¡Ì¡…Í•}‘¥ÈèA…Ñ °µ…¹¥™•ÍÑ}Ù…±Õ”è¹ä¤€´ø±¥ÍÑmA…Ñ¡tè(€€€µ…¹¥™•ÍÐ€ô}µ…ÁÁ¥¹œ¡µ…¹¥™•ÍÑ}Ù…±Õ”¤(€€€™¥±•Ì€ôµ…¹¥™•ÍÐ¹•Ð ‰™¥±•Ìˆ°mt¤(€€€É•ÍÕ±Ðè±¥ÍÑmA…Ñ¡t€ômt(€€€¥˜¥Í¥¹ÍÑ…¹”¡™¥±•Ì°±¥ÍÐ¤è(€€€€€€€™½ÈÉ½Ü¥¸™¥±•Ìè(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡É½Ü°‘¥Ð¤è(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”(€€€€€€€€€€€Á…Ñ €ô…Í•}‘¥È€¼ÍÑÈ¡É½Ü¹•Ð ‰Í¹…ÁÍ¡½Ñ}Á…Ñ ˆ°€ˆˆ¤¤(€€€€€€€€€€€¥˜Á…Ñ ¹¥Í}™¥±” ¤è(€€€€€€€€€€€€€€€É•ÍÕ±Ð¹…ÁÁ•¹¡Á…Ñ ¤(€€€É•ÑÕÉ¸É•ÍÕ±Ð(()‘•˜}Ù•É¥™å}å…É…}µ…¹¥™•ÍÐ¡…Í•}‘¥ÈèA…Ñ °µ…¹¥™•ÍÑ}Ù…±Õ”è¹ä¤€´ø‘¥ÑmÍÑÈ°¹åtè(€€€µ…¹¥™•ÍÐ€ô}µ…ÁÁ¥¹œ¡µ…¹¥™•ÍÑ}Ù…±Õ”¤(€€€¥˜¹½Ð‰½½°¡µ…¹¥™•ÍÐ¹•Ð ‰•¹…‰±•ˆ°…±Í”¤¤è(€€€€€€€É•ÑÕÉ¸ì‰Ù•É¥™¥•‘}å…É…}ÉÕ±•Ìˆè€À°€‰å…É…}•¹…‰±•ˆè…±Í•ô(€€€Á…Ñ¡Ì€ô}µ…¹¥™•ÍÑ}ÉÕ±•}Á…Ñ¡Ì¡…Í•}‘¥È°µ…¹¥™•ÍÐ¤(€€€•áÁ•Ñ•‘}É½ÝÌ€ômÉ½Ü™½ÈÉ½Ü¥¸µ…¹¥™•ÍÐ¹•Ð ‰™¥±•Ìˆ°mt¤¥˜¥Í¥¹ÍÑ…¹”¡É½Ü°‘¥Ð¥t¥˜¥Í¥¹ÍÑ…¹”¡µ…¹¥™•ÍÐ¹•Ð ‰™¥±•Ìˆ¤°±¥ÍÐ¤•±Í”mt(€€€¥˜±•¸¡Á…Ñ¡Ì¤€„ô±•¸¡•áÁ•Ñ•‘}É½ÝÌ¤è(€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È ‰½¹”½Èµ½É”Í¹…ÁÍ¡½ÑÑ•eIÉÕ±•Ì…É”µ¥ÍÍ¥¹œˆ¤(€€€™½ÈÁ…Ñ °É½Ü¥¸é¥À¡Á…Ñ¡Ì°•áÁ•Ñ•‘}É½ÝÌ°ÍÑÉ¥ÐõQÉÕ”¤è(€€€€€€€¥˜}Í¡„ÈÔØ¡Á…Ñ ¤€„ôÍÑÈ¡É½Ü¹•Ð ‰Í¡„ÈÔØˆ°€ˆˆ¤¤è(€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È¡˜‰eIÉÕ±”¡…Í µ¥Íµ…Ñ èíÁ…Ñ ¹¹…µ•ôˆ¤(€€€É•ÑÕÉ¸ì‰Ù•É¥™¥•‘}å…É…}ÉÕ±•Ìˆè±•¸¡Á…Ñ¡Ì¤°€‰å…É…}•¹…‰±•ˆèQÉÕ•ô(()‘•˜}½±±•Ñ}Ñ½½±}µ…¹¥™•ÍÐ¡Ù½±…Ñ¥±¥Ñå}½µµ…¹èÍÑÈ°ÉÕ¹¹•ÈèY½±…Ñ¥±¥ÑåIÕ¹¹•È°•áÑ•É¹…±}Í•ÑÑ¥¹Ìè‘¥ÑmÍÑÈ°¹åt¤€´ø‘¥ÑmÍÑÈ°¹åtè(€€€Ñ½½±Ìè±¥ÍÑm‘¥ÑmÍÑÈ°¹åut€ômt(€€€Ù½±}Á…Ñ €ôÍ¡ÕÑ¥°¹Ý¡¥ ¡Ù½±…Ñ¥±¥Ñå}½µµ…¹¤½ÈÙ½±…Ñ¥±¥Ñå}½µµ…¹(€€€Ñ½½±Ì¹…ÁÁ•¹¡}Ñ½½±}•¹ÑÉä ‰Ù½±…Ñ¥±¥ÑäÌˆ°Ù½±}Á…Ñ °ÉÕ¹¹•È¹Ù•ÉÍ¥½¹}Ñ•áÐ ¤°ÉÕ¹¹•È¹¥Í}…Ù…¥±…‰±” ¤°QÉÕ”¤¤(€€€½ÁÑ¥½¹…°€ôì(€€€€€€€€‰™±½ÍÌˆè€ ‰™±½ÍÌˆ°‰½½°¡•áÑ•É¹…±}Í•ÑÑ¥¹Ì¹•Ð ‰•¹…‰±•}™±½ÍÌˆ°…±Í”¤¤¤°(€€€€€€€€‰…Á„ˆè€ ‰…Á„ˆ°‰½½°¡•áÑ•É¹…±}Í•ÑÑ¥¹Ì¹•Ð ‰•¹…‰±•}…Á„ˆ°…±Í”¤¤¤°(€€€€€€€€‰±…µ…Øˆè€ ‰±…µÍ…¸ˆ°‰½½°¡•áÑ•É¹…±}Í•ÑÑ¥¹Ì¹•Ð ‰•¹…‰±•}±…µ…Øˆ°…±Í”¤¤¤°(€€€€€€€€‰‘•Ñ•Ðµ¥Ðµ•…Íäˆè€ ‰‘¥•Œˆ°‰½½°¡•áÑ•É¹…±}Í•ÑÑ¥¹Ì¹•Ð ‰•¹…‰±•}‘¥”ˆ°…±Í”¤¤¤°(€€€ô(€€€™½È¹…µ”°€¡½µµ…¹°•¹…‰±•¤¥¸½ÁÑ¥½¹…°¹¥Ñ•µÌ ¤è(€€€€€€€Á…Ñ €ôÍ¡ÕÑ¥°¹Ý¡¥ ¡½µµ…¹¤½È€ˆˆ(€€€€€€€Ñ½½±Ì¹…ÁÁ•¹¡}Ñ½½±}•¹ÑÉä¡¹…µ”°Á…Ñ °}½µµ…¹‘}Ù•ÉÍ¥½¸¡Á…Ñ ¤¥˜Á…Ñ •±Í”€‰Õ¹…Ù…¥±…‰±”ˆ°‰½½°¡Á…Ñ ¤°•¹…‰±•¤¤(€€€™½ÈÁ…­…”°•¹…‰±•¥¸€  ‰Á•™¥±”ˆ°‰½½°¡•áÑ•É¹…±}Í•ÑÑ¥¹Ì¹•Ð ‰•¹…‰±•}Á•™¥±”ˆ°…±Í”¤¤¤°€ ‰å…É„µÁåÑ¡½¸ˆ°QÉÕ”¤¤è(€€€€€€€ÑÉäè(€€€€€€€€€€€Ù•ÉÍ¥½¸€ô¥µÁ½ÉÑ±¥ˆ¹µ•Ñ…‘…Ñ„¹Ù•ÉÍ¥½¸¡Á…­…”¤(€€€€€€€€€€€…Ù…¥±…‰±”€ôQÉÕ”(€€€€€€€•á•ÁÐ¥µÁ½ÉÑ±¥ˆ¹µ•Ñ…‘…Ñ„¹A…­…•9½Ñ½Õ¹‘ÉÉ½Èè(€€€€€€€€€€€Ù•ÉÍ¥½¸€ô€‰Õ¹…Ù…¥±…‰±”ˆ(€€€€€€€€€€€…Ù…¥±…‰±”€ô…±Í”(€€€€€€€Ñ½½±Ì¹…ÁÁ•¹¡ì‰Ñ½½°ˆèÁ…­…”°€‰•¹…‰±•ˆè•¹…‰±•°€‰…Ù…¥±…‰±”ˆè…Ù…¥±…‰±”°€‰Ù•ÉÍ¥½¸ˆèÙ•ÉÍ¥½¸°€‰‰¥¹…Éå}Á…Ñ ˆè€ˆˆ°€‰Í¡„ÈÔØˆè€ˆ‰ô¤(€€€É•ÑÕÉ¸ì‰…ÁÑÕÉ•‘}…Ðˆè‘…Ñ•Ñ¥µ”¹¹½Ü¡Ñ¥µ•é½¹”¹ÕÑŒ¤¹¥Í½™½Éµ…Ð ¤°€‰Ñ½½±ÌˆèÑ½½±Íô(()‘•˜}Ñ½½±}•¹ÑÉä¡¹…µ”èÍÑÈ°Á…Ñ¡}Ù…±Õ”èÍÑÈ°Ù•ÉÍ¥½¸èÍÑÈ°…Ù…¥±…‰±”è‰½½°°•¹…‰±•è‰½½°¤€´ø‘¥ÑmÍÑÈ°¹åtè(€€€Á…Ñ €ôA…Ñ ¡Á…Ñ¡}Ù…±Õ”¤¥˜Á…Ñ¡}Ù…±Õ”•±Í”9½¹”(€€€É•ÑÕÉ¸ì(€€€€€€€€‰Ñ½½°ˆè¹…µ”°(€€€€€€€€‰•¹…‰±•ˆè•¹…‰±•°(€€€€€€€€‰…Ù…¥±…‰±”ˆè…Ù…¥±…‰±”°(€€€€€€€€‰Ù•ÉÍ¥½¸ˆèÙ•ÉÍ¥½¸°(€€€€€€€€‰‰¥¹…Éå}Á…Ñ ˆèÁ…Ñ¡}Ù…±Õ”°(€€€€€€€€‰Í¡„ÈÔØˆè}Í¡„ÈÔØ¡Á…Ñ ¤¥˜Á…Ñ ¥Ì¹½Ð9½¹”…¹Á…Ñ ¹¥Í}™¥±” ¤•±Í”€ˆˆ°(€€€ô(()‘•˜}½µµ…¹‘}Ù•ÉÍ¥½¸¡Á…Ñ èÍÑÈ¤€´øÍÑÈè(€€€ÑÉäè(€€€€€€€½µÁ±•Ñ•€ôÍÕ‰ÁÉ½•ÍÌ¹ÉÕ¸¡mÁ…Ñ °€ˆ´µÙ•ÉÍ¥½¸‰t°…ÁÑÕÉ•}½ÕÑÁÕÐõQÉÕ”°Ñ•áÐõQÉÕ”°Ñ¥µ•½ÕÐôÄÀ°¡•¬õ…±Í”¤(€€€•á•ÁÐ€¡=MÉÉ½È°ÍÕ‰ÁÉ½•ÍÌ¹MÕ‰ÁÉ½•ÍÍÉÉ½È¤è(€€€€€€€É•ÑÕÉ¸€‰Ù•ÉÍ¥½¸Õ¹…Ù…¥±…‰±”ˆ(€€€Ù…±Õ”€ô€¡½µÁ±•Ñ•¹ÍÑ‘½ÕÐ½È½µÁ±•Ñ•¹ÍÑ‘•ÉÈ½È€ˆˆ¤¹ÍÑÉ¥À ¤¹ÍÁ±¥Ñ±¥¹•Ì ¤(€€€É•ÑÕÉ¸Ù…±Õ•lÁulèÌÀÁt¥˜Ù…±Õ”•±Í”˜‰É•ÑÕÉ¹}½‘”õí½µÁ±•Ñ•¹É•ÑÕÉ¹½‘•ôˆ(()‘•˜}ÉÕ¹¹•É}™É½µ}½¹™¥œ¡™œè‘¥ÑmÍÑÈ°¹åt¤€´øY½±…Ñ¥±¥ÑåIÕ¹¹•Èè(€€€Ù½°€ô}µ…ÁÁ¥¹œ¡™œ¹•Ð ‰Ù½±…Ñ¥±¥Ñäˆ°íô¤¤(€€€‰Õ¥±‘•È€ôY½±…Ñ¥±¥Ñå½µµ…¹‘	Õ¥±‘•È¡ÍÑÈ¡Ù½°¹•Ð ‰½µµ…¹ˆ°€‰Ù½°ˆ¤¤°ÍÑÈ¡Ù½°¹•Ð ‰É•¹‘•É•Èˆ°€‰©Í½¸ˆ¤¤°‰½½°¡Ù½°¹•Ð ‰ÅÕ¥•Ðˆ°QÉÕ”¤¤¤(€€€É•ÑÕÉ¸Y½±…Ñ¥±¥ÑåIÕ¹¹•È¡‰Õ¥±‘•È°¥¹Ð¡Ù½°¹•Ð ‰Ñ¥µ•½ÕÑ}Í•½¹‘Ìˆ°€ØÀÀ¤¤¤(()‘•˜}µ…ÁÁ¥¹œ¡Ù…±Õ”è¹ä¤€´ø‘¥ÑmÍÑÈ°¹åtè(€€€É•ÑÕÉ¸Ù…±Õ”¥˜¥Í¥¹ÍÑ…¹”¡Ù…±Õ”°‘¥Ð¤•±Í”íô(()‘•˜}É½Ý}±¥ÍÐ¡Ù…±Õ”è¹ä¤€´ø±¥ÍÑm‘¥ÑmÍÑÈ°¹åutè(€€€É•ÑÕÉ¸m¥Ñ•´™½È¥Ñ•´¥¸Ù…±Õ”¥˜¥Í¥¹ÍÑ…¹”¡¥Ñ•´°‘¥Ð¥t¥˜¥Í¥¹ÍÑ…¹”¡Ù…±Õ”°±¥ÍÐ¤•±Í”mt(()‘•˜}½ÁÑ¥½¹…±}¥¹Ð¡Ù…±Õ”è¹ä¤€´ø¥¹Ðð9½¹”è(€€€¥˜Ù…±Õ”¥¸€¡9½¹”°€ˆˆ¤è(€€€€€€€É•ÑÕÉ¸9½¹”(€€€ÑÉäè(€€€€€€€É•ÑÕÉ¸¥¹Ð¡Ù…±Õ”¤(€€€•á•ÁÐ€¡QåÁ•ÉÉ½È°Y…±Õ•ÉÉ½È¤è(€€€€€€€É•ÑÕÉ¸9½¹”(()‘•˜}¹½Éµ…±¥é•}…¹‘}…¹…±åé” (€€€…Í•}‘¥ÈèA…Ñ °(€€€‘ÕµÁ}™¥±•Ìè±¥ÍÑmÍÑÉt°(€€€ÍÑ…ÑÕÍ•Ìè±¥ÍÑmA±Õ¥¹MÑ…ÑÕÍt°(€€€€¨°(€€€•áÑ•É¹…±}Ñ½½±Ìè‘¥ÑmÍÑÈ°¹åtð9½¹”€ô9½¹”°(¤è(€€€€ˆˆ‰½µÁ…Ñ¥‰¥±¥ÑäÝÉ…ÁÁ•È™½È¥¹Ñ•É…Ñ¥½¹ÌÑ¡…ÐÁÉ•Ù¥½ÕÍ±ä¥¹Ù½­•¹½Éµ…±¥é…Ñ¥½¸‘¥É•Ñ±ä¸ˆˆˆ(€€€‘•°‘ÕµÁ}™¥±•Ì(€€€É•ÑÕÉ¸…¹…±åé•}…Í”¡…Í•}‘¥È°ÍÑ…ÑÕÍ•Ì°±½…‘}½¹™¥œ ¤°•áÑ•É¹…±}Ñ½½±Ìõ•áÑ•É¹…±}Ñ½½±Ì½Èíô¤(