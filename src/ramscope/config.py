from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from ramscope.volatility.plugin_plan import CORE_PLUGINS, DEEP_PLUGINS, FULL_DUMP_PLUGINS, FULL_PLUGINS


DEFAULT_CONFIG: dict[str, Any] = {
    "volatility": {
        "command": "vol",
        "renderer": "json",
        "quiet": True,
        "timeout_seconds": 600,
    },
    "execution": {
        "workers": "auto",
        "auto_min_cpus": 4,
        "auto_min_memory_gb": 8,
        "max_parallel_light": 2,
        "timeouts": {
            "standard": 600,
            "heavy": 1800,
            "dump": 3600,
            "windows.malfind": 1800,
        },
        "malfind": {
            "dump_mode": "targeted",
            "max_targets": 12,
        },
    },
    "plugins": {
        "windows.info": True,
        "windows.pslist": True,
        "windows.pstree": True,
        "windows.cmdline": True,
        "windows.dlllist": True,
        "windows.netscan": True,
        "windows.malfind": True,
        **{
            name: False
            for name in dict.fromkeys(DEEP_PLUGINS + FULL_PLUGINS + FULL_DUMP_PLUGINS)
            if name not in CORE_PLUGINS
        },
    },
    "plugin_args": {
        "windows.registry.printkey_run": ["--key", r"Software\Microsoft\Windows\CurrentVersion\Run"],
        "windows.registry.printkey_runonce": ["--key", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"],
        "windows.registry.printkey_wow64_run": ["--key", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"],
        "windows.registry.printkey_wow64_runonce": ["--key", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"],
        "windows.vadyarascan": [],
    },
    "plugin_dump_args": {
        "windows.malfind": ["--dump"],
        "windows.dlllist": ["--dump"],
        "windows.memmap": ["--dump"],
        "windows.dumpfiles": [],
    },
    "analysis": {
        "enable_yara": True,
        "enable_ioc_extraction": True,
        "enable_risk_scoring": True,
        "enable_html_report": True,
        "enable_pdf_report": False,
        "enable_full_artifact_dumps": False,
        "yara_timeout_seconds": 60,
        "external_tools": {
            "enable_floss": True,
            "enable_capa": True,
            "enable_clamav": True,
            "enable_die": True,
            "enable_pefile": True,
            "capa_rules": "",
            "timeout_seconds": 120,
            "max_file_size_mb": 100,
            "max_output_mb": 32,
        },
        "baseline": {
            "trusted_system_roots": [
                "c:\\windows\\system32\\",
                "c:\\windows\\syswow64\\",
                "c:\\program files\\",
                "c:\\program files (x86)\\",
            ],
            "user_writable_tokens": [
                "\\appdata\\",
                "\\temp\\",
                "\\users\\public\\",
                "\\downloads\\",
            ],
            "benign_domain_suffixes": [
                "microsoft.com",
                "windows.com",
                "windowsupdate.com",
                "office.com",
            ],
            "network_heavy_processes": [
                "chrome.exe",
                "msedge.exe",
                "firefox.exe",
                "teams.exe",
                "onedrive.exe",
                "msedgewebview2.exe",
            ],
        },
    },
    "risk_weights": {
        "memory": 1.0,
        "thread": 1.0,
        "signature": 1.0,
        "network": 1.0,
        "persistence": 1.0,
        "module": 1.0,
        "process": 1.0,
        "execution": 1.0,
        "kernel": 1.0,
        "hook": 1.0,
        "lsass": 1.0,
        "file": 1.0,
        "mutex": 1.0,
        "dump": 1.0,
    },
    "risk_category_caps": {
        "memory": 40,
        "thread": 30,
        "signature": 25,
        "network": 20,
        "persistence": 25,
        "module": 20,
        "process": 25,
        "execution": 25,
        "kernel": 40,
        "hook": 40,
        "lsass": 45,
        "file": 20,
        "mutex": 15,
        "dump": 10,
    },
    "risk_total_score_cap": 100,
}


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    config = deepcopy(DEFAULT_CONFIG)
    if config_path is not None:
        try:
            with config_path.open("r", encoding="utf-8") as file_obj:
                loaded = yaml.safe_load(file_obj) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"Could not load YAML configuration: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ValueError("Configuration must be a mapping.")
        deep_merge(config, loaded)
    validate_config(config)
    return config


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def validate_config(config: dict[str, Any]) -> None:
    volatility = _mapping(config, "volatility")
    if not str(volatility.get("command", "")).strip():
        raise ValueError("volatility.command must not be empty.")
    if str(volatility.get("renderer", "json")).casefold() != "json":
        raise ValueError("RAMScope currently requires volatility.renderer=json.")
    _positive_int(volatility.get("timeout_seconds", 600), "volatility.timeout_seconds")

    execution = _mapping(config, "execution")
    worker_value = execution.get("workers", "auto")
    if str(worker_value).casefold() != "auto":
        parsed_workers = _positive_int(worker_value, "execution.workers")
        if parsed_workers > 2:
            raise ValueError("execution.workers must be auto, 1, or 2.")
    _positive_int(execution.get("max_parallel_light", 2), "execution.max_parallel_light")
    timeouts = _mapping(execution, "timeouts")
    for key, value in timeouts.items():
        _positive_int(value, f"execution.timeouts.{key}")
    malfind = _mapping(execution, "malfind")
    if str(malfind.get("dump_mode", "targeted")).casefold() not in {"targeted", "all", "none"}:
        raise ValueError("execution.malfind.dump_mode must be targeted, all, or none.")
    _non_negative_int(malfind.get("max_targets", 12), "execution.malfind.max_targets")

    analysis = _mapping(config, "analysis")
    for key in (
        "enable_yara",
        "enable_ioc_extraction",
        "enable_risk_scoring",
        "enable_html_report",
        "enable_pdf_report",
        "enable_full_artifact_dumps",
    ):
        if not isinstance(analysis.get(key), bool):
            raise ValueError(f"analysis.{key} must be true or false.")
    _positive_int(analysis.get("yara_timeout_seconds", 60), "analysis.yara_timeout_seconds")
    external = _mapping(analysis, "external_tools")
    _positive_int(external.get("timeout_seconds", 120), "analysis.external_tools.timeout_seconds")
    _positive_int(external.get("max_file_size_mb", 100), "analysis.external_tools.max_file_size_mb")
    _positive_int(external.get("max_output_mb", 32), "analysis.external_tools.max_output_mb")

    _positive_int(config.get("risk_total_score_cap", 100), "risk_total_score_cap")
    for name, value in _mapping(config, "risk_weights").items():
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"risk_weights.{name} must be numeric.") from exc
        if parsed < 0:
            raise ValueError(f"risk_weights.{name} must be non-negative.")
    for name, value in _mapping(config, "risk_category_caps").items():
        _non_negative_int(value, f"risk_category_caps.{name}")


def enabled_plugins(
    config: dict[str, Any],
    include_deep: bool = False,
    include_full: bool = False,
    include_dump_artifacts: bool = False,
) -> list[str]:
    plugins = [name for name, enabled in _mapping(config, "plugins").items() if bool(enabled)]
    if include_deep or include_full:
        plugins.extend(DEEP_PLUGINS)
    if include_full:
        plugins.extend(FULL_PLUGINS)
    if include_full and include_dump_artifacts:
        plugins.extend(FULL_DUMP_PLUGINS)
    return list(dict.fromkeys(plugins))


def plugin_args_for(config: dict[str, Any], plugin: str) -> list[str]:
    args = _mapping(config, "plugin_args").get(plugin, [])
    return [str(item) for item in ([args] if isinstance(args, str) else (args or []))]


def plugin_dump_args_for(config: dict[str, Any], plugin: str) -> list[str]:
    args = _mapping(config, "plugin_dump_args").get(plugin, [])
    return [str(item) for item in ([args] if isinstance(args, str) else (args or []))]


def _mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a mapping.")
    return value


def _positive_int(value: Any, name: str) -> int:
    parsed = _non_negative_int(value, name)
    if parsed < 1:
        raise ValueError(f"{name} must be greater than zero.")
    return parsed


def _non_negative_int(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be non-negative.")
    return parsed
