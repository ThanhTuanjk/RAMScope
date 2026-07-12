from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

import ramscope.cli as cli_module
import ramscope.volatility.runner as runner_module
from ramscope.cli import _config_hash, app
from ramscope.config import load_config, plugin_args_for
from ramscope.models import Finding, IOC, PluginStatus, ProcessProfile, TargetInfo
from ramscope.reliable_pipeline import _attach_and_score, analyze_case
from ramscope.reporting.reliable_report import write_reports
from ramscope.utils.json_utils import read_json, write_json
from ramscope.volatility.command_builder import VolatilityCommandBuilder
from ramscope.volatility.runner import PluginRunResult, VolatilityRunner


def _write_raw(case_dir: Path, plugin: str, rows: list[dict[str, Any]]) -> Path:
    path = case_dir / "raw" / "volatility" / f"{plugin}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _disable_external_tools(cfg: dict[str, Any]) -> None:
    cfg["analysis"]["external_tools"].update(
        {
            "enable_floss": False,
            "enable_capa": False,
            "enable_clamav": False,
            "enable_die": False,
            "enable_pefile": False,
        }
    )


def test_runner_blank_success_writes_valid_json_with_real_newline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        pid = 12345

        def __init__(self, command: list[str], **kwargs: Any) -> None:
            self.returncode = 0
            self._stdout = kwargs["stdout"]
            self._stderr = kwargs["stderr"]

        def wait(self, timeout: int | None = None) -> int:
            del timeout
            self._stdout.flush()
            self._stderr.flush()
            return 0

        def poll(self) -> int:
            return 0

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(runner_module.subprocess, "Popen", FakeProcess)
    runner = VolatilityRunner(VolatilityCommandBuilder("fake-vol"), timeout_seconds=5)
    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"memory")

    result = runner.run_plugin(memory, "windows.info", tmp_path / "raw")

    assert result.succeeded
    assert result.output_path is not None
    assert result.output_path.read_bytes() == b"[]\n"
    assert json.loads(result.output_path.read_text(encoding="utf-8")) == []


def test_runner_timeout_log_uses_real_newlines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeTimeoutProcess:
        pid = 12345

        def __init__(self, command: list[str], **kwargs: Any) -> None:
            self.returncode = None
            self._stdout = kwargs["stdout"]
            self._stderr = kwargs["stderr"]

        def wait(self, timeout: int | None = None) -> int:
            del timeout
            raise runner_module.subprocess.TimeoutExpired(["fake-vol"], 1)

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(runner_module.subprocess, "Popen", FakeTimeoutProcess)
    monkeypatch.setattr(runner_module, "_terminate_process_tree", lambda process: None)
    runner = VolatilityRunner(VolatilityCommandBuilder("fake-vol"), timeout_seconds=1)
    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"memory")

    result = runner.run_plugin(memory, "windows.info", tmp_path / "raw")

    assert result.timed_out
    assert result.error_path is not None
    error = result.error_path.read_text(encoding="utf-8")
    assert "Plugin timed out after 1 seconds.\nCommand:" in error
    assert "\\nCommand:" not in error


def test_default_registry_keys_and_baseline_paths_have_single_separators() -> None:
    cfg = load_config()
    assert plugin_args_for(cfg, "windows.registry.printkey_run") == [
        "--key",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ]
    roots = cfg["analysis"]["baseline"]["trusted_system_roots"]
    assert "c:\\windows\\system32\\" in roots
    assert all("\\\\" not in value for value in roots)


def test_mutex_detection_accepts_normal_windows_separator(tmp_path: Path) -> None:
    _write_raw(tmp_path, "windows.mutantscan", [{"Name": r"Global\MSSE", "Offset": "0x100"}])
    status = PluginStatus("windows.mutantscan", "success")

    result = analyze_case(tmp_path, [status], load_config())

    assert any("mutex" in finding.title.casefold() for finding in result.findings)
    assert status.analysis_status == "observed"


def test_invalid_format_is_rejected_before_case_creation(tmp_path: Path) -> None:
    runner = CliRunner()
    output_root = tmp_path / "cases"
    result = runner.invoke(
        app,
        ["analyze", "--input", str(tmp_path / "missing.raw"), "--case", "BAD", "--output", str(output_root), "--format", "banana"],
    )
    assert result.exit_code != 0
    assert "--format must be" in result.output
    assert not output_root.exists()


def test_html_disabled_is_rejected_before_case_creation(tmp_path: Path) -> None:
    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"memory")
    cfg = load_config()
    cfg["analysis"]["enable_html_report"] = False
    _disable_external_tools(cfg)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    output_root = tmp_path / "cases"

    result = CliRunner().invoke(
        app,
        ["analyze", "--input", str(memory), "--case", "HTML-OFF", "--output", str(output_root), "--config", str(config_path), "--format", "html"],
    )

    assert result.exit_code != 0
    assert "HTML reporting is disabled" in result.output
    assert not output_root.exists()


def test_enable_yara_false_skips_rule_snapshot_and_compilation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"memory")
    cfg = load_config()
    cfg["analysis"]["enable_yara"] = False
    cfg["execution"]["malfind"]["dump_mode"] = "none"
    _disable_external_tools(cfg)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")

    monkeypatch.setattr(cli_module.VolatilityRunner, "is_available", lambda self: False)
    monkeypatch.setattr(cli_module.VolatilityRunner, "available_plugins", lambda self: set())
    monkeypatch.setattr(cli_module.VolatilityRunner, "version_text", lambda self: "unavailable")

    output_root = tmp_path / "cases"
    result = CliRunner().invoke(
        app,
        ["analyze", "--input", str(memory), "--case", "YARA-OFF", "--output", str(output_root), "--config", str(config_path), "--format", "md"],
    )

    assert result.exit_code == 0, result.output
    case_dir = output_root / "YARA-OFF"
    manifest = read_json(case_dir / "evidence" / "yara_manifest.json")
    assert manifest["enabled"] is False
    assert manifest["files"] == []
    assert not (case_dir / "evidence" / "yara_rules").exists()
    assert not (case_dir / "normalized" / "yara" / "compiled_rules.yarac").exists()


def test_hollowing_and_ghosting_rows_survive_normalization_and_create_cautious_leads(tmp_path: Path) -> None:
    _write_raw(tmp_path, "windows.pslist", [{"PID": 1337, "ImageFileName": "sample.exe", "Offset(V)": "0x1337"}])
    _write_raw(
        tmp_path,
        "windows.hollowprocesses",
        [{"PID": 1337, "Process": "sample.exe", "Hollowed": True, "Notes": "PEB image base differs from mapped image"}],
    )
    _write_raw(
        tmp_path,
        "windows.processghosting",
        [
            {
                "PID": 1337,
                "Process": "sample.exe",
                "FILE_OBJECT": "0xffff8000",
                "DeletePending": True,
                "DeleteOnClose": False,
                "Path": r"C:\Users\Public\ghost.exe",
            }
        ],
    )
    statuses = [
        PluginStatus("windows.pslist", "success"),
        PluginStatus("windows.hollowprocesses", "success"),
        PluginStatus("windows.processghosting", "success"),
    ]

    result = analyze_case(tmp_path, statuses, load_config())

    titles = {finding.title for finding in result.findings}
    assert "Possible process hollowing candidate requires validation" in titles
    assert "Possible process ghosting candidate requires validation" in titles
    assert all("confirmed" not in title.casefold() for title in titles)
    normalized_hollow = read_json(tmp_path / "normalized" / "hollowprocesses.json")
    assert normalized_hollow[0]["hollowed"] is True


def test_scheduled_task_and_timeliner_are_semantically_used(tmp_path: Path) -> None:
    _write_raw(
        tmp_path,
        "windows.registry.scheduled_tasks",
        [
            {
                "TaskName": "Updater",
                "Action": "powershell.exe",
                "Arguments": "-EncodedCommand AAAA",
                "LastRunTime": "2026-07-11 09:10:00 UTC",
            }
        ],
    )
    _write_raw(
        tmp_path,
        "timeliner",
        [
            {
                "Plugin": "windows.registry.scheduled_tasks",
                "Description": "Updater task executed",
                "Created Date": "2026-07-11 09:10:00 UTC",
            }
        ],
    )
    statuses = [PluginStatus("windows.registry.scheduled_tasks", "success"), PluginStatus("timeliner", "success")]

    result = analyze_case(tmp_path, statuses, load_config())

    assert any(finding.category == "persistence" and "Scheduled task" in finding.title for finding in result.findings)
    assert any(event.event_type == "scheduled_task" for event in result.timeline)
    assert any(event.source == "timeliner" and "Updater task executed" in event.detail for event in result.timeline)
    assert statuses[0].analysis_status == "analyzed"
    assert statuses[1].analysis_status == "analyzed"


def test_same_dump_multiple_tools_do_not_count_as_independent_corroboration() -> None:
    profile = ProcessProfile(pid=7, name="sample.exe", process_key="eprocess:7")
    memory = Finding(
        "",
        7,
        "sample.exe",
        "memory",
        "Medium",
        25,
        "possible",
        category="memory",
        signal_groups=["memory"],
        process_key=profile.process_key,
        provenance_ids=["dump:abc"],
    )
    signature = Finding(
        "",
        7,
        "sample.exe",
        "signature",
        "Low",
        15,
        "possible",
        category="signature",
        signal_groups=["signature"],
        process_key=profile.process_key,
        provenance_ids=["dump:abc"],
    )
    findings = [memory, signature]

    _attach_and_score([profile], findings, load_config())

    assert not any(item.disposition == "corroborated" for item in findings)
    assert profile.severity != "High"


def test_independent_memory_and_network_provenance_creates_correlation() -> None:
    profile = ProcessProfile(pid=7, name="sample.exe", process_key="eprocess:7")
    findings = [
        Finding(
            "",
            7,
            "sample.exe",
            "memory",
            "Medium",
            25,
            "possible",
            category="memory",
            signal_groups=["memory"],
            process_key=profile.process_key,
            provenance_ids=["vad:eprocess:7:0x1000:0x2000"],
        ),
        Finding(
            "",
            7,
            "sample.exe",
            "network",
            "Medium",
            20,
            "possible",
            category="network",
            signal_groups=["network"],
            process_key=profile.process_key,
            provenance_ids=["network:eprocess:7:8.8.8.8:443"],
        ),
    ]

    _attach_and_score([profile], findings, load_config())

    correlation = [item for item in findings if item.disposition == "corroborated"]
    assert len(correlation) == 1
    assert correlation[0].severity == "High"


def test_report_counts_actionable_and_candidate_iocs_separately(tmp_path: Path) -> None:
    iocs = [
        IOC("ip", "8.8.8.8", "network", actionability="candidate"),
        IOC("domain", "evil.example", "cmdline", actionability="actionable"),
    ]
    path = write_reports(tmp_path, {}, [], [], iocs, [], TargetInfo(), [], "md")[0]
    report = path.read_text(encoding="utf-8")

    assert "- Actionable IOCs: 1" in report
    assert "- Candidate IOCs: 1" in report
    assert "evil[.]example" in report
    assert "8[.]8[.]8[.]8" in report
    assert "No actionable IOC was extracted" not in report


def test_config_fingerprint_changes_when_rule_hash_or_runtime_flag_changes() -> None:
    cfg = load_config()
    runtime_a = {"yara_rules": [{"path": "rule.yar", "sha256": "a"}], "dump_artifacts": False}
    runtime_b = {"yara_rules": [{"path": "rule.yar", "sha256": "b"}], "dump_artifacts": False}
    runtime_c = {"yara_rules": [{"path": "rule.yar", "sha256": "a"}], "dump_artifacts": True}

    assert _config_hash(cfg, runtime_a) != _config_hash(cfg, runtime_b)
    assert _config_hash(cfg, runtime_a) != _config_hash(cfg, runtime_c)


def test_atomic_json_write_replaces_file_and_leaves_no_temporary_files(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "artifact.json"
    write_json(target, {"version": 1})
    write_json(target, {"version": 2})

    assert read_json(target) == {"version": 2}
    assert list(target.parent.glob(f".{target.name}.*.tmp")) == []


def test_reassess_reuses_original_config_and_does_not_modify_source_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows_by_plugin: dict[str, list[dict[str, Any]]] = {
        "windows.info": [{"NtBuildLab": "19045.1.amd64fre"}],
        "windows.pslist": [{"PID": 77, "PPID": 4, "ImageFileName": "sample.exe", "Offset(V)": "0x77"}],
        "windows.pstree": [{"PID": 77, "PPID": 4, "ImageFileName": "sample.exe", "Offset(V)": "0x77"}],
        "windows.cmdline": [{"PID": 77, "Process": "sample.exe", "Args": "sample.exe https://evil.example"}],
        "windows.dlllist": [],
        "windows.netscan": [{"PID": 77, "Owner": "sample.exe", "Proto": "TCPv4", "ForeignAddr": "8.8.8.8", "ForeignPort": 443, "State": "ESTABLISHED"}],
        "windows.malfind": [{"PID": 77, "Process": "sample.exe", "Start VPN": "0x1000", "End VPN": "0x2000", "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d 5a"}],
    }

    available = {
        "windows.info.Info",
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.cmdline.CmdLine",
        "windows.dlllist.DllList",
        "windows.netscan.NetScan",
        "windows.malware.malfind.Malfind",
    }

    def fake_is_available(self: VolatilityRunner) -> bool:
        return True

    def fake_available_plugins(self: VolatilityRunner) -> set[str]:
        return set(available)

    def fake_version(self: VolatilityRunner) -> str:
        return "test-volatility"

    def fake_run_plugin(
        self: VolatilityRunner,
        input_file: Path,
        plugin: str,
        raw_dir: Path,
        **kwargs: Any,
    ) -> PluginRunResult:
        del self, input_file, kwargs
        raw_dir.mkdir(parents=True, exist_ok=True)
        output_path = raw_dir / f"{plugin}.json"
        output_path.write_text(json.dumps(rows_by_plugin.get(plugin, [])) + "\n", encoding="utf-8")
        return PluginRunResult(
            plugin=plugin,
            command=["fake-vol", plugin],
            return_code=0,
            output_path=output_path,
            error_path=None,
            stdout_sha256=_hash(output_path),
        )

    monkeypatch.setattr(cli_module.VolatilityRunner, "is_available", fake_is_available)
    monkeypatch.setattr(cli_module.VolatilityRunner, "available_plugins", fake_available_plugins)
    monkeypatch.setattr(cli_module.VolatilityRunner, "version_text", fake_version)
    monkeypatch.setattr(cli_module.VolatilityRunner, "run_plugin", fake_run_plugin)

    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"memory")
    cfg = load_config()
    cfg["volatility"]["command"] = "fake-vol"
    cfg["analysis"]["enable_yara"] = False
    cfg["analysis"]["enable_ioc_extraction"] = False
    cfg["analysis"]["enable_risk_scoring"] = False
    cfg["execution"]["malfind"]["dump_mode"] = "none"
    _disable_external_tools(cfg)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    output_root = tmp_path / "cases"

    runner = CliRunner()
    first = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(memory),
            "--case",
            "REASSESS",
            "--output",
            str(output_root),
            "--config",
            str(config_path),
            "--format",
            "md",
        ],
    )
    assert first.exit_code == 0, first.output
    source_case = output_root / "REASSESS"
    source_hashes = {
        str(path.relative_to(source_case)): _hash(path)
        for root in (source_case / "normalized", source_case / "iocs")
        for path in root.rglob("*")
        if path.is_file()
    }
    original_profiles = read_json(source_case / "normalized" / "process_profiles.json")
    assert original_profiles[0]["risk_score"] == 0
    assert read_json(source_case / "iocs" / "iocs.json") == []

    second = runner.invoke(app, ["reassess", "--case", str(source_case), "--format", "md"])
    assert second.exit_code == 0, second.output

    after_hashes = {
        str(path.relative_to(source_case)): _hash(path)
        for root in (source_case / "normalized", source_case / "iocs")
        for path in root.rglob("*")
        if path.is_file()
    }
    assert after_hashes == source_hashes
    destinations = sorted((source_case / "reassessments").iterdir())
    assert len(destinations) == 1
    reassessed = destinations[0]
    reassessed_profiles = read_json(reassessed / "normalized" / "process_profiles.json")
    assert reassessed_profiles[0]["risk_score"] == 0
    assert read_json(reassessed / "iocs" / "iocs.json") == []
    reassessment_manifest = read_json(reassessed / "reassessment_manifest.json")
    assert reassessment_manifest["integrity_verified"] is True
