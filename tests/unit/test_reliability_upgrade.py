import json

from ramscope.cli import _external_tool_settings, _verify_case_artifacts
from ramscope.config import load_config
from ramscope import execution
from ramscope.execution import lane, run_jobs
from ramscope.models import Finding, PluginStatus, ProcessProfile, TargetInfo
from ramscope.reliable_pipeline import _attach_and_score, analyze_case
from ramscope.reporting.reliable_report import write_reports
from ramscope.utils.forensic import is_absolute_windows_path, is_system_path, optional, same_windows_path
from ramscope.volatility.command_builder import VolatilityCommandBuilder
from ramscope.volatility.runner import VolatilityRunner


def _write(case, plugin, rows):
    target = case / "raw" / "volatility"
    target.mkdir(parents=True, exist_ok=True)
    (target / f"{plugin}.json").write_text(json.dumps(rows), encoding="utf-8")


def test_sentinel_and_device_path_normalization():
    assert optional("Disabled") is None
    assert optional(" N/A ") is None
    assert same_windows_path(r"\Device\HarddiskVolume3\Windows\System32\wbem\WmiPrvSE.exe", r"C:\Windows\System32\wbem\wmiprvse.exe")


def test_windows_path_normalization_accepts_real_windows_paths():
    assert is_absolute_windows_path(r"C:\Windows\System32\svchost.exe")
    assert is_system_path(r"c:\windows\system32\LSASS.EXE")
    assert is_system_path(r"\Device\HarddiskVolume3\Windows\System32\services.exe")
    assert not is_system_path(r"C:\Users\User\AppData\malware.exe")
    assert not is_system_path(r"C:\Windows\Temp\svchost.exe")


def test_volatility_help_discovery_uses_real_newlines(monkeypatch):
    class Completed:
        returncode = 0
        stdout = "    windows.info.Info  Show OS info\n    windows.pslist.PsList  List processes\n"
        stderr = "    windows.netscan.NetScan  Network connections\n    windows.malware.malfind.Malfind  Find memory\n"
    runner = VolatilityRunner(VolatilityCommandBuilder("vol"))
    monkeypatch.setattr(runner, "_help", lambda: Completed())
    plugins = runner.available_plugins()
    assert {"windows.info.Info", "windows.pslist.PsList", "windows.netscan.NetScan", "windows.malware.malfind.Malfind"}.issubset(plugins)


def test_clean_regressions_do_not_become_high(tmp_path):
    _write(tmp_path, "windows.pslist", [{"PID": 4, "PPID": 0, "ImageFileName": "svchost.exe", "ImagePath": "Disabled", "Offset(V)": "0x10"}])
    _write(tmp_path, "windows.pebmasquerade", [{"PID": 4, "Process": "svchost.exe", "PEB_CommandLine_Spoofed": False, "PEB_ImageFilePath_Spoofed": False}])
    _write(tmp_path, "windows.vadinfo", [{"PID": 4, "Process": "svchost.exe", "Protection": "PAGE_EXECUTE_WRITECOPY", "File output": "Disabled", "PrivateMemory": False}])
    result = analyze_case(tmp_path, [], load_config())
    assert not any(item.severity in {"High", "Critical"} for item in result.findings)
    assert not any("PEB spoofing" in item.title for item in result.findings)
    assert not any("VAD" in item.title for item in result.findings)


def test_windows_11_profile_is_detected_from_build(tmp_path):
    _write(tmp_path, "windows.info", [{"NtBuildLab": "22631.1.amd64fre.ni_release"}])
    result = analyze_case(tmp_path, [], load_config())
    assert result.target.selected_profile == "windows-11"


def test_public_network_plus_memory_lead_is_correlated(tmp_path):
    _write(tmp_path, "windows.pslist", [{"PID": 99, "ImageFileName": "sample.exe", "Offset(V)": "0x99"}])
    _write(tmp_path, "windows.malfind", [{"PID": 99, "Process": "sample.exe", "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d 5a"}])
    _write(tmp_path, "windows.netscan", [{"PID": 99, "Owner": "sample.exe", "Proto": "TCPv4", "ForeignAddr": "45.90.10.20", "ForeignPort": 443, "State": "ESTABLISHED"}])
    result = analyze_case(tmp_path, [], load_config())
    assert any(item.category == "network" for item in result.findings)
    assert any(item.severity == "High" and item.disposition == "corroborated" for item in result.findings)


def test_heavy_jobs_are_sequential_and_result_order_is_deterministic():
    output = run_jobs(["windows.pslist", "windows.malfind", "windows.cmdline"], 2, lambda item: item)
    assert [item[0] for item in output] == ["windows.pslist", "windows.malfind", "windows.cmdline"]
    assert lane("windows.malfind") == "heavy"


def test_auto_workers_require_both_cpu_and_memory(monkeypatch):
    monkeypatch.setattr(execution.os, "cpu_count", lambda: 8)
    monkeypatch.setattr(execution, "_physical_memory_gb", lambda: 4.0)
    assert execution.workers("auto", {"auto_min_cpus": 4, "auto_min_memory_gb": 8}) == 1
    monkeypatch.setattr(execution, "_physical_memory_gb", lambda: 16.0)
    assert execution.workers("auto", {"auto_min_cpus": 4, "auto_min_memory_gb": 8}) == 2


def test_external_tool_cli_switches_are_preserved():
    settings = _external_tool_settings(load_config(), True, False, True, False, True)
    assert settings["enable_floss"] is False
    assert settings["enable_capa"] is True
    assert settings["enable_clamav"] is False
    assert settings["enable_die"] is True
    assert settings["enable_pefile"] is False


def test_full_plugin_is_normalized_and_marked_observed(tmp_path):
    _write(tmp_path, "windows.mutantscan", [{"Name": "ordinary_mutex", "Offset": "0x10"}])
    statuses = [PluginStatus("windows.mutantscan", "success")]
    result = analyze_case(tmp_path, statuses, load_config())
    assert statuses[0].analysis_status == "observed"
    assert any(item.get("plugin") == "windows.mutantscan" for item in result.observed_artifacts)
    assert (tmp_path / "normalized" / "mutantscan.json").is_file()


def test_skipped_or_missing_plugin_output_remains_unassessed(tmp_path):
    skipped = PluginStatus("windows.pslist", "skipped", reason="Volatility unavailable")
    analyze_case(tmp_path, [skipped], load_config())
    assert skipped.analysis_status == "unassessed"
    missing = PluginStatus("windows.pslist", "success")
    analyze_case(tmp_path, [missing], load_config())
    assert missing.status == "partial" and missing.analysis_status == "unassessed"


def test_run_key_requires_exact_key_and_suspicious_value(tmp_path):
    _write(tmp_path, "windows.registry.printkey_run", [
        {"Key": r"Microsoft\Windows\CurrentVersion\Runtime", "Name": "normal", "Data": r"C:\Windows\normal.exe"},
        {"Key": r"Microsoft\Windows\CurrentVersion\Run", "Name": "lead", "Data": r"C:\Users\a\AppData\Local\x.exe"},
    ])
    result = analyze_case(tmp_path, [PluginStatus("windows.registry.printkey_run", "success")], load_config())
    persistence = [item for item in result.findings if item.category == "persistence"]
    assert len(persistence) == 1 and persistence[0].severity == "Medium"


def test_pid_reuse_without_stable_identity_does_not_correlate(tmp_path):
    _write(tmp_path, "windows.pslist", [
        {"PID": 77, "ImageFileName": "first.exe"},
        {"PID": 77, "ImageFileName": "second.exe"},
    ])
    _write(tmp_path, "windows.netscan", [{"PID": 77, "Owner": "first.exe", "ForeignAddr": "8.8.8.8"}])
    result = analyze_case(tmp_path, [], load_config())
    assert len(result.profiles) == 2
    assert all(item.identity_ambiguous for item in result.profiles)
    assert not any(item.network_connections for item in result.profiles)


def test_suppressed_signal_does_not_corroborate_sibling():
    profile = ProcessProfile(pid=1, name="sample.exe", process_key="eprocess:1")
    memory = Finding("", 1, "sample.exe", "memory", "Medium", 20, "possible", category="memory", signal_groups=["memory"], process_key=profile.process_key, disposition="lead")
    signature = Finding("", 1, "sample.exe", "signature", "Low", 10, "possible", category="signature", signal_groups=["signature"], process_key=profile.process_key, disposition="lead", suppressed_reason="security context")
    _attach_and_score([profile], [memory, signature])
    assert memory.severity != "High"


def test_markdown_fields_cannot_forge_report_sections(tmp_path):
    finding = Finding("", 5, "x\n## Forged", "title\n# Forged", "Low", 5, "possible", category="process", disposition="lead")
    paths = write_reports(tmp_path, {"sha256": "a", "md5": "b"}, [], [finding], [], [], TargetInfo(), [], "md")
    report = paths[0].read_text(encoding="utf-8")
    assert "\n## Forged" not in report
    assert "\\# Forged" in report


def test_pdf_report_is_real_when_enabled(tmp_path):
    import pytest
    pytest.importorskip("reportlab")
    paths = write_reports(tmp_path, {}, [], [], [], [], TargetInfo(), [], "pdf", True)
    pdf = paths[-1]
    assert pdf.name == "report.pdf" and pdf.read_bytes().startswith(b"%PDF") and pdf.stat().st_size > 0


def test_analysis_config_flags_change_reliable_pipeline(tmp_path):
    _write(tmp_path, "windows.pslist", [{"PID": 42, "ImageFileName": "sample.exe", "Offset(V)": "0x42"}])
    cfg = load_config()
    cfg["analysis"].update({"enable_yara": False, "enable_ioc_extraction": False, "enable_risk_scoring": False})
    result = analyze_case(tmp_path, [], cfg)
    assert result.iocs == [] and result.profiles[0].risk_score == 0


def test_reassess_integrity_rejects_changed_source_evidence(tmp_path):
    import hashlib
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"original")
    metadata = {"input_file": str(evidence), "file_size_bytes": 8, "sha256": hashlib.sha256(b"original").hexdigest()}
    evidence.write_bytes(b"tampered")
    try:
        _verify_case_artifacts(tmp_path, [PluginStatus("windows.info", "skipped")], metadata)
    except ValueError as exc:
        assert "source evidence changed" in str(exc)
    else:
        raise AssertionError("changed source evidence was accepted")
