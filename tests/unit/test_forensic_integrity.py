from __future__ import annotations

import json
from pathlib import Path

import pytest

from ramscope.analyzers.correlator import Correlator
from ramscope.analyzers.yara_scanner import YaraScanner, prepare_yara_rule_pack
from ramscope.case.case_manager import CaseManager
from ramscope.cli import _builtin_yara_rules_dir, _cache_output_valid, _config_sha256
from ramscope.models import NetworkArtifact, PluginStatus
from ramscope.parsers.full_parser import CallbackParser, DriverParser, TimelineParser, VadYaraParser
from ramscope.parsers.process_parser import ProcessParser
from ramscope.volatility.command_builder import VolatilityCommandBuilder
from ramscope.volatility.plugin_plan import REGISTRY_JOBS, resolve_plugin
from ramscope.volatility.runner import VolatilityRunner


def test_process_identity_and_pid_reuse_do_not_cross_contaminate() -> None:
    processes = [
        {"pid": 444, "ppid": 4, "name": "same.exe", "create_time": "2026-01-01 10:00:00", "eprocess_offset": "0x1000", "process_key": "eprocess:0x1000", "source_plugin": "windows.pslist"},
        {"pid": 444, "ppid": 4, "name": "same.exe", "create_time": "2026-01-01 11:00:00", "eprocess_offset": "0x2000", "process_key": "eprocess:0x2000", "source_plugin": "windows.psscan"},
    ]
    network = [NetworkArtifact(444, "same.exe", "TCPv4", "10.0.0.1", 50000, "8.8.8.8", 443, "ESTABLISHED")]
    profiles = Correlator().build_profiles(processes, [], [], network, [])
    real = [profile for profile in profiles if profile.process_key.startswith("eprocess:")]
    unresolved = [profile for profile in profiles if profile.process_key.endswith("|unresolved")]
    assert len(real) == 2
    assert len(unresolved) == 1
    assert unresolved[0].network_connections[0].remote_addr == "8.8.8.8"
    assert not real[0].network_connections and not real[1].network_connections
    assert all(profile.identity_ambiguous for profile in profiles)


def test_process_parser_prefers_eprocess_identity(tmp_path: Path) -> None:
    source = tmp_path / "pslist.json"
    source.write_text(json.dumps([{"PID": 7, "PPID": 4, "ImageFileName": "x.exe", "Offset(V)": "0xabc", "CreateTime": "2026-01-01"}]), encoding="utf-8")
    row = ProcessParser().parse_file(source)[0]
    assert row["process_key"] == "eprocess:0xabc"


def test_resume_requires_same_evidence_config_and_profile(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory-evidence")
    manager = CaseManager(tmp_path / "cases")
    case_dir, first = manager.create_case("CASE-1", evidence, "vol", config_sha256="abc", analysis_profile="deep")
    resumed_dir, resumed = manager.create_case("CASE-1", evidence, "vol", resume=True, config_sha256="abc", analysis_profile="deep")
    assert resumed_dir == case_dir and resumed.sha256 == first.sha256
    with pytest.raises(ValueError, match="configuration hash"):
        manager.create_case("CASE-1", evidence, "vol", resume=True, config_sha256="different", analysis_profile="deep")
    with pytest.raises(ValueError, match="analysis profile"):
        manager.create_case("CASE-1", evidence, "vol", resume=True, config_sha256="abc", analysis_profile="full")


def test_specialized_full_parsers_preserve_semantics(tmp_path: Path) -> None:
    source = tmp_path / "rows.json"
    source.write_text(json.dumps([{"PID": 9, "Process": "p.exe", "DriverName": "evil.sys", "ImagePath": "C:\\\\Temp\\\\evil.sys", "Callback": "0x123", "Rule": "R1", "Created Date": "2026-01-01", "Description": "event"}]), encoding="utf-8")
    assert DriverParser("windows.driverscan").parse_file(source)[0]["path"].lower().endswith("evil.sys")
    assert CallbackParser().parse_file(source)[0]["address"] == "0x123"
    assert VadYaraParser().parse_file(source)[0]["rule"] == "R1"
    assert TimelineParser().parse_file(source)[0]["timestamp"] == "2026-01-01"


def test_registry_jobs_resolve_to_printkey() -> None:
    available = {"windows.registry.printkey"}
    assert all(resolve_plugin(job, available) == "windows.registry.printkey" for job in REGISTRY_JOBS)


def test_runtime_builtin_yara_rules_are_packaged() -> None:
    rules_dir = _builtin_yara_rules_dir()
    assert rules_dir.is_dir()
    assert len(list(rules_dir.glob("*.yar"))) >= 5


def test_yara_pack_records_valid_invalid_and_scan_provenance(tmp_path: Path) -> None:
    pytest.importorskip("yara")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "good.yar").write_text('rule GoodRule { strings: $a = "RAMSCOPE_TEST" condition: $a }', encoding="utf-8")
    (rules / "bad.yar").write_text("rule Broken { condition: }", encoding="utf-8")
    compiled, status = prepare_yara_rule_pack([rules], tmp_path / "normalized" / "yara")
    assert compiled and compiled.is_file()
    assert status["valid_files"] == 1 and status["invalid_files"] == 1
    target = tmp_path / "dumps"
    target.mkdir()
    (target / "pid.123.dmp").write_bytes(b"RAMSCOPE_TEST")
    scanner = YaraScanner([rules], compiled_path=compiled, timeout_seconds=5)
    findings = scanner.scan_directory(target)
    assert findings and scanner.last_status["matches"] == 1
    assert scanner.last_status["targets"][0]["sha256"]


def test_runner_records_command_timing_and_hashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        def __init__(self, *args, stdout=None, stderr=None, **kwargs):
            stdout.write('[{"PID": 4}]')
            self.returncode = 0

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr("ramscope.volatility.runner.subprocess.Popen", FakeProcess)
    runner = VolatilityRunner(VolatilityCommandBuilder("vol"), timeout_seconds=5)
    result = runner.run_plugin(tmp_path / "memory.raw", "windows.pslist", tmp_path / "raw")
    assert result.succeeded
    assert result.command[-1] == "windows.pslist"
    assert result.started_at and result.finished_at and result.duration_seconds >= 0
    assert len(result.stdout_sha256) == 64


def test_runtime_fingerprint_and_cache_integrity(tmp_path: Path) -> None:
    assert _config_sha256({"a": 1}, {"profile": "deep"}) != _config_sha256({"a": 1}, {"profile": "full"})
    raw = tmp_path / "windows.pslist.json"
    raw.write_text("[]\n", encoding="utf-8")
    import hashlib
    expected = hashlib.sha256(raw.read_bytes()).hexdigest()
    dump = tmp_path / "pid.4.dmp"
    dump.write_bytes(b"dump")
    dump_hash = hashlib.sha256(dump.read_bytes()).hexdigest()
    status = PluginStatus("windows.pslist", "success", stdout_sha256=expected, dump_hashes={str(dump): dump_hash})
    assert _cache_output_valid(status, raw)
    dump.write_bytes(b"tampered dump")
    assert not _cache_output_valid(status, raw)
    dump.write_bytes(b"dump")
    raw.write_text("tampered", encoding="utf-8")
    assert not _cache_output_valid(status, raw)
