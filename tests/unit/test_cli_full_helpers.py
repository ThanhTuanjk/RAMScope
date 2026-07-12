import json
from pathlib import Path

from ramscope.cli import _normalize_and_analyze, _plugin_skip_reason, _runtime_plugin_args, _should_capture_dump
from ramscope.config import DEFAULT_CONFIG
from ramscope.models import PluginStatus


def test_vadyarascan_gets_yara_file_from_rule_paths(tmp_path: Path) -> None:
    rule = tmp_path / "triage.yar"
    rule.write_text("rule T { condition: true }", encoding="utf-8")
    args = _runtime_plugin_args(DEFAULT_CONFIG, "windows.vadyarascan", [tmp_path])
    assert args == ["--yara-file", str(rule)]
    assert _plugin_skip_reason("windows.vadyarascan", args) == ""


def test_vadyarascan_skips_without_rule_source() -> None:
    args = _runtime_plugin_args(DEFAULT_CONFIG, "windows.vadyarascan", [])
    assert _plugin_skip_reason("windows.vadyarascan", args)


def test_dump_capture_policy() -> None:
    assert _should_capture_dump("windows.malfind", no_malfind_dump=False, include_dump_artifacts=False)
    assert not _should_capture_dump("windows.malfind", no_malfind_dump=True, include_dump_artifacts=True)
    assert _should_capture_dump("windows.memmap", no_malfind_dump=False, include_dump_artifacts=True)
    assert not _should_capture_dump("windows.memmap", no_malfind_dump=False, include_dump_artifacts=False)


def test_malformed_plugin_json_is_recorded_without_crashing(tmp_path: Path) -> None:
    raw = tmp_path / "raw" / "volatility"
    raw.mkdir(parents=True)
    (raw / "windows.pslist.json").write_text("{broken", encoding="utf-8")
    _normalize_and_analyze(
        tmp_path, [], [PluginStatus("windows.pslist", "success")],
        external_tools={"enable_floss": False, "enable_capa": False, "enable_clamav": False, "enable_die": False, "enable_pefile": False},
    )
    warnings = json.loads((tmp_path / "normalized" / "parser_warnings.json").read_text(encoding="utf-8"))
    assert any(item["artifact"] == "processes" and "Could not parse" in item["warning"] for item in warnings)
