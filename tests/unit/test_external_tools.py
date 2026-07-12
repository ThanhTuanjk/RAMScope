from pathlib import Path

from ramscope.analyzers.external_tools import ExternalToolAnalyzer


def test_external_tools_disabled_do_not_require_optional_binaries(tmp_path: Path) -> None:
    dump_dir = tmp_path / "dumps"
    dump_dir.mkdir()
    (dump_dir / "pid.4120.dmp").write_bytes(b"MZ" + b"\x00" * 256)

    findings, status, suspicious_strings = ExternalToolAnalyzer(
        enable_floss=False,
        enable_capa=False,
        enable_clamav=False,
        enable_die=False,
        enable_pefile=False,
    ).analyze(dump_dir, tmp_path / "external_tools")

    assert findings == []
    assert suspicious_strings == []
    assert (tmp_path / "external_tools" / "status.json").exists()
    assert {row["tool"] for row in status} >= {"floss", "capa", "clamav", "die", "pefile"}
