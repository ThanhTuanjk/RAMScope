from pathlib import Path

from ramscope.models import IOC, PluginStatus, ProcessProfile
from ramscope.reporting.report_generator import ReportGenerator


def test_report_generator_basic_and_defangs_iocs(tmp_path: Path) -> None:
    case_dir = tmp_path / "CASE001"
    outputs = ReportGenerator().generate(
        case_dir,
        {"case_id": "CASE001"},
        [ProcessProfile(pid=1, name="System")],
        [],
        [IOC("url", "http://example.com/a", "cmdline")],
        "html",
        [PluginStatus("windows.apihooks", "unsupported", reason="not installed")],
    )
    assert any(path.name == "report.html" for path in outputs)
    markdown = (case_dir / "reports" / "report.md").read_text(encoding="utf-8")
    assert "hxxp://example[.]com/a" in markdown
    assert "unsupported" in markdown
