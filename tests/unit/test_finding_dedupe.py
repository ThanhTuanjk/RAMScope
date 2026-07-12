from ramscope.cli import _dedupe_findings
from ramscope.models import Finding


def test_dedupe_merges_semantically_equal_findings_and_evidence() -> None:
    first = Finding("", 4120, "powershell.exe", "Suspicious YARA hit", "High", 70, "medium", "yara", [{"source": "rule", "detail": "first"}])
    second = Finding("", 4120, "powershell.exe", "Suspicious YARA hit", "High", 80, "high", "yara", [{"source": "rule", "detail": "second"}])
    deduped = _dedupe_findings([first, second])
    assert len(deduped) == 1
    assert deduped[0].score == 80
    assert deduped[0].confidence == "high"
    assert deduped[0].occurrence_count == 2
    assert len(deduped[0].evidence) == 2
