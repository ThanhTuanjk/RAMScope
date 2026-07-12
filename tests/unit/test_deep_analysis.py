from ramscope.analyzers.deep_analyzer import DeepAnalyzer
from ramscope.models import MalfindArtifact, ProcessProfile


def test_deep_analyzer_flags_lolbin_executable_vad_with_strong_context() -> None:
    profile = ProcessProfile(
        pid=4120,
        name="rundll32.exe",
        command_line=r"rundll32.exe C:\Users\Public\payload.dll,Start",
        malfind_regions=[MalfindArtifact(4120, "rundll32.exe", "0x1000", "0x2000", "PAGE_EXECUTE_READWRITE", "VadS", True)],
    )
    findings = DeepAnalyzer().analyze(
        [profile], [],
        [{"pid": 4120, "vad_start": "0x1000", "vad_end": "0x2000", "protection": "PAGE_EXECUTE_READWRITE", "file_output": ""}],
        [], [],
    )
    assert any(finding.category == "deep_memory" for finding in findings)


def test_psscan_only_terminated_process_is_not_called_hidden() -> None:
    profile = ProcessProfile(pid=88, name="old.exe", exit_time="2026-01-01 00:00:00", observed_in=["windows.psscan"])
    findings = DeepAnalyzer().analyze([profile], [], [], [], [], [{"pid": 88}], [], {})
    assert not any(finding.category == "process_cross_view" for finding in findings)


def test_active_psscan_discrepancy_requires_corroboration() -> None:
    profile = ProcessProfile(
        pid=4120,
        name="rundll32.exe",
        observed_in=["windows.psscan"],
        malfind_regions=[MalfindArtifact(4120, "rundll32.exe", "0x1000", "0x2000", "PAGE_EXECUTE_READWRITE", "VadS", True)],
    )
    psxview = [{"pid": 4120, "pslist": False, "psscan": True}]
    findings = DeepAnalyzer().analyze([profile], [], [], [], [], [{"pid": 4120}], psxview, {})
    assert any(finding.category == "process_cross_view" for finding in findings)
