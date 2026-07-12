from ramscope.analyzers.full_analyzer import FullAnalyzer


def test_full_analyzer_flags_vadyara_and_suspicious_mutex() -> None:
    findings = FullAnalyzer().analyze({
        "vadyarascan": [{"pid": 4120, "process_name": "rundll32.exe", "details": "rule=SUSP_Test address=0x1000"}],
        "mutantscan": [{"name": "Global\\cobalt_beacon_mutex", "details": "Global\\cobalt_beacon_mutex"}],
    })
    assert any(finding.category == "vadyara" and finding.pid == 4120 for finding in findings)
    assert any(finding.category == "mutex" for finding in findings)


def test_module_scan_difference_alone_is_not_rootkit_finding() -> None:
    findings = FullAnalyzer().analyze({
        "modules": [{"name": "ntoskrnl.exe"}],
        "modscan": [{"name": "ntoskrnl.exe"}, {"name": "orphan.sys"}],
    })
    assert not any(finding.category == "kernel" for finding in findings)


def test_module_scan_difference_with_suspicious_driver_context_is_flagged() -> None:
    findings = FullAnalyzer().analyze({
        "modules": [{"name": "ntoskrnl.exe"}],
        "modscan": [{"name": "orphan.sys"}],
        "driverscan": [{"name": "orphan.sys", "path": r"C:\Users\Public\orphan.sys", "details": r"orphan.sys C:\Users\Public\orphan.sys driver"}],
    })
    assert any(finding.category == "kernel" for finding in findings)


def test_plain_kernel_rows_are_not_flagged() -> None:
    findings = FullAnalyzer().analyze({
        "driverscan": [{"name": "kbdclass.sys", "path": r"C:\Windows\System32\drivers\kbdclass.sys"}],
        "callbacks": [{"module": "ntoskrnl.exe", "details": "Process callback ntoskrnl.exe"}],
    })
    assert findings == []
