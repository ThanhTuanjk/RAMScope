from ramscope.analyzers.network_analyzer import NetworkAnalyzer
from ramscope.analyzers.persistence_analyzer import PersistenceAnalyzer
from ramscope.models import Finding, NetworkArtifact, ProcessProfile
from ramscope.scoring.risk_scorer import RiskScorer


def test_risk_scorer_caps_external_tool_category() -> None:
    profile = ProcessProfile(
        pid=4120,
        name="sample.exe",
        findings=[
            Finding("", 4120, "sample.exe", "FLOSS strings", "Medium", 40, "medium", "strings"),
            Finding("", 4120, "sample.exe", "capa capability", "Medium", 40, "medium", "capability"),
            Finding("", 4120, "sample.exe", "ClamAV hit", "High", 70, "medium", "av"),
            Finding("", 4120, "sample.exe", "packer hint", "Medium", 40, "medium", "packer"),
            Finding("", 4120, "sample.exe", "PE metadata", "Medium", 40, "medium", "pe_metadata"),
        ],
    )
    RiskScorer().score([profile])
    assert profile.risk_score == 45
    assert any("category cap" in reason for reason in profile.score_reasons)


def test_public_ip_from_browser_is_ioc_context_not_automatic_finding() -> None:
    profile = ProcessProfile(
        pid=100,
        name="chrome.exe",
        network_connections=[NetworkArtifact(100, "chrome.exe", "TCPv4", "10.0.0.2", 50000, "8.8.8.8", 443, "ESTABLISHED")],
    )
    findings = NetworkAnalyzer({"network_heavy_processes": ["chrome.exe"]}).analyze([profile])
    assert findings == []


def test_normal_system_service_is_not_persistence_finding() -> None:
    profile = ProcessProfile(
        pid=700,
        name="svchost.exe",
        persistence_links=[{"source_plugin": "windows.svcscan", "binary": r"C:\Windows\System32\svchost.exe -k netsvcs"}],
    )
    assert PersistenceAnalyzer().analyze([profile]) == []
