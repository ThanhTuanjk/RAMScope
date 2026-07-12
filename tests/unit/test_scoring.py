from ramscope.models import MalfindArtifact, NetworkArtifact, ProcessProfile
from ramscope.scoring.risk_scorer import RiskScorer


def test_risk_scorer_high_profile() -> None:
    profile = ProcessProfile(pid=4120, name="powershell.exe", command_line="powershell.exe -enc SQBFAFgA", malfind_regions=[MalfindArtifact(4120, "powershell.exe", "0x1000", "0x2000", "PAGE_EXECUTE_READWRITE", "VadS", True)], network_connections=[NetworkArtifact(4120, "powershell.exe", "TCPv4", "192.168.1.10", 49712, "45.90.10.20", 443, "ESTABLISHED")])
    RiskScorer().score([profile])
    assert profile.risk_score >= 90
    assert profile.severity == "Critical"
