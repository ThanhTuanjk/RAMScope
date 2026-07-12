from ramscope.analyzers.ioc_extractor import IOCExtractor
from ramscope.models import NetworkArtifact, ProcessProfile


def test_ioc_extractor_network_ip() -> None:
    profile = ProcessProfile(pid=4120, name="powershell.exe", network_connections=[NetworkArtifact(4120, "powershell.exe", "TCPv4", "192.168.1.10", 49712, "45.90.10.20", 443, "ESTABLISHED")])
    iocs = IOCExtractor().extract([profile])
    assert any(ioc.value == "45.90.10.20" for ioc in iocs)
