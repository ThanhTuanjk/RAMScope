from __future__ import annotations

import ipaddress
from typing import Any

from ramscope.models import Finding, ProcessProfile


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


class NetworkAnalyzer:
    def __init__(self, baseline: dict[str, Any] | None = None) -> None:
        baseline = baseline or {}
        self.network_heavy = {str(item).lower() for item in baseline.get("network_heavy_processes", [])}

    def analyze(self, profiles: list[ProcessProfile]) -> list[Finding]:
        findings = []
        for profile in profiles:
            public_connections = [conn for conn in profile.network_connections if is_public_ip(conn.remote_addr)]
            if not public_connections:
                continue
            suspicious_context = _suspicious_process_context(profile)
            if profile.malfind_regions:
                sample = public_connections[0]
                findings.append(Finding(
                    "", profile.pid, profile.name, "Public network activity from a process with a malfind indicator", "High", 65, "possible", "network",
                    [{"source": "windows.netscan/windows.malfind", "detail": f"{len(public_connections)} public endpoint(s); sample={sample.remote_addr}:{sample.remote_port} state={sample.state}"}],
                    "Correlate endpoint timing, VAD address, dumped bytes, DNS/proxy logs, and threat intelligence before concluding C2 activity.", occurrence_count=len(public_connections),
                ))
            elif suspicious_context and profile.name.lower() not in self.network_heavy:
                sample = public_connections[0]
                findings.append(Finding(
                    "", profile.pid, profile.name, "Public network endpoint with suspicious process context", "Medium", 35, "possible", "network",
                    [{"source": "windows.netscan", "detail": f"{len(public_connections)} public endpoint(s); sample={sample.remote_addr}:{sample.remote_port} state={sample.state}"}],
                    "A public IP is not malicious by itself. Validate command line, process path, endpoint ownership, timing, and network telemetry.", occurrence_count=len(public_connections),
                ))
        return findings


def _suspicious_process_context(profile: ProcessProfile) -> bool:
    text = f"{profile.image_path} {profile.command_line}".lower()
    return any(token in text for token in ("\\appdata\\", "\\temp\\", "\\users\\public\\", " -enc", "-encodedcommand", "frombase64string", " iex", "javascript:", "http://", "https://"))
