from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from ramscope.models import IOC, ProcessProfile
from ramscope.utils.regex_patterns import DOMAIN_PATTERN, EMAIL_PATTERN, IPV4_PATTERN, REGISTRY_PATTERN, URL_PATTERN, WINDOWS_PATH_PATTERN


class IOCExtractor:
    def __init__(self, baseline: dict[str, Any] | None = None) -> None:
        baseline = baseline or {}
        self.trusted_roots = tuple(str(item).lower() for item in baseline.get("trusted_system_roots", ["c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\"]))
        self.benign_domains = tuple(str(item).lower().lstrip(".") for item in baseline.get("benign_domain_suffixes", ["microsoft.com", "windows.com", "windowsupdate.com", "office.com"]))

    def extract(self, profiles: list[ProcessProfile]) -> list[IOC]:
        iocs: list[IOC] = []
        seen: set[tuple[str, str, int | None]] = set()

        def add(ioc: IOC) -> None:
            key = (ioc.type, ioc.value.lower(), ioc.pid)
            if key not in seen:
                seen.add(key)
                iocs.append(ioc)

        for profile in profiles:
            strong_context = bool(profile.malfind_regions) or any(f.category in {"injection", "vadyara", "hollowing", "ghosting", "masquerade"} for f in profile.findings)
            texts = [("cmdline", profile.command_line), ("image_path", profile.image_path)]
            texts.extend(("dll", str(dll.get("path", ""))) for dll in profile.dlls)
            for conn in profile.network_connections:
                if conn.remote_addr:
                    confidence = "medium" if strong_context and _public_ip(conn.remote_addr) else "low"
                    add(IOC("ip", conn.remote_addr, "network", profile.name, profile.pid, confidence, "Remote endpoint recovered from memory; reputation is not inferred.", process_key=profile.process_key))
            for source, text in texts:
                for value in re.findall(URL_PATTERN, text):
                    add(IOC("url", value, source, profile.name, profile.pid, "low" if self._benign_domain(value) else "medium", process_key=profile.process_key))
                for value in re.findall(IPV4_PATTERN, text):
                    if _valid_ip(value):
                        add(IOC("ip", value, source, profile.name, profile.pid, "medium" if strong_context and _public_ip(value) else "low", process_key=profile.process_key))
                for value in re.findall(DOMAIN_PATTERN, text):
                    if not value.lower().endswith((".exe", ".dll")):
                        add(IOC("domain", value, source, profile.name, profile.pid, "low" if self._benign_domain(value) else "medium", process_key=profile.process_key))
                for value in re.findall(EMAIL_PATTERN, text):
                    add(IOC("email", value, source, profile.name, profile.pid, "medium", process_key=profile.process_key))
                for value in re.findall(REGISTRY_PATTERN, text, flags=re.IGNORECASE):
                    add(IOC("registry", value, source, profile.name, profile.pid, "medium", process_key=profile.process_key))
                for value in re.findall(WINDOWS_PATH_PATTERN, text):
                    confidence = "low" if value.lower().startswith(self.trusted_roots) else "medium"
                    note = "Trusted location observed; this does not prove the file is benign." if confidence == "low" else "User-writable or unusual path observed."
                    add(IOC("path", value, source, profile.name, profile.pid, confidence, note, process_key=profile.process_key))
        for profile in profiles:
            profile.iocs = [ioc for ioc in iocs if ioc.process_key == profile.process_key]
        return iocs

    def _benign_domain(self, value: str) -> bool:
        candidate = value.lower().strip().rstrip(".")
        if "://" in candidate:
            candidate = (urlsplit(candidate).hostname or "").lower().rstrip(".")
        return any(candidate == suffix or candidate.endswith("." + suffix) for suffix in self.benign_domains)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
