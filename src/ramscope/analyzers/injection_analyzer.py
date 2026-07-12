from __future__ import annotations

from ramscope.models import Finding, ProcessProfile


class InjectionAnalyzer:
    def analyze(self, profiles: list[ProcessProfile]) -> list[Finding]:
        findings = []
        for profile in profiles:
            for region in profile.malfind_regions:
                details = ["windows.malfind reported a suspicious memory region."]
                if "execute_readwrite" in region.protection.lower():
                    details.append("Region protection includes PAGE_EXECUTE_READWRITE.")
                if region.has_pe_header:
                    details.append("Region appears to contain a PE header indicator.")
                if region.dump_file:
                    details.append(f"Dump file available for YARA/string review: {region.dump_file}.")
                findings.append(Finding("", profile.pid, profile.name, "Possible injection/hollowing-related memory indicator", "High", 70, "possible", "injection", [{"source": "windows.malfind", "detail": " ".join(details)}], "Review VAD details, ancestry, DLLs, and dumped memory."))
        return findings
