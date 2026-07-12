from __future__ import annotations

from typing import Any

from ramscope.models import Finding, ProcessProfile


class PersistenceAnalyzer:
    def __init__(self, baseline: dict[str, Any] | None = None) -> None:
        baseline = baseline or {}
        self.user_writable = tuple(str(item).lower() for item in baseline.get("user_writable_tokens", ["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\"]))

    def analyze(self, profiles: list[ProcessProfile]) -> list[Finding]:
        findings = []
        for profile in profiles:
            for item in profile.persistence_links:
                text = " ".join(str(value) for value in item.values()).lower()
                suspicious_path = any(token in text for token in self.user_writable)
                run_key = bool(item.get("is_run_key")) or "runonce" in text
                if not (run_key or suspicious_path):
                    continue
                findings.append(Finding(
                    "", profile.pid, profile.name, "Possible memory-recovered persistence artifact", "Medium", 35, "possible", "persistence",
                    [{"source": str(item.get("source_plugin", "memory artifact")), "detail": str(item)[:1000]}],
                    "Memory persistence artifacts can be incomplete. Confirm with full registry hives, service configuration, disk, and event logs.",
                ))
        return findings
