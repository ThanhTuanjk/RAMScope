from __future__ import annotations

from typing import Any

from ramscope.models import Finding, ProcessProfile


class DllAnalyzer:
    def __init__(self, baseline: dict[str, Any] | None = None) -> None:
        baseline = baseline or {}
        self.user_writable = tuple(str(item).lower() for item in baseline.get("user_writable_tokens", ["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\"]))

    def analyze(self, profiles: list[ProcessProfile]) -> list[Finding]:
        findings = []
        for profile in profiles:
            for dll in profile.dlls:
                path = str(dll.get("path", "")).strip()
                if not path:
                    continue
                if any(token in path.lower() for token in self.user_writable):
                    findings.append(Finding(
                        "", profile.pid, profile.name, "DLL/module loaded from a user-writable path", "Medium", 30, "possible", "dll",
                        [{"source": "windows.dlllist", "detail": f"DLL path requires review: {path}"}],
                        "Validate file hash/signature, loader ancestry, VAD mapping, and whether the path is expected for this application.",
                    ))
        return findings
