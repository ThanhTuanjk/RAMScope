from __future__ import annotations

from typing import Any

from ramscope.models import ProcessProfile
from ramscope.scoring.rules import severity_for_score


class RiskScorer:
    def __init__(self, weights: dict[str, Any] | None = None, category_caps: dict[str, Any] | None = None, total_score_cap: int = 100) -> None:
        self.weights = {
            "malfind_hit": 30, "page_execute_readwrite": 20, "pe_header_in_memory": 20,
            "powershell_encoded": 25, "base64_or_iex": 25, "office_spawns_lolbin": 20,
            "system_process_unusual_path": 25, "suspicious_dll_path": 15,
            "network_with_suspicious_context": 20, "network_from_malfind_process": 25,
            "persistence_artifact": 20, "yara_hit": 30, "floss_suspicious_strings": 15,
            "capa_capability": 25, "clamav_detection": 30, "die_packer_signal": 10,
            "pe_metadata_anomaly": 15, "deep_module_anomaly": 20, "deep_vad_anomaly": 25,
            "process_cross_view": 25, "specialized_process_signal": 30,
            "suspicious_handle": 10, "privilege_context": 10, "critical_multi_signal_combo": 20,
            "vadyara_hit": 30, "file_artifact": 10, "mutex_artifact": 10,
            "kernel_driver_signal": 25, "hook_signal": 30, "skeleton_key_signal": 35,
            "dump_artifact_created": 5,
        }
        self.indicator_categories = {
            "malfind_hit": "memory", "page_execute_readwrite": "memory", "pe_header_in_memory": "memory", "deep_vad_anomaly": "memory",
            "powershell_encoded": "cmdline", "base64_or_iex": "cmdline", "office_spawns_lolbin": "process", "system_process_unusual_path": "process",
            "suspicious_dll_path": "module", "deep_module_anomaly": "module", "process_cross_view": "process", "specialized_process_signal": "memory",
            "network_with_suspicious_context": "network", "network_from_malfind_process": "network", "persistence_artifact": "persistence",
            "yara_hit": "signature", "vadyara_hit": "signature", "floss_suspicious_strings": "external_tool", "capa_capability": "external_tool",
            "clamav_detection": "external_tool", "die_packer_signal": "external_tool", "pe_metadata_anomaly": "external_tool",
            "suspicious_handle": "context", "privilege_context": "context", "critical_multi_signal_combo": "correlation",
            "file_artifact": "file", "mutex_artifact": "mutex", "kernel_driver_signal": "kernel", "hook_signal": "hook",
            "skeleton_key_signal": "lsass", "dump_artifact_created": "dump",
        }
        self.category_caps = {
            "memory": 60, "cmdline": 45, "process": 45, "module": 40, "network": 35, "persistence": 30,
            "signature": 40, "external_tool": 45, "context": 25, "correlation": 20, "file": 15, "mutex": 15,
            "kernel": 45, "hook": 45, "lsass": 45, "dump": 10,
        }
        self.total_score_cap = int(total_score_cap)
        if weights:
            self.weights.update({key: int(value) for key, value in weights.items() if key in self.weights})
        if category_caps:
            self.category_caps.update({key: int(value) for key, value in category_caps.items() if key in self.category_caps})

    def score(self, profiles: list[ProcessProfile]) -> list[ProcessProfile]:
        for profile in profiles:
            reasons: list[str] = []
            category_scores: dict[str, int] = {}

            def add(weight_key: str, reason: str) -> None:
                points = self.weights[weight_key]
                category = self.indicator_categories.get(weight_key, "context")
                used = category_scores.get(category, 0)
                cap = self.category_caps.get(category, points)
                applied = max(0, min(points, cap - used))
                if applied <= 0:
                    return
                category_scores[category] = used + applied
                reasons.append(f"+{applied}: {reason}" + (" (category cap applied)" if applied < points else ""))

            cmd = profile.command_line.lower()
            categories = {finding.category for finding in profile.findings}
            groups = {group for finding in profile.findings for group in finding.signal_groups}
            direct_groups: set[str] = set(groups)
            if profile.malfind_regions:
                add("malfind_hit", "windows.malfind reported at least one suspicious memory region")
                direct_groups.add("memory")
            if any("execute_readwrite" in region.protection.lower() for region in profile.malfind_regions):
                add("page_execute_readwrite", "PAGE_EXECUTE_READWRITE memory protection indicator")
            if any(region.has_pe_header for region in profile.malfind_regions):
                add("pe_header_in_memory", "PE header indicator in suspicious memory region")
            if "powershell" in profile.name.lower() and (" -enc" in cmd or "-encodedcommand" in cmd):
                add("powershell_encoded", "PowerShell encoded-command indicator")
                direct_groups.add("execution")
            if "frombase64string" in cmd or " iex" in cmd or "iex " in cmd:
                add("base64_or_iex", "FromBase64String or IEX command indicator")
            if profile.parent_name.lower() in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"} and profile.name.lower() in {"powershell.exe", "cmd.exe", "mshta.exe"}:
                add("office_spawns_lolbin", "Office process spawned a script-capable child")
            if profile.name.lower() in {"svchost.exe", "lsass.exe", "services.exe"} and profile.image_path and "c:\\windows\\system32" not in profile.image_path.lower():
                add("system_process_unusual_path", "System process name recovered outside expected System32 path")
            if "dll" in categories:
                add("suspicious_dll_path", "DLL/module loaded from a user-writable path")
            if profile.network_connections and profile.malfind_regions:
                add("network_from_malfind_process", "Network activity from a process with a malfind indicator")
                direct_groups.add("network")
            elif "network" in categories:
                add("network_from_malfind_process" if profile.malfind_regions else "network_with_suspicious_context", "Network endpoint correlated with suspicious process context")
                direct_groups.add("network")
            if "persistence" in categories:
                add("persistence_artifact", "Memory-recovered persistence context")
            if "yara" in categories:
                add("yara_hit", "YARA hit on a correlated dump")
            if "vadyara" in categories:
                add("vadyara_hit", "YARA matched bytes inside a process VAD")
            if "strings" in categories:
                add("floss_suspicious_strings", "FLOSS recovered suspicious strings")
            if "capability" in categories:
                add("capa_capability", "capa reported capability signals")
            if "av" in categories:
                add("clamav_detection", "ClamAV reported a signature match")
            if "packer" in categories:
                add("die_packer_signal", "Detect-It-Easy reported packer/protector context")
            if "pe_metadata" in categories:
                add("pe_metadata_anomaly", "PE metadata anomaly")
            if "module" in categories:
                add("deep_module_anomaly", "Loader/module discrepancy with supporting evidence")
            if "deep_memory" in categories:
                add("deep_vad_anomaly", "Executable VAD with supporting evidence")
            if "process_cross_view" in categories:
                add("process_cross_view", "Process cross-view discrepancy with supporting evidence")
            if categories.intersection({"hollowing", "ghosting", "masquerade", "thread"}):
                add("specialized_process_signal", "Specialized Volatility process/memory plugin produced a lead")
            if "handle" in categories:
                add("suspicious_handle", "Named-pipe/handle context with independent evidence")
            if "privilege" in categories:
                add("privilege_context", "Privilege context with independent evidence")
            if "file" in categories:
                add("file_artifact", "Recoverable user-writable file artifact")
            if "mutex" in categories:
                add("mutex_artifact", "Threat-hunting mutex token")
            if "kernel" in categories:
                add("kernel_driver_signal", "Kernel/driver cross-view or path context")
            if "hook" in categories:
                add("hook_signal", "ETW/system-call modification context")
            if "lsass" in categories:
                add("skeleton_key_signal", "Skeleton-key style plugin lead")
            if "dump" in categories:
                add("dump_artifact_created", "Additional dump metadata exists")
            if len(direct_groups) >= 3 and direct_groups.intersection({"memory", "signature"}) and "network" in direct_groups:
                add("critical_multi_signal_combo", "At least three independent signal groups include memory/signature and network")
            raw_score = sum(category_scores.values())
            profile.risk_score = min(raw_score, self.total_score_cap)
            if raw_score > self.total_score_cap:
                reasons.append(f"Score capped at {self.total_score_cap} to reduce repeated-indicator inflation.")
            profile.severity = severity_for_score(profile.risk_score)
            profile.score_reasons = reasons
        return profiles
