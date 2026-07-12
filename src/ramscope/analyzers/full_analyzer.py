from __future__ import annotations

from collections import defaultdict
from typing import Any

from ramscope.models import Finding

USER_WRITABLE_TOKENS = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\")
SUSPICIOUS_FILE_EXTENSIONS = (".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".scr", ".sys")
SUSPICIOUS_MUTEX_TOKENS = ("mimikatz", "meterpreter", "cobalt", "beacon", "sliver", "empire", "postex", "inject", "backdoor")
NEGATIVE_TOKENS = ("false", "not found", "none", "clean", "disabled", "unmodified")


class FullAnalyzer:
    def analyze(self, artifacts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._analyze_vadyarascan(artifacts.get("vadyarascan", [])))
        findings.extend(self._analyze_filescan(artifacts.get("filescan", [])))
        findings.extend(self._analyze_dump_artifacts(artifacts))
        findings.extend(self._analyze_mutantscan(artifacts.get("mutantscan", [])))
        findings.extend(self._analyze_kernel_cross_view(artifacts))
        findings.extend(self._analyze_evasion_plugins(artifacts))
        findings.extend(self._analyze_skeleton_key(artifacts.get("skeleton_key_check", [])))
        return findings

    def _analyze_vadyarascan(self, rows: list[dict[str, Any]]) -> list[Finding]:
        grouped: dict[tuple[str, int | None], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            grouped[(str(row.get("process_key", "")), row.get("pid"))].append(row)
        findings = []
        for (process_key, pid), items in grouped.items():
            sample = "; ".join(_summarize(item) for item in items[:5])
            findings.append(Finding(
                "", pid, str(items[0].get("process_name", "")), "YARA matched bytes inside process VAD regions", "Medium", 25, "possible", "vadyara",
                [{"source": "windows.vadyarascan", "detail": f"{len(items)} row(s); sample: {sample}"}],
                "Validate rule specificity, VAD permissions, owning process, address overlap with malfind, and adjacent bytes.",
                occurrence_count=len(items),
                process_key=process_key,
            ))
        return findings

    def _analyze_filescan(self, rows: list[dict[str, Any]]) -> list[Finding]:
        findings = []
        for row in rows[:5000]:
            text = _row_text(row)
            if any(token in text for token in USER_WRITABLE_TOKENS) and any(ext in text for ext in SUSPICIOUS_FILE_EXTENSIONS):
                findings.append(Finding(
                    "", row.get("pid"), str(row.get("process_name", "")), "Recoverable file object in a user-writable location", "Medium", 25, "possible", "file",
                    [{"source": "windows.filescan", "detail": _summarize(row)}],
                    "A recoverable file object does not prove execution. Correlate it with handles, process command line, hashes, and disk evidence.",
                    process_key=str(row.get("process_key", "")),
                ))
                if len(findings) >= 25:
                    break
        return findings

    def _analyze_dump_artifacts(self, artifacts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
        findings = []
        for key, plugin in (("dumpfiles", "windows.dumpfiles"), ("memmap", "windows.memmap")):
            rows = artifacts.get(key, [])
            if rows:
                findings.append(Finding(
                    "", None, "", f"{plugin} produced artifact metadata", "Low", 5, "low", "dump",
                    [{"source": plugin, "detail": f"{len(rows)} row(s) recorded; produced files are listed in plugin_status.json."}],
                    "Review dumped files only in an isolated analysis environment.", occurrence_count=len(rows),
                ))
        return findings

    def _analyze_mutantscan(self, rows: list[dict[str, Any]]) -> list[Finding]:
        findings = []
        for row in rows[:5000]:
            if any(token in _row_text(row) for token in SUSPICIOUS_MUTEX_TOKENS):
                findings.append(Finding(
                    "", row.get("pid"), str(row.get("process_name", "")), "Mutex/mutant name contains a threat-hunting token", "Medium", 25, "possible", "mutex",
                    [{"source": "windows.mutantscan", "detail": _summarize(row)}],
                    "Mutex names are weak indicators. Validate against known-good software and correlate with process, memory, network, and signatures.",
                    process_key=str(row.get("process_key", "")),
                ))
                if len(findings) >= 25:
                    break
        return findings

    def _analyze_kernel_cross_view(self, artifacts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
        findings: list[Finding] = []
        listed = {_artifact_name(row) for row in artifacts.get("modules", []) if _artifact_name(row)}
        scanned = {_artifact_name(row) for row in artifacts.get("modscan", []) if _artifact_name(row)}
        scan_only = scanned - listed
        supporting_rows: list[tuple[str, dict[str, Any]]] = []
        for key in ("driverscan", "drivermodule", "driverirp", "callbacks", "ssdt", "timers"):
            supporting_rows.extend((key, row) for row in artifacts.get(key, []))
        for module_name in sorted(scan_only):
            corroboration = [(key, row) for key, row in supporting_rows if module_name in _row_text(row) and _strong_kernel_context(row)]
            if corroboration:
                key, row = corroboration[0]
                findings.append(Finding(
                    "", row.get("pid"), str(row.get("process_name", "")), "Kernel module cross-view discrepancy with corroborating evidence", "High", 60, "possible", "kernel",
                    [{"source": "windows.modules/windows.modscan", "detail": f"{module_name} was recovered by scanning but not list walking."}, {"source": f"windows.{key}", "detail": _summarize(row)}],
                    "Validate module addresses, driver signature and path, callbacks/IRPs, unload history, and disk evidence before concluding rootkit activity.",
                    process_key=str(row.get("process_key", "")),
                ))
        for key in ("driverscan", "drivermodule", "driverirp", "callbacks", "ssdt", "timers", "devicetree", "symlinkscan"):
            for row in artifacts.get(key, [])[:3000]:
                if _strong_kernel_context(row):
                    findings.append(Finding(
                        "", row.get("pid"), str(row.get("process_name", "")), "Kernel or driver artifact path requires review", "High", 50, "possible", "kernel",
                        [{"source": f"windows.{key}", "detail": _summarize(row)}],
                        "Validate path, signature, module ownership, callbacks/IRPs, and known security software.",
                        process_key=str(row.get("process_key", "")),
                    ))
                    if len(findings) >= 30:
                        return findings
        if artifacts.get("svcdiff"):
            rows = artifacts["svcdiff"]
            findings.append(Finding(
                "", None, "", "Service cross-view discrepancy requires rootkit/persistence review", "High", 50, "possible", "kernel",
                [{"source": "windows.malware.svcdiff", "detail": f"{len(rows)} discrepancy row(s); sample: {_summarize(rows[0])}"}],
                "Validate service list/scanner differences, service binary paths, registry state, and disk evidence.", occurrence_count=len(rows),
            ))
        return findings

    def _analyze_evasion_plugins(self, artifacts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
        findings = []
        for key, title in (
            ("etwpatch", "Possible ETW patching/evasion indicator"),
            ("unhooked_system_calls", "Possible modified or redirected system-call stub indicator"),
        ):
            rows = artifacts.get(key, [])
            for row in rows[:100]:
                text = _row_text(row)
                if not any(token in text for token in NEGATIVE_TOKENS):
                    findings.append(Finding(
                        "", row.get("pid"), str(row.get("process_name", "")), title, "High", 60, "possible", "hook",
                        [{"source": f"windows.{key}", "detail": _summarize(row)}],
                        "Validate target module, original bytes, owning process, security software, and adjacent memory before escalation.",
                        process_key=str(row.get("process_key", "")),
                    ))
        return findings

    def _analyze_skeleton_key(self, rows: list[dict[str, Any]]) -> list[Finding]:
        findings = []
        for row in rows:
            text = _row_text(row)
            if any(token in text for token in ("true", "found", "patched", "detected", "possible", "suspicious")) and not any(token in text for token in NEGATIVE_TOKENS):
                findings.append(Finding(
                    "", row.get("pid"), str(row.get("process_name", "lsass.exe")), "Possible LSASS skeleton-key style indicator", "High", 70, "possible", "lsass",
                    [{"source": "windows.skeleton_key_check", "detail": _summarize(row)}],
                    "Treat as high priority, then validate with LSASS memory, credential, domain-controller, and event-log evidence.",
                    process_key=str(row.get("process_key", "")),
                    mitre_techniques=["T1556"],
                ))
        return findings


def _row_text(row: dict[str, Any]) -> str:
    return " ".join(str(value) for value in row.values() if value is not None).lower()


def _summarize(row: dict[str, Any]) -> str:
    text = row.get("details") or " ".join(f"{key}={value}" for key, value in row.items() if value not in (None, ""))
    return str(text)[:800]


def _artifact_name(row: dict[str, Any]) -> str:
    value = str(row.get("name") or row.get("module") or row.get("path") or "").replace("/", "\\")
    return value.rsplit("\\", 1)[-1].lower()


def _strong_kernel_context(row: dict[str, Any]) -> bool:
    text = _row_text(row)
    return any(token in text for token in USER_WRITABLE_TOKENS) and (".sys" in text or "driver" in text or "callback" in text)
