from __future__ import annotations

from typing import Any

from ramscope.models import Finding, ProcessProfile

LOLBIN_NAMES = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"}
USER_WRITABLE_TOKENS = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\")
SPECIALIZED_SIGNALS = {
    "hollowprocesses": ("Possible process hollowing indicator", "hollowing"),
    "processghosting": ("Possible process ghosting indicator", "ghosting"),
    "pebmasquerade": ("Possible PEB process masquerading indicator", "masquerade"),
    "suspicious_threads": ("Suspicious userland thread indicator", "thread"),
    "suspended_threads": ("Suspended thread context requiring review", "thread"),
}


class DeepAnalyzer:
    def analyze(
        self,
        profiles: list[ProcessProfile],
        ldrmodules: list[dict[str, Any]],
        vadinfo: list[dict[str, Any]],
        handles: list[dict[str, Any]],
        privs: list[dict[str, Any]],
        psscan: list[dict[str, Any]] | None = None,
        psxview: list[dict[str, Any]] | None = None,
        specialized: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        specialized = specialized or {}
        specialized_keys = {str(row.get("process_key")) for rows in specialized.values() for row in rows if row.get("process_key")}
        specialized_pids = {row.get("pid") for rows in specialized.values() for row in rows if row.get("pid") is not None and not row.get("process_key")}
        psx_mismatch = _psxview_mismatch_pids(psxview or [])

        for profile in profiles:
            scan_only = "windows.psscan" in profile.observed_in and "windows.pslist" not in profile.observed_in
            supporting = bool(profile.malfind_regions) or profile.process_key in specialized_keys or profile.pid in specialized_pids or profile.pid in psx_mismatch
            if scan_only and not profile.exit_time.strip() and supporting:
                findings.append(Finding(
                    "", profile.pid, profile.name,
                    "Possible active process cross-view discrepancy",
                    "High" if profile.malfind_regions or profile.process_key in specialized_keys or profile.pid in specialized_pids else "Medium",
                    55 if profile.malfind_regions or profile.process_key in specialized_keys or profile.pid in specialized_pids else 35,
                    "possible", "process_cross_view",
                    [{"source": "windows.psscan/windows.psxview", "detail": "Process was recovered by scanning but not normal list walking, with supporting context and no recovered exit time."}],
                    "Validate process state, exit time, psxview sources, threads, handles, and memory regions before concluding that it was hidden.",
                    process_key=profile.process_key,
                ))

        for artifact_name, rows in specialized.items():
            title_category = SPECIALIZED_SIGNALS.get(artifact_name)
            if not title_category:
                continue
            title, category = title_category
            for row in rows[:100]:
                pid = row.get("pid")
                matched = _find_profile(profiles, row)
                if artifact_name == "suspended_threads" and not (matched and (matched.malfind_regions or _suspicious_lolbin_command(matched.command_line))):
                    continue
                findings.append(Finding(
                    "", pid, matched.name if matched else str(row.get("process_name", "")),
                    title, "High", 60, "possible", category,
                    [{"source": str(row.get("source_plugin", artifact_name)), "detail": str(row.get("details", row))[:800]}],
                    "Treat this plugin result as a strong lead and validate with process ancestry, VADs, malfind, module state, and dumped bytes.",
                    process_key=matched.process_key if matched else str(row.get("process_key", "")),
                    mitre_techniques=["T1055.012"] if artifact_name == "hollowprocesses" else [],
                ))

        for row in ldrmodules:
            matched = _find_profile(profiles, row)
            if not matched:
                continue
            flags = [row.get("in_load"), row.get("in_init"), row.get("in_mem")]
            path = str(row.get("path", "")).lower()
            supporting = bool(matched.malfind_regions) or matched.process_key in specialized_keys or matched.pid in specialized_pids or any(token in path for token in USER_WRITABLE_TOKENS)
            if any(flag is False for flag in flags) and supporting:
                findings.append(Finding(
                    "", matched.pid, matched.name, "Possible unlinked module with supporting evidence", "High", 50, "possible", "module",
                    [{"source": "windows.ldrmodules", "detail": f"Loader-list mismatch path={row.get('path', '')} base={row.get('base', '')}; supporting memory/path context exists."}],
                    "Validate with dlllist, VAD mappings, dumped bytes, signatures, and known security software.",
                    process_key=matched.process_key,
                ))

        for row in vadinfo:
            matched = _find_profile(profiles, row)
            if not matched:
                continue
            protection = str(row.get("protection", "")).lower()
            file_output = str(row.get("file_output", ""))
            executable = "execute" in protection
            writable = "write" in protection or "copy" in protection
            anonymous = not file_output.strip() or file_output.strip().lower() in {"disabled", "n/a", "none"}
            strong_context = writable or bool(matched.malfind_regions) or matched.process_key in specialized_keys or matched.pid in specialized_pids
            lolbin_context = matched.name.lower() in LOLBIN_NAMES and _suspicious_lolbin_command(matched.command_line)
            if executable and (strong_context or (anonymous and lolbin_context)):
                findings.append(Finding(
                    "", matched.pid, matched.name, "Possible suspicious executable VAD indicator", "High" if strong_context else "Medium", 45 if strong_context else 30,
                    "possible", "deep_memory",
                    [{"source": "windows.vadinfo", "detail": f"{row.get('vad_start', '')}-{row.get('vad_end', '')} protection={row.get('protection', '')} file={file_output or '<none>'}"}],
                    "Correlate this VAD by address with malfind, VAD YARA, ldrmodules, process command line, and dumped bytes.",
                    process_key=matched.process_key,
                ))

        for row in handles:
            matched = _find_profile(profiles, row)
            if not matched:
                continue
            text = f"{row.get('handle_type', '')} {row.get('name', '')}".lower()
            if "\\\\.\\pipe\\" in text and (matched.malfind_regions or matched.process_key in specialized_keys or matched.pid in specialized_pids or _suspicious_lolbin_command(matched.command_line)):
                findings.append(Finding(
                    "", matched.pid, matched.name, "Possible suspicious named-pipe context", "Medium", 25, "possible", "handle",
                    [{"source": "windows.handles", "detail": str(row)[:800]}],
                    "Named pipes are common. Validate the pipe owner, peer process, process ancestry, network activity, and memory evidence.",
                    process_key=matched.process_key,
                ))

        for row in privs:
            matched = _find_profile(profiles, row)
            if not matched:
                continue
            if "sedebugprivilege" in str(row.get("privilege", "")).lower() and row.get("enabled") is True and (matched.malfind_regions or matched.process_key in specialized_keys or matched.pid in specialized_pids):
                findings.append(Finding(
                    "", matched.pid, matched.name, "SeDebugPrivilege enabled with independent suspicious context", "Medium", 25, "possible", "privilege",
                    [{"source": "windows.privileges", "detail": str(row)[:800]}],
                    "Validate token owner, process ancestry, user SID, and the independent memory finding.",
                    process_key=matched.process_key,
                ))
        return findings


def _find_profile(profiles: list[ProcessProfile], row: dict[str, Any]) -> ProcessProfile | None:
    process_key = str(row.get("process_key", ""))
    if process_key:
        exact = next((profile for profile in profiles if profile.process_key == process_key), None)
        if exact is not None:
            return exact
    offset = str(row.get("eprocess_offset", "")).lower()
    if offset:
        exact = next((profile for profile in profiles if profile.eprocess_offset.lower() == offset), None)
        if exact is not None:
            return exact
    pid = row.get("pid")
    candidates = [profile for profile in profiles if profile.pid == pid]
    process_name = str(row.get("process_name", row.get("name", ""))).lower()
    named = [profile for profile in candidates if process_name and profile.name.lower() == process_name]
    if len(named) == 1:
        return named[0]
    return candidates[0] if len(candidates) == 1 else None


def _psxview_mismatch_pids(rows: list[dict[str, Any]]) -> set[int]:
    mismatches: set[int] = set()
    ignored = {"pid", "ppid", "name", "process_name", "source_plugin", "details"}
    for row in rows:
        values = [value for key, value in row.items() if key not in ignored and isinstance(value, bool)]
        if values and any(values) and not all(values) and row.get("pid") is not None:
            mismatches.add(int(row["pid"]))
    return mismatches


def _suspicious_lolbin_command(command_line: str) -> bool:
    text = command_line.lower()
    return any(token in text for token in ("javascript:", "http://", "https://", "\\appdata\\", "\\temp\\", " -enc", "frombase64string", " iex"))
