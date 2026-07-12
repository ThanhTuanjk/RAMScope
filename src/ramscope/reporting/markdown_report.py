from __future__ import annotations

from ramscope.models import Finding, IOC, PluginStatus, ProcessProfile, TimelineEvent


class MarkdownReport:
    def render(self, case_info: dict[str, object], profiles: list[ProcessProfile], findings: list[Finding], iocs: list[IOC], plugin_status: list[PluginStatus] | None = None, timeline: list[TimelineEvent] | None = None) -> str:
        top_profiles = sorted(profiles, key=lambda item: item.risk_score, reverse=True)[:10]
        lines = ["# RAMScope Forensic Triage Report", ""]
        lines += ["## 1. Case Information", f"- Case ID: {case_info.get('case_id', '')}", f"- Input file: {case_info.get('input_file', '')}", ""]
        lines += ["## 2. Evidence Integrity", f"- MD5: {case_info.get('md5', '')}", f"- SHA256: {case_info.get('sha256', '')}", ""]
        lines += ["## 3. Analysis Environment", f"- Tool: {case_info.get('tool_name', 'RAMScope')} {case_info.get('tool_version', '')}", f"- Backend: {case_info.get('volatility_backend', 'Volatility3')}", ""]
        lines += ["## 4. Executive Summary", f"- Processes profiled: {len(profiles)}", f"- Findings requiring review: {len(findings)}", f"- IOCs extracted: {len(iocs)}", "- Findings are triage indicators and require analyst validation.", ""]
        lines.append("## 5. Evidence Coverage")
        statuses = plugin_status or []
        for status in statuses:
            resolved = f" -> {status.resolved_plugin}" if status.resolved_plugin and status.resolved_plugin != status.plugin else ""
            reason = status.reason or (f"error={status.error_path}" if status.error_path and status.status != "success" else "")
            provenance = f" duration={status.duration_seconds}s stdout_sha256={status.stdout_sha256 or '<none>'}"
            lines.append(f"- {status.plugin}{resolved}: {status.status}{provenance}" + (f" ({reason})" if reason else ""))
            if status.command:
                lines.append(f"  - Command: `{' '.join(status.command)}`")
            for dump_path, dump_hash in status.dump_hashes.items():
                lines.append(f"  - Dump SHA256: `{dump_hash}` `{dump_path}`")
        if not statuses:
            lines.append("- No plugin execution summary was recorded; categories without data were not fully assessed.")
        lines += ["", "## 6. Top Suspicious Processes"]
        for profile in top_profiles:
            lines.append(f"### PID {profile.pid} - {profile.name or '<unknown>'} - {profile.severity} ({profile.risk_score})")
            lines.append(f"- Process key: `{profile.process_key or '<unresolved>'}`")
            lines.append(f"- EPROCESS: `{profile.eprocess_offset or '<not recovered>'}`")
            lines.append(f"- Identity ambiguous: {profile.identity_ambiguous}")
            lines.append(f"- Parent: {profile.parent_name or '<unknown>'}")
            lines.append(f"- Observed in: {', '.join(profile.observed_in) or '<not recorded>'}")
            lines.append(f"- Command line: `{profile.command_line or '<none recovered>'}`")
            for reason in profile.score_reasons:
                lines.append(f"- {reason}")
            lines.append("")
        sections = [
            ("7. Process Findings", {"process", "process_cross_view", "masquerade"}),
            ("8. Command Line Findings", {"cmdline"}),
            ("9. Injection / Hollowing / Ghosting", {"injection", "hollowing", "ghosting", "thread"}),
            ("10. DLL / Module Findings", {"dll", "module"}),
            ("11. Network Findings", {"network"}),
            ("12. Persistence Findings", {"persistence"}),
            ("13. VAD / Memory Findings", {"deep_memory", "vadyara"}),
            ("14. Handle / Privilege Findings", {"handle", "privilege"}),
            ("15. File / Mutex Findings", {"file", "mutex", "dump"}),
            ("16. Kernel / Driver Findings", {"kernel"}),
            ("17. Hook / Evasion Findings", {"hook"}),
            ("18. LSASS Findings", {"lsass"}),
            ("19. YARA / External Tool Findings", {"yara", "strings", "capability", "av", "packer", "pe_metadata"}),
        ]
        for title, categories in sections:
            lines.append(f"## {title}")
            selected = [finding for finding in findings if finding.category in categories]
            if not selected:
                lines.append("No finding was recorded from the available evidence in this category. Check Evidence Coverage before interpreting this as absence of activity.")
            for finding in selected:
                groups = f" groups={','.join(finding.signal_groups)}" if finding.signal_groups else ""
                techniques = f" MITRE={','.join(finding.mitre_techniques)}" if finding.mitre_techniques else ""
                lines.append(f"- [{finding.severity}] {finding.title} (PID {finding.pid}, key={finding.process_key or '<unresolved>'}, confidence={finding.confidence},{groups} occurrences={finding.occurrence_count}{techniques})")
                for evidence in finding.evidence[:10]:
                    lines.append(f"  - {evidence.get('source', '')}: {evidence.get('detail', '')}")
                lines.append(f"  - Analyst next step: {finding.recommendation}")
            lines.append("")
        lines.append("## 20. IOC List")
        for ioc in iocs:
            lines.append(f"- {ioc.type}: `{_defang(ioc.value)}` source={ioc.source} pid={ioc.pid} key={ioc.process_key or '<unresolved>'} confidence={ioc.confidence}")
        if not iocs:
            lines.append("- No IOCs were extracted from the normalized artifacts available to RAMScope.")
        lines += ["", "## 21. Timeline", ""]
        for event in (timeline or [])[:50]:
            lines.append(f"- {event.timestamp or 'time not recovered'} [{event.event_type}] PID {event.pid} key={event.process_key or '<unresolved>'} {event.process_name}: {event.detail}")
        if not timeline:
            lines.append("- No timeline events were generated.")
        lines += ["", "## 22. Interpretation Limits", "- Risk scores prioritize analyst review and do not prove malware execution.", "- Unsupported, failed, skipped, or missing plugins leave corresponding behaviors unassessed.", "- Cross-view differences can include terminated or stale objects and require corroboration.", "- Public IPs, LOLBins, mutexes, files, packers, and YARA matches require context and analyst validation.", "- Persistence recovered from RAM does not replace full disk and registry analysis.", "", "## 23. Raw Evidence", "Raw Volatility output is stored under `raw/volatility/` and normalized artifacts under `normalized/`.", ""]
        return "\n".join(lines)


def _defang(value: str) -> str:
    text = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    if "." in text and not text.lower().startswith(("c:\\", "hkey_")):
        text = text.replace(".", "[.]")
    return text
