from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

from ramscope.models import Finding, IOC, PluginStatus, ProcessProfile, TargetInfo
from ramscope.reporting.pdf_report import PdfReport


VALID_FORMATS = {"md", "markdown", "html", "pdf", "all"}
SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def write_reports(
    case_dir: Path,
    metadata: dict[str, Any],
    profiles: list[ProcessProfile],
    findings: list[Finding],
    iocs: list[IOC],
    statuses: list[PluginStatus],
    target: TargetInfo,
    unresolved: list[dict[str, Any]],
    output_format: str = "html",
    enable_pdf: bool = False,
) -> list[Path]:
    normalized_format = output_format.casefold()
    if normalized_format not in VALID_FORMATS:
        raise ValueError("Report format must be md, markdown, html, pdf, or all.")
    if normalized_format in {"pdf", "all"} and not enable_pdf:
        raise ValueError("PDF reporting is disabled by configuration.")

    reports = case_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    completed = sum(item.status in {"success", "cached"} for item in statuses)
    analyzed = sum(item.analysis_status == "analyzed" for item in statuses)
    observed_only = sum(item.analysis_status == "observed" for item in statuses)
    unassessed = [item.plugin for item in statuses if item.analysis_status == "unassessed" or item.status not in {"success", "cached"}]
    corroborated = [item for item in findings if item.disposition == "corroborated"]
    leads = [item for item in findings if item.disposition == "lead"]
    actionable_iocs = [item for item in iocs if item.actionability == "actionable"]
    candidate_iocs = [item for item in iocs if item.actionability == "candidate"]

    verdict = (
        "Multiple independently sourced suspicious indicators require priority analyst review."
        if corroborated
        else "No corroborated suspicious finding was produced within the completed analysis coverage."
    )
    lines = [
        "# RAMScope Forensic Triage Report",
        "",
        "## Assessment",
        f"- {_md(verdict)}",
        f"- Target: {_md(target.family)} build={_md(target.build or '<not recovered>')}; profile={_md(target.selected_profile)}; status={_md(target.status)}.",
        f"- Collection coverage: {completed}/{len(statuses)} planned plugin runs completed.",
        f"- Analysis coverage: {analyzed} semantically analyzed; {observed_only} normalized for analyst review.",
    ]
    if unassessed:
        lines.append(f"- Unassessed or partial: {_md(', '.join(sorted(set(unassessed))))}.")
    lines += [
        "",
        "## Evidence Integrity",
        f"- SHA256: {_md(metadata.get('sha256', ''))}",
        f"- MD5: {_md(metadata.get('md5', ''))}",
        "",
        "## Summary",
        f"- Process profiles: {len(profiles)}",
        f"- Corroborated suspicious findings: {len(corroborated)}",
        f"- Leads requiring analyst validation: {len(leads)}",
        f"- Actionable IOCs: {len(actionable_iocs)}",
        f"- Candidate IOCs: {len(candidate_iocs)}",
        f"- Unresolved artifacts: {len(unresolved)}",
        "",
        "## Top Leads",
    ]
    for finding in sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), item.score), reverse=True)[:20]:
        proof = "; ".join(item.get("detail", "") for item in finding.evidence[:2])
        pid_text = str(finding.pid) if finding.pid is not None else "n/a"
        process_text = finding.process_name or "<unresolved>"
        lines.append(f"- [{_md(finding.severity)}/{_md(finding.disposition)}] PID {pid_text} {_md(process_text)}: {_md(finding.title)}. Evidence: {_md(proof)}")
        if finding.suppressed_reason:
            lines.append(f"  - Suppressor: {_md(finding.suppressed_reason)}")
        if finding.provenance_ids:
            lines.append(f"  - Provenance: {_md(', '.join(finding.provenance_ids[:5]))}")
        lines.append(f"  - Next step: {_md(finding.recommendation)}")
    if not findings:
        lines.append("- No lead was produced from completed plugin output.")

    lines += ["", "## Actionable IOCs"]
    if actionable_iocs:
        lines.extend(
            f"- {ioc.type}: `{_defang_ioc(ioc.type, ioc.value)}` confidence={_md(ioc.confidence)} source={_md(ioc.source)} occurrences={ioc.occurrence_count}"
            for ioc in actionable_iocs
        )
    else:
        lines.append("- No actionable IOC was extracted.")

    lines += ["", "## Candidate IOCs"]
    if candidate_iocs:
        lines.extend(
            f"- {ioc.type}: `{_defang_ioc(ioc.type, ioc.value)}` confidence={_md(ioc.confidence)} source={_md(ioc.source)} occurrences={ioc.occurrence_count}; requires analyst validation"
            for ioc in candidate_iocs
        )
    else:
        lines.append("- No candidate IOC was extracted.")

    lines += ["", "## Evidence Coverage"]
    if statuses:
        lines.extend(
            f"- {_md(status.plugin)}: collection={_md(status.status)}; analysis={_md(status.analysis_status)}; "
            f"lane={_md(status.lane or 'n/a')}; duration={status.duration_seconds}s; "
            f"timeout={str(status.timeout_seconds) + 's' if status.timeout_seconds else 'n/a'}; detail={_md(status.reason or 'n/a')}"
            for status in statuses
        )
    else:
        lines.append("- No plugin status ledger was supplied to this renderer.")

    lines += [
        "",
        "## Interpretation Limits",
        "- A lead or risk score is not proof of malware execution.",
        "- Failed, timed-out, unsupported, skipped, and parser-rejected plugins leave corresponding behavior unassessed.",
        "- Network artifacts recovered from memory do not alone establish command-and-control activity.",
        "- Windows 11 remains compatibility-ready until a clean Windows 11 memory image completes the acceptance suite.",
    ]
    markdown = "\n".join(lines) + "\n"
    md_path = reports / "report.md"
    md_path.write_text(markdown, encoding="utf-8", newline="\n")
    result = [md_path]

    if normalized_format in {"html", "all"}:
        body = "\n".join(
            "<tr>"
            f"<td>{html.escape(item.severity)}</td>"
            f"<td>{html.escape(item.disposition)}</td>"
            f"<td>{'' if item.pid is None else item.pid}</td>"
            f"<td>{html.escape(item.process_name)}</td>"
            f"<td>{html.escape(item.title)}</td>"
            "</tr>"
            for item in findings
        )
        page = (
            "<!doctype html><html><head><meta charset='utf-8'><title>RAMScope report</title>"
            "<style>body{font-family:Arial,sans-serif;margin:32px;line-height:1.45}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:7px;text-align:left}"
            ".note{color:#7a5200}pre{white-space:pre-wrap;background:#f6f8fa;padding:16px}</style></head><body>"
            f"<h1>RAMScope Forensic Triage Report</h1><p class='note'>{html.escape(verdict)}</p>"
            "<h2>Findings</h2><table><tr><th>Severity</th><th>Disposition</th><th>PID</th><th>Process</th><th>Finding</th></tr>"
            f"{body}</table><h2>Report appendix</h2><pre>{html.escape(markdown)}</pre></body></html>"
        )
        html_path = reports / "report.html"
        html_path.write_text(page, encoding="utf-8", newline="\n")
        result.append(html_path)

    if normalized_format in {"pdf", "all"}:
        result.append(PdfReport().render(reports / "report.pdf", "RAMScope Forensic Triage Report", markdown))
    return result


def _defang_ioc(ioc_type: str, value: str) -> str:
    if ioc_type == "url":
        scheme_defanged = re.sub(r"^https://", "hxxps://", value, flags=re.IGNORECASE)
        scheme_defanged = re.sub(r"^http://", "hxxp://", scheme_defanged, flags=re.IGNORECASE)
        return scheme_defanged.replace(".", "[.]")
    if ioc_type in {"domain", "ip"}:
        return value.replace(".", "[.]")
    return value


def _md(value: object) -> str:
    clean = str(value).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+!|>])", r"\\\1", clean)
