from __future__ import annotations

import html

from ramscope.models import Finding, IOC, PluginStatus, ProcessProfile


class HtmlReport:
    def render_case(self, markdown_text: str, profiles: list[ProcessProfile], findings: list[Finding], iocs: list[IOC], plugin_status: list[PluginStatus] | None = None) -> str:
        rows = "\n".join(
            f"<tr><td>{p.pid}</td><td>{html.escape(p.name)}</td><td class='{p.severity.lower()}'>{p.severity}</td><td>{p.risk_score}</td><td>{html.escape(p.parent_name)}</td></tr>"
            for p in sorted(profiles, key=lambda item: item.risk_score, reverse=True)[:15]
        )
        finding_rows = "\n".join(
            f"<tr><td>{html.escape(f.category)}</td><td class='{f.severity.lower()}'>{f.severity}</td><td>{f.pid or ''}</td><td><code>{html.escape(f.process_key)}</code></td><td>{html.escape(f.title)}</td><td>{html.escape(f.confidence)}</td><td>{html.escape(', '.join(f.mitre_techniques))}</td><td>{f.occurrence_count}</td></tr>"
            for f in findings
        )
        ioc_rows = "\n".join(
            f"<tr><td>{html.escape(i.type)}</td><td><code>{html.escape(_defang(i.value))}</code></td><td>{html.escape(i.source)}</td><td>{i.pid or ''}</td><td>{html.escape(i.confidence)}</td></tr>"
            for i in iocs
        )
        plugin_rows = "\n".join(
            f"<tr><td>{html.escape(s.plugin)}</td><td>{html.escape(s.resolved_plugin)}</td><td>{html.escape(s.status)}</td><td>{s.duration_seconds}</td><td><code>{html.escape(s.stdout_sha256)}</code></td><td>{html.escape(s.reason or s.error_path)}</td></tr>"
            for s in (plugin_status or [])
        )
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>RAMScope Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #17202a; line-height: 1.45; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0 28px; }}
    th, td {{ border: 1px solid #d8dee4; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f3f6f8; }}
    .critical {{ color: #8b0000; font-weight: 700; }} .high {{ color: #b42318; font-weight: 700; }}
    .medium {{ color: #9a6700; font-weight: 700; }} .low {{ color: #1f6f43; font-weight: 700; }}
    pre {{ white-space: pre-wrap; background: #f6f8fa; padding: 12px; border-radius: 6px; }}
  </style>
</head>
<body>
  <h1>RAMScope Forensic Triage Report</h1>
  <p>Findings are cautious triage indicators and require analyst validation.</p>
  <h2>Top Suspicious Processes</h2>
  <table><thead><tr><th>PID</th><th>Process key</th><th>Name</th><th>Severity</th><th>Risk</th><th>Parent</th><th>Identity ambiguous</th></tr></thead><tbody>{rows}</tbody></table>
  <h2>Findings</h2>
  <table><thead><tr><th>Category</th><th>Severity</th><th>PID</th><th>Process key</th><th>Title</th><th>Confidence</th><th>MITRE ATT&CK</th><th>Count</th></tr></thead><tbody>{finding_rows}</tbody></table>
  <h2>IOCs (defanged)</h2>
  <table><thead><tr><th>Type</th><th>Value</th><th>Source</th><th>PID</th><th>Confidence</th></tr></thead><tbody>{ioc_rows}</tbody></table>
  <h2>Evidence Coverage</h2>
  <table><thead><tr><th>Requested plugin</th><th>Resolved plugin</th><th>Status</th><th>Seconds</th><th>Output SHA256</th><th>Reason</th></tr></thead><tbody>{plugin_rows}</tbody></table>
  <h2>Markdown Appendix</h2>
  <pre>{html.escape(markdown_text)}</pre>
</body>
</html>
"""

    def render(self, markdown_text: str) -> str:
        return self.render_case(markdown_text, [], [], [], [])


def _defang(value: str) -> str:
    text = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    if "." in text and not text.lower().startswith(("c:\\", "hkey_")):
        text = text.replace(".", "[.]")
    return text
