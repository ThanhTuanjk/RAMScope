# Output Format

Case folders include `evidence`, `raw`, `normalized`, `dumps`, `iocs`, `reports`, and `logs`.

Important normalized files:

- `process_profiles.json`: correlated process view.
- `risk_summary.json`: findings and scored profiles.
- `plugin_status.json`: success/failure/timeout/skipped state per Volatility plugin.
- `external_tool_status.json`: success/failure/skipped state for optional FLOSS, capa, ClamAV, Detect-It-Easy, and pefile runs.
- `timeline.json`: process and artifact timeline events recovered from memory.
- `findings.csv`, `process_profiles.csv`, `network.csv`, `malfind.csv`: spreadsheet-friendly exports.

Optional external tool output is stored under `normalized/external_tools/`. Missing tools are recorded as `unavailable`; this is expected on a fresh VM until the analyst installs them.
