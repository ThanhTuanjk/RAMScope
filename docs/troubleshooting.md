# Troubleshooting

Start with:

```powershell
ramscope doctor
ramscope plugins
```

If Volatility is missing, RAMScope records plugins as unavailable and still produces a coverage-aware report. If a plugin times out, inspect `raw/volatility/errors/` and the coverage section; a timeout means unassessed, not clean.

For a slow VM, use the default or deep profile first, set `--workers 1`, and keep targeted malfind dumping enabled. Full-memory scans and dumps are deliberately serialized to avoid exhausting RAM and disk I/O.

On PowerShell, if activation is blocked for the current session, use the venv interpreter directly: `.\.venv\Scripts\python.exe -m ramscope --help`.

