# Contributing

Keep RAMScope defensive, evidence-based, and analyst-focused. Do not add malware samples, offensive payloads, real memory images, case data, private IOCs, or secrets.

## Development

```powershell
.\scripts\dev-setup.ps1
.\scripts\run-tests.ps1
```

Changes to parser, correlation, scoring, or severity language should include a focused synthetic fixture and explain the evidence boundary in the pull request. Findings must use cautious language such as observed, possible, likely, or requires analyst validation.
