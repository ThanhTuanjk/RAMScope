# Risk Scoring

RAMScope scores investigation priority, not malware certainty. Repeated rows are deduplicated and every category has a cap.

## Signal groups

- Memory: malfind, executable/private VAD, hollowing, ghosting, suspicious threads.
- Execution/process: command line, ancestry, masquerading, process cross-view discrepancies.
- Network: public endpoints only when correlated with suspicious process or memory context.
- Signature: YARA, VAD YARA, antivirus, and capability evidence.
- Persistence, module, kernel, hook/evasion, and artifact context are tracked separately.

`High confidence` requires at least three independent groups and a strong memory, signature, kernel, or hook/evasion signal. `Likely` requires at least two meaningful independent groups. A public IP, LOLBin, mutex, recoverable file, loader mismatch, or scan-only object alone remains a weak lead.

Scores are capped at 100. Default severity bands remain Low 0-29, Medium 30-59, High 60-89, and Critical 90-100. Findings always require analyst validation.
