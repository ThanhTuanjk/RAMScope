# Changelog

## 0.4.0

- Fixed Volatility plugin discovery against real `vol --help` output and corrected blank-output/newline handling so successful empty plugins produce valid JSON.
- Added atomic JSON writes, bounded error capture, process-tree termination on timeout, per-plugin output hashes, and verified resume/reassessment artifacts.
- Corrected Windows path, Registry key, URL/domain, named-pipe, and mutex normalization to prevent escaped-string false positives and missed artifacts.
- Replaced row-driven escalation with evidence-gated observed, lead, and corroborated dispositions using provenance-aware correlation.
- Prevented PEB `False`, image-backed `EXECUTE_WRITECOPY`, ordinary browser/JIT memory, and uncorroborated loader discrepancies from becoming High findings by themselves.
- Preserved and interpreted semantic fields from hollowing, process-ghosting, scheduled-task, and timeliner plugins with cautious wording.
- Added deterministic process correlation that leaves ambiguous PID-reuse artifacts unresolved.
- Added effective config validation and honored YARA, IOC, scoring, HTML, PDF, dump-mode, worker, and external-tool controls.
- Snapshotted effective configuration, runtime flags, YARA rules and hashes, plugin resolution, and tool provenance for reproducible reassessment.
- Isolated reassessment output from the source case and made `report` render only from normalized artifacts.
- Added real PDF generation, separate actionable/candidate IOC reporting, and accurate collection/analysis coverage.
- Expanded regression coverage for clean Windows paths, empty plugin output, timeout logs, false-positive controls, hollowing/ghosting semantics, scheduled tasks, timeline use, scoring provenance, YARA disablement, and reassessment immutability.

## 0.3.0

- Added EPROCESS/create-time process identity, semantic plugin parsing, YARA pack provenance, resume integrity, and deep/full coverage.

## 0.1.0

- Initial GitHub-ready RAMScope project.
