# RAMScope Usage

```powershell
ramscope doctor
ramscope validate --input memory.raw
ramscope analyze --input memory.raw --case CASE001 --output cases --format html --deep
ramscope analyze --input memory.raw --case CASE001 --output cases --format html --full --workers auto
ramscope analyze --input memory.raw --case CASE001 --output cases --malfind-dumps targeted --malfind-pid 1234
ramscope reassess --case cases\CASE001 --format html
```

`--malfind-dumps targeted` is the default. RAMScope scans before dumping and only dumps prioritized or analyst-selected PIDs. Use `all` only when broad artifact extraction is justified.

VMs with 4-6 GB RAM are supported. Keep `--workers auto` so RAMScope uses one worker on these systems; analysis retains the same plugin coverage but completes more slowly than on an 8+ GB host.

`--target-profile auto` reads `windows.info`. Windows 10 is the current validated baseline; Windows 11 is compatibility-ready until a clean Windows 11 image completes the same acceptance suite.

High and Critical are reserved for corroborated evidence. A YARA match, VAD permission, loader mismatch, public IP, or plugin row on its own remains a lead requiring analyst validation.
