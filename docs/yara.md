# YARA

YARA is optional. Built-in rules are packaged with RAMScope, while a case may supply additional rules with `--yara-rules`.

Use `--no-yara` when the environment does not have `yara-python` or when the analysis must exclude signature matching. A community-rule match is an observed lead and requires process, memory, network, persistence, or other independent corroboration before a high-severity finding is produced.

Rules and their hashes are recorded in the case manifest for reproducibility. Do not place private rule packs or sensitive indicators in a public repository.

