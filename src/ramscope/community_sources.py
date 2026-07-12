from __future__ import annotations

COMMUNITY_SOURCES = {
    "signature-base": {
        "url": "https://github.com/Neo23x0/signature-base.git",
        "rules_path": "yara",
        "note": "High-quality YARA rules and IOCs with minimal false positives.",
    },
    "elastic-protections": {
        "url": "https://github.com/elastic/protections-artifacts.git",
        "rules_path": "yara/rules",
        "note": "Elastic Security endpoint detection logic including YARA.",
    },
    "reversinglabs-yara": {
        "url": "https://github.com/reversinglabs/reversinglabs-yara-rules.git",
        "rules_path": "yara",
        "note": "Threat analyst rules for hunters and incident responders.",
    },
    "yara-rules": {
        "url": "https://github.com/Yara-Rules/rules.git",
        "rules_path": ".",
        "note": "Large community YARA rule collection.",
    },
    "lolbas": {
        "url": "https://github.com/LOLBAS-Project/LOLBAS.git",
        "rules_path": "",
        "note": "Living Off The Land reference data; RAMScope uses LOLBin concepts in process analysis.",
    },
    "capa-rules": {
        "url": "https://github.com/mandiant/capa-rules.git",
        "rules_path": "",
        "note": "Mandiant capa capability rules. Install capa separately; RAMScope can call capa when available.",
    },
    "awesome-yara": {
        "url": "https://github.com/InQuest/awesome-yara.git",
        "rules_path": "",
        "note": "Curated index of YARA tools and public rule repositories for analyst research.",
    },
}
