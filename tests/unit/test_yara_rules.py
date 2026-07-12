from pathlib import Path


def test_builtin_yara_rule_count_is_useful() -> None:
    rules_dir = Path(__file__).resolve().parents[2] / "rules"
    rule_count = 0
    for path in rules_dir.rglob("*.yar"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("rule "):
                rule_count += 1
    assert rule_count >= 25
