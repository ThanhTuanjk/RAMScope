from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ramscope.models import Finding
from ramscope.utils.json_utils import write_json


def prepare_yara_rule_pack(rule_dirs: list[Path], output_dir: Path) -> tuple[Path | None, dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    status: dict[str, Any] = {"status": "skipped", "files": [], "valid_files": 0, "invalid_files": 0, "compiled_pack": "", "compiled_sha256": ""}
    try:
        import yara
    except ImportError:
        status.update({"status": "unavailable", "reason": "yara-python is not installed."})
        write_json(output_dir / "status.json", status)
        return None, status

    source_files = _rule_files(rule_dirs)
    if not source_files:
        status.update({"status": "skipped", "reason": "No .yar or .yara files were found."})
        write_json(output_dir / "status.json", status)
        return None, status

    valid: dict[str, str] = {}
    used_namespaces: set[str] = set()
    for index, path in enumerate(source_files, start=1):
        entry: dict[str, Any] = {"path": str(path), "sha256": _sha256(path), "status": "valid", "error": ""}
        try:
            yara.compile(filepath=str(path))
            namespace = _namespace(path.stem, index, used_namespaces)
            valid[namespace] = str(path)
            entry["namespace"] = namespace
            status["valid_files"] += 1
        except Exception as exc:  # noqa: BLE001 - rule packs can contain unsupported modules or syntax.
            entry.update({"status": "invalid", "error": str(exc)[:1000]})
            status["invalid_files"] += 1
        status["files"].append(entry)

    if not valid:
        status.update({"status": "failed", "reason": "No YARA file compiled successfully."})
        write_json(output_dir / "status.json", status)
        return None, status
    try:
        compiled = yara.compile(filepaths=valid)
        compiled_path = output_dir / "ramscope_rules.yarac"
        compiled.save(str(compiled_path))
        status.update({"status": "success", "compiled_pack": str(compiled_path), "compiled_sha256": _sha256(compiled_path)})
    except Exception as exc:  # noqa: BLE001 - namespace-level conflicts must be visible and fail-soft.
        status.update({"status": "failed", "reason": f"Could not build namespaced rule pack: {str(exc)[:1000]}"})
        write_json(output_dir / "status.json", status)
        return None, status
    write_json(output_dir / "status.json", status)
    return compiled_path, status


class YaraScanner:
    def __init__(self, rules_dir: Path | list[Path] | None, compiled_path: Path | None = None, timeout_seconds: int = 60) -> None:
        if rules_dir is None:
            self.rule_dirs: list[Path] = []
        elif isinstance(rules_dir, Path):
            self.rule_dirs = [rules_dir]
        else:
            self.rule_dirs = list(rules_dir)
        self.compiled_path = compiled_path
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.last_status: dict[str, Any] = {"status": "not_run", "targets": [], "matches": 0, "errors": []}

    def scan_directory(self, target_dir: Path) -> list[Finding]:
        if not target_dir.exists():
            self.last_status = {"status": "skipped", "reason": "Target dump directory does not exist.", "targets": [], "matches": 0, "errors": []}
            return []
        try:
            import yara
        except ImportError:
            self.last_status = {"status": "unavailable", "reason": "yara-python is not installed.", "targets": [], "matches": 0, "errors": []}
            return []
        try:
            if self.compiled_path and self.compiled_path.is_file():
                rules = yara.load(str(self.compiled_path))
            else:
                files = _rule_files(self.rule_dirs)
                if not files:
                    self.last_status = {"status": "skipped", "reason": "No valid YARA source was supplied.", "targets": [], "matches": 0, "errors": []}
                    return []
                namespaces = {_namespace(path.stem, index, set()): str(path) for index, path in enumerate(files, start=1)}
                rules = yara.compile(filepaths=namespaces)
        except Exception as exc:  # noqa: BLE001
            self.last_status = {"status": "failed", "reason": str(exc)[:1000], "targets": [], "matches": 0, "errors": []}
            return []

        findings: list[Finding] = []
        status: dict[str, Any] = {"status": "success", "targets": [], "matches": 0, "errors": []}
        for target in sorted(path for path in target_dir.rglob("*") if path.is_file() and path.stat().st_size > 0):
            target_status = {"path": str(target), "sha256": _sha256(target), "status": "success", "matches": 0}
            try:
                matches = rules.match(str(target), timeout=self.timeout_seconds)
                target_status["matches"] = len(matches)
                status["matches"] += len(matches)
            except Exception as exc:  # noqa: BLE001
                target_status.update({"status": "failed", "error": str(exc)[:1000]})
                status["errors"].append({"path": str(target), "error": str(exc)[:1000]})
                status["targets"].append(target_status)
                continue
            for match in matches:
                meta = dict(getattr(match, "meta", {}) or {})
                severity = str(meta.get("severity", "High")).title()
                if severity not in {"Low", "Medium", "High", "Critical"}:
                    severity = "High"
                techniques = _mitre_values(meta)
                namespace = str(getattr(match, "namespace", "default"))
                detail = f"Rule {match.rule} namespace={namespace} matched {target.name}; dump_sha256={target_status['sha256']}"
                findings.append(Finding(
                    "", None, "", f"YARA hit: {match.rule}", severity, 70, "possible", "yara",
                    [{"source": "yara", "detail": detail}],
                    "Review rule metadata, matched bytes, target process identity, and goodware prevalence before concluding.",
                    mitre_techniques=techniques,
                ))
            status["targets"].append(target_status)
        if status["errors"]:
            status["status"] = "partial"
        self.last_status = status
        return findings


def _rule_files(rule_dirs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in rule_dirs:
        if path.is_file() and path.suffix.lower() in {".yar", ".yara"}:
            files.append(path.resolve())
        elif path.is_dir():
            files.extend(candidate.resolve() for candidate in path.rglob("*") if candidate.is_file() and candidate.suffix.lower() in {".yar", ".yara"})
    return sorted(dict.fromkeys(files))


def _namespace(stem: str, index: int, used: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9_]", "_", stem)[:48] or "rules"
    candidate = f"{base}_{index:04d}"
    while candidate in used:
        index += 1
        candidate = f"{base}_{index:04d}"
    used.add(candidate)
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mitre_values(meta: dict[str, Any]) -> list[str]:
    raw = meta.get("mitre_attack") or meta.get("mitre") or meta.get("attack") or ""
    if isinstance(raw, (list, tuple)):
        values = [str(item) for item in raw]
    else:
        values = re.split(r"[,;\s]+", str(raw))
    return sorted({value.upper() for value in values if re.fullmatch(r"T\d{4}(?:\.\d{3})?", value.upper())})
