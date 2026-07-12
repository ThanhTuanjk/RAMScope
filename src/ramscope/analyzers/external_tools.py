from __future__ import annotations

import json
import hashlib
import math
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ramscope.models import Finding
from ramscope.utils.json_utils import write_json


SUSPICIOUS_STRING_TOKENS = [
    "powershell",
    "frombase64string",
    "encodedcommand",
    "iex ",
    "http://",
    "https://",
    ".onion",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "schtasks",
    "startup",
    "currentversion\\run",
    "\\appdata\\",
    "\\temp\\",
    "virtualalloc",
    "virtualprotect",
    "createremotethread",
    "writeprocessmemory",
    "loadlibrary",
]

PACKER_TOKENS = [
    "packer",
    "protector",
    "obfuscator",
    "upx",
    "aspack",
    "themida",
    "vmprotect",
    "enigma",
    "mpress",
]


class ExternalToolAnalyzer:
    """Run optional offline tools against suspicious dump files.

    The analyzer is intentionally fail-soft. Missing tools or per-file errors are
    recorded in status JSON instead of stopping the forensic pipeline.
    """

    def __init__(
        self,
        *,
        enable_floss: bool = True,
        enable_capa: bool = True,
        enable_clamav: bool = True,
        enable_die: bool = True,
        enable_pefile: bool = True,
        capa_rules: str = "",
        timeout_seconds: int = 120,
        max_file_size_mb: int = 100,
        max_output_mb: int = 32,
    ) -> None:
        self.enable_floss = enable_floss
        self.enable_capa = enable_capa
        self.enable_clamav = enable_clamav
        self.enable_die = enable_die
        self.enable_pefile = enable_pefile
        self.capa_rules = capa_rules
        self.timeout_seconds = timeout_seconds
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.max_output_bytes = max_output_mb * 1024 * 1024

    def analyze(self, dump_dir: Path, output_dir: Path) -> tuple[list[Finding], list[dict[str, Any]], list[str]]:
        output_dir.mkdir(parents=True, exist_ok=True)
        findings: list[Finding] = []
        status: list[dict[str, Any]] = []
        suspicious_strings: list[str] = []
        dump_files = self._dump_files(dump_dir)

        if not dump_files:
            status.append({"tool": "external-tools", "status": "skipped", "detail": "No suspicious memory dump files were available."})
            write_json(output_dir / "status.json", status)
            return findings, status, suspicious_strings

        if self.enable_pefile:
            pe_findings, pe_status = self._run_pefile(dump_files, output_dir / "pefile")
            findings.extend(pe_findings)
            status.extend(pe_status)
        else:
            status.append({"tool": "pefile", "status": "disabled"})

        if self.enable_floss:
            floss_findings, floss_status, floss_strings = self._run_floss(dump_files, output_dir / "floss")
            findings.extend(floss_findings)
            status.extend(floss_status)
            suspicious_strings.extend(floss_strings)
        else:
            status.append({"tool": "floss", "status": "disabled"})

        if self.enable_capa:
            capa_findings, capa_status = self._run_capa(dump_files, output_dir / "capa")
            findings.extend(capa_findings)
            status.extend(capa_status)
        else:
            status.append({"tool": "capa", "status": "disabled"})

        if self.enable_clamav:
            clamav_findings, clamav_status = self._run_clamav(dump_files, output_dir / "clamav")
            findings.extend(clamav_findings)
            status.extend(clamav_status)
        else:
            status.append({"tool": "clamav", "status": "disabled"})

        if self.enable_die:
            die_findings, die_status = self._run_die(dump_files, output_dir / "die")
            findings.extend(die_findings)
            status.extend(die_status)
        else:
            status.append({"tool": "die", "status": "disabled"})

        write_json(output_dir / "status.json", status)
        if suspicious_strings:
            (output_dir / "suspicious_strings.txt").write_text("\n".join(dict.fromkeys(suspicious_strings)) + "\n", encoding="utf-8")
        return findings, status, list(dict.fromkeys(suspicious_strings))

    def _dump_files(self, dump_dir: Path) -> list[Path]:
        if not dump_dir.exists():
            return []
        return sorted(path for path in dump_dir.rglob("*") if path.is_file() and path.stat().st_size > 0)

    def _should_scan(self, path: Path, tool: str, status: list[dict[str, Any]]) -> bool:
        size = path.stat().st_size
        if size > self.max_file_size:
            status.append({"tool": tool, "file": str(path), "status": "skipped_large", "size": size})
            return False
        return True

    def _run_command(self, command: list[str], output_path: Path) -> tuple[int, str, str, bool]:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.tmp")
        try:
            with output_path.open("w", encoding="utf-8", errors="replace") as stdout_file, stderr_path.open("w", encoding="utf-8", errors="replace") as stderr_file:
                process = subprocess.Popen(command, stdout=stdout_file, stderr=stderr_file, text=True)
                try:
                    return_code = process.wait(timeout=self.timeout_seconds)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    stdout = _read_bounded(output_path, self.max_output_bytes)
                    stderr = _read_bounded(stderr_path, self.max_output_bytes)
                    stderr_path.unlink(missing_ok=True)
                    return 124, stdout, stderr, True
        except OSError as exc:
            output_path.write_text(f"Execution failed.\n{exc}\n", encoding="utf-8")
            stderr_path.unlink(missing_ok=True)
            return 127, "", str(exc), False
        stdout = _read_bounded(output_path, self.max_output_bytes)
        stderr = _read_bounded(stderr_path, self.max_output_bytes)
        stderr_path.unlink(missing_ok=True)
        return return_code, stdout, stderr, False

    def _run_floss(self, files: list[Path], output_dir: Path) -> tuple[list[Finding], list[dict[str, Any]], list[str]]:
        tool = shutil.which("floss")
        status: list[dict[str, Any]] = []
        findings: list[Finding] = []
        suspicious_strings: list[str] = []
        if not tool:
            return [], [{"tool": "floss", "status": "unavailable", "detail": "floss was not found on PATH."}], []
        for path in files:
            if not self._should_scan(path, "floss", status):
                continue
            out = output_dir / f"{_safe_name(path)}.txt"
            code, stdout, stderr, timed_out = self._run_command([tool, str(path)], out)
            status.append({"tool": "floss", "file": str(path), "status": _status(code, timed_out), "return_code": code, "output": str(out)})
            lines = _interesting_lines(stdout)
            suspicious = [line for line in lines if _contains_any(line, SUSPICIOUS_STRING_TOKENS)]
            suspicious_strings.extend(f"{path.name}: {line}" for line in suspicious[:50])
            if suspicious:
                findings.append(Finding("", None, "", "Possible suspicious strings recovered from memory dump", "Medium", 35, "possible", "strings", [{"source": "floss", "detail": f"{len(suspicious)} suspicious string candidates in {path.name}; output={out}"}]))
            elif code not in (0, 1) and stderr:
                status.append({"tool": "floss", "file": str(path), "status": "error", "detail": stderr[:500]})
        return findings, status, suspicious_strings

    def _run_capa(self, files: list[Path], output_dir: Path) -> tuple[list[Finding], list[dict[str, Any]]]:
        tool = shutil.which("capa")
        status: list[dict[str, Any]] = []
        findings: list[Finding] = []
        if not tool:
            return [], [{"tool": "capa", "status": "unavailable", "detail": "capa was not found on PATH."}]
        for path in files:
            if not self._should_scan(path, "capa", status):
                continue
            out = output_dir / f"{_safe_name(path)}.json"
            command = [tool, "-j"]
            if self.capa_rules:
                command.extend(["-r", self.capa_rules])
            command.append(str(path))
            code, stdout, stderr, timed_out = self._run_command(command, out)
            has_signal = _capa_has_signal(stdout)
            if code != 0 and not has_signal:
                fallback = output_dir / f"{_safe_name(path)}.txt"
                fallback_command = [tool]
                if self.capa_rules:
                    fallback_command.extend(["-r", self.capa_rules])
                fallback_command.append(str(path))
                code, stdout, stderr, timed_out = self._run_command(fallback_command, fallback)
                out = fallback
                has_signal = _capa_text_has_signal(stdout)
            status.append({"tool": "capa", "file": str(path), "status": _status(code, timed_out), "return_code": code, "output": str(out)})
            if has_signal:
                findings.append(Finding("", None, "", "Possible executable capability signals recovered from memory dump", "High", 60, "possible", "capability", [{"source": "capa", "detail": f"capa reported capability matches for {path.name}; output={out}"}]))
            elif code not in (0, 1) and stderr:
                status.append({"tool": "capa", "file": str(path), "status": "error", "detail": stderr[:500]})
        return findings, status

    def _run_clamav(self, files: list[Path], output_dir: Path) -> tuple[list[Finding], list[dict[str, Any]]]:
        tool = shutil.which("clamscan")
        status: list[dict[str, Any]] = []
        findings: list[Finding] = []
        if not tool:
            return [], [{"tool": "clamav", "status": "unavailable", "detail": "clamscan was not found on PATH."}]
        for path in files:
            if not self._should_scan(path, "clamav", status):
                continue
            out = output_dir / f"{_safe_name(path)}.txt"
            code, stdout, stderr, timed_out = self._run_command([tool, "--no-summary", str(path)], out)
            status.append({"tool": "clamav", "file": str(path), "status": _status(code, timed_out), "return_code": code, "output": str(out)})
            if "FOUND" in stdout:
                findings.append(Finding("", None, "", "Possible antivirus signature match on memory dump", "High", 60, "possible", "av", [{"source": "clamav", "detail": f"clamscan returned a signature match for {path.name}; output={out}"}]))
            elif code not in (0, 1) and stderr:
                status.append({"tool": "clamav", "file": str(path), "status": "error", "detail": stderr[:500]})
        return findings, status

    def _run_die(self, files: list[Path], output_dir: Path) -> tuple[list[Finding], list[dict[str, Any]]]:
        tool = _find_die()
        status: list[dict[str, Any]] = []
        findings: list[Finding] = []
        if not tool:
            return [], [{"tool": "die", "status": "unavailable", "detail": "Detect-It-Easy CLI was not found on PATH."}]
        for path in files:
            if not self._should_scan(path, "die", status):
                continue
            out = output_dir / f"{_safe_name(path)}.txt"
            code, stdout, stderr, timed_out = self._run_command([tool, str(path)], out)
            status.append({"tool": "die", "file": str(path), "status": _status(code, timed_out), "return_code": code, "output": str(out)})
            if _contains_any(stdout, PACKER_TOKENS):
                findings.append(Finding("", None, "", "Possible packer or protector signal on memory dump", "Medium", 30, "possible", "packer", [{"source": "detect-it-easy", "detail": f"Detect-It-Easy output contains packer/protector terms for {path.name}; output={out}"}]))
            elif code not in (0, 1) and stderr:
                status.append({"tool": "die", "file": str(path), "status": "error", "detail": stderr[:500]})
        return findings, status

    def _run_pefile(self, files: list[Path], output_dir: Path) -> tuple[list[Finding], list[dict[str, Any]]]:
        status: list[dict[str, Any]] = []
        findings: list[Finding] = []
        try:
            import pefile
        except ImportError:
            return [], [{"tool": "pefile", "status": "unavailable", "detail": "pefile Python package is not installed."}]
        output_dir.mkdir(parents=True, exist_ok=True)
        for path in files:
            if not self._should_scan(path, "pefile", status):
                continue
            if not _has_mz_header(path):
                status.append({"tool": "pefile", "file": str(path), "status": "skipped", "detail": "No MZ header at file start."})
                continue
            out = output_dir / f"{_safe_name(path)}.json"
            try:
                pe = pefile.PE(str(path), fast_load=True)
                pe.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    ]
                )
                metadata = _pe_metadata(pe)
                write_json(out, metadata)
                status.append({"tool": "pefile", "file": str(path), "status": "success", "output": str(out)})
                anomalies = _pe_anomalies(metadata)
                if anomalies:
                    findings.append(Finding("", None, "", "Possible PE metadata anomaly in dumped memory", "Medium", 35, "possible", "pe_metadata", [{"source": "pefile", "detail": f"{'; '.join(anomalies)} for {path.name}; output={out}"}]))
            except Exception as exc:  # noqa: BLE001 - preserve analysis continuity for malformed dumps.
                status.append({"tool": "pefile", "file": str(path), "status": "error", "detail": str(exc)[:500]})
        return findings, status


def _safe_name(path: Path) -> str:
    suffix = hashlib.sha256(str(path.resolve()).casefold().encode("utf-8")).hexdigest()[:12]
    return f"{suffix}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', path.name)}"


def _read_bounded(path: Path, limit: int) -> str:
    if not path.is_file():
        return ""
    with path.open("r", encoding="utf-8", errors="replace") as file_obj:
        value = file_obj.read(limit + 1)
    return value[:limit] + ("\n[output truncated by RAMScope]" if len(value) > limit else "")


def _status(return_code: int, timed_out: bool) -> str:
    if timed_out:
        return "timeout"
    if return_code == 0:
        return "success"
    if return_code == 1:
        return "signal_or_partial"
    return "failed"


def _find_die() -> str | None:
    for candidate in ("diec", "diec.exe", "die", "die.exe"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _interesting_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if len(line) < 5 or len(line) > 500:
            continue
        if line.startswith(("FLOSS", "INFO:", "WARNING:", "ERROR:")):
            continue
        lines.append(line)
    return lines


def _contains_any(text: str, tokens: list[str]) -> bool:
    lowered = text.lower()
    return any(token.lower() in lowered for token in tokens)


def _capa_has_signal(text: str) -> bool:
    if not text.strip():
        return False
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return _capa_text_has_signal(text)
    rules = data.get("rules") if isinstance(data, dict) else None
    if isinstance(rules, dict):
        return bool(rules)
    return _capa_text_has_signal(text)


def _capa_text_has_signal(text: str) -> bool:
    lowered = text.lower()
    if not lowered.strip() or "0 matches" in lowered or "no capabilities found" in lowered:
        return False
    return any(token in lowered for token in ["namespace", "capability", "att&ck", "maec", "mbc"])


def _has_mz_header(path: Path) -> bool:
    try:
        return path.read_bytes()[:2] == b"MZ"
    except OSError:
        return False


def _pe_metadata(pe: Any) -> dict[str, Any]:
    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        data = section.get_data() or b""
        sections.append(
            {
                "name": name,
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "characteristics": int(section.Characteristics),
                "entropy": round(_entropy(data), 3),
                "executable": bool(section.Characteristics & 0x20000000),
                "writable": bool(section.Characteristics & 0x80000000),
            }
        )
    imports: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
        imports.append(dll)
    return {
        "machine": int(pe.FILE_HEADER.Machine),
        "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
        "number_of_sections": int(pe.FILE_HEADER.NumberOfSections),
        "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
        "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
        "imports": imports,
        "sections": sections,
    }


def _pe_anomalies(metadata: dict[str, Any]) -> list[str]:
    anomalies: list[str] = []
    sections = metadata.get("sections", [])
    if isinstance(sections, list):
        if any(float(section.get("entropy", 0)) >= 7.2 for section in sections if isinstance(section, dict)):
            anomalies.append("high entropy section")
        if any(section.get("executable") and section.get("writable") for section in sections if isinstance(section, dict)):
            anomalies.append("executable and writable section")
    if not metadata.get("imports"):
        anomalies.append("no import table recovered")
    return anomalies


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)
