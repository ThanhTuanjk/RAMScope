from __future__ import annotations

import hashlib
import importlib.metadata
import os
import re
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ramscope.volatility.command_builder import VolatilityCommandBuilder


@dataclass(frozen=True)
class PluginRunResult:
    plugin: str
    command: list[str]
    return_code: int
    output_path: Path | None
    error_path: Path | None
    timed_out: bool = False
    dump_files: list[Path] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    stdout_sha256: str = ""
    error_sha256: str = ""
    dump_hashes: dict[str, str] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0 and not self.timed_out


class VolatilityRunner:
    def __init__(self, builder: VolatilityCommandBuilder, timeout_seconds: int = 600) -> None:
        self.builder = builder
        self.timeout_seconds = max(1, int(timeout_seconds))
        self._available_plugins: set[str] | None = None

    def _help(self) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                [self.builder.command, "--help"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None

    def is_available(self) -> bool:
        completed = self._help()
        return completed is not None and completed.returncode in (0, 1)

    def available_plugins(self) -> set[str]:
        if self._available_plugins is not None:
            return set(self._available_plugins)
        completed = self._help()
        if completed is None:
            self._available_plugins = set()
            return set()
        output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        pattern = re.compile(r"^\s{4}([a-z][A-Za-z0-9_.]+)\s{2,}", re.MULTILINE)
        self._available_plugins = {match.group(1) for match in pattern.finditer(output)}
        return set(self._available_plugins)

    def version_text(self) -> str:
        if not self.is_available():
            return "unavailable"
        try:
            return importlib.metadata.version("volatility3")
        except importlib.metadata.PackageNotFoundError:
            return "command available; package version unavailable"

    def run_plugin(
        self,
        input_file: Path,
        plugin: str,
        raw_dir: Path,
        *,
        plugin_args: list[str] | None = None,
        dump_dir: Path | None = None,
        dump: bool = False,
        dump_args: list[str] | None = None,
        resolved_plugin: str | None = None,
        timeout_seconds: int | None = None,
        output_id: str | None = None,
    ) -> PluginRunResult:
        raw_dir.mkdir(parents=True, exist_ok=True)
        error_dir = raw_dir / "errors"
        error_dir.mkdir(parents=True, exist_ok=True)
        identifier = output_id or plugin
        output_path = raw_dir / f"{identifier}.json"
        error_path = error_dir / f"{identifier}.error.txt"
        stderr_path = error_dir / f"{identifier}.stderr.tmp"

        args = list(plugin_args or [])
        if dump_args is not None:
            args.extend(dump_args)
        elif dump:
            args.append("--dump")
        command = self.builder.build(input_file, resolved_plugin or plugin, extra_args=args)

        before: dict[Path, str] = {}
        cwd: Path | None = None
        if dump and dump_dir is not None:
            dump_dir.mkdir(parents=True, exist_ok=True)
            cwd = dump_dir
            before = {path.resolve(): _sha256(path) for path in dump_dir.glob("*") if path.is_file()}

        started_at = _utc_now()
        started = time.perf_counter()
        timeout = max(1, int(timeout_seconds or self.timeout_seconds))
        return_code = 127

        try:
            popen_kwargs: dict[str, Any] = {
                "stdout": None,
                "stderr": None,
                "text": True,
                "cwd": str(cwd) if cwd else None,
            }
            if os.name == "nt":
                popen_kwargs["creationflags"] = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            else:
                popen_kwargs["start_new_session"] = True

            with output_path.open("w", encoding="utf-8", errors="replace", newline="\n") as stdout_file, stderr_path.open(
                "w", encoding="utf-8", errors="replace", newline="\n"
            ) as stderr_file:
                popen_kwargs["stdout"] = stdout_file
                popen_kwargs["stderr"] = stderr_file
                process = subprocess.Popen(command, **popen_kwargs)
                try:
                    return_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    _terminate_process_tree(process)
                    stdout_file.flush()
                    stderr_file.flush()
                    stdout_file.close()
                    stderr_file.close()
                    stderr = _read_bounded(stderr_path)
                    _write_text(
                        error_path,
                        f"Plugin timed out after {timeout} seconds.\n"
                        f"Command: {_format_command(command)}\n\n"
                        f"Partial stdout saved at: {output_path}\n\n"
                        f"Partial stderr:\n{stderr}",
                    )
                    dumps = _changed_dump_files(dump_dir, before) if dump and dump_dir is not None else []
                    stderr_path.unlink(missing_ok=True)
                    return self._result(plugin, command, 124, output_path, error_path, True, dumps, started_at, started)
        except OSError as exc:
            _write_text(error_path, f"Could not execute Volatility command.\n{type(exc).__name__}: {exc}\n")
            output_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)
            return self._result(plugin, command, 127, None, error_path, False, [], started_at, started)

        if _file_is_blank(output_path):
            _write_text(output_path, "[]\n")

        dump_files = _changed_dump_files(dump_dir, before) if dump and dump_dir is not None else []
        stderr = _read_bounded(stderr_path)
        stderr_path.unlink(missing_ok=True)
        if return_code != 0:
            _write_text(
                error_path,
                f"Command: {_format_command(command)}\n\nSTDERR:\n{stderr}\n",
            )
            return self._result(plugin, command, return_code, output_path, error_path, False, dump_files, started_at, started)
        error_path.unlink(missing_ok=True)
        return self._result(plugin, command, 0, output_path, None, False, dump_files, started_at, started)

    def _result(
        self,
        plugin: str,
        command: list[str],
        return_code: int,
        output_path: Path | None,
        error_path: Path | None,
        timed_out: bool,
        dump_files: list[Path],
        started_at: str,
        started: float,
    ) -> PluginRunResult:
        return PluginRunResult(
            plugin=plugin,
            command=command,
            return_code=return_code,
            output_path=output_path,
            error_path=error_path,
            timed_out=timed_out,
            dump_files=dump_files,
            started_at=started_at,
            finished_at=_utc_now(),
            duration_seconds=round(time.perf_counter() - started, 3),
            stdout_sha256=_sha256(output_path),
            error_sha256=_sha256(error_path),
            dump_hashes={str(path): _sha256(path) for path in dump_files},
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path | None) -> str:
    if path is None or not path.is_file():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _changed_dump_files(dump_dir: Path | None, before: dict[Path, str]) -> list[Path]:
    if dump_dir is None or not dump_dir.is_dir():
        return []
    changed: list[Path] = []
    for path in sorted(item.resolve() for item in dump_dir.glob("*") if item.is_file()):
        if path not in before or _sha256(path) != before[path]:
            changed.append(path)
    return changed


def _read_bounded(path: Path, limit: int = 1024 * 1024) -> str:
    if not path.is_file():
        return ""
    with path.open("r", encoding="utf-8", errors="replace") as file_obj:
        value = file_obj.read(limit + 1)
    return value[:limit] + ("\n[stderr truncated by RAMScope]" if len(value) > limit else "")


def _file_is_blank(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return True
    with path.open("rb") as file_obj:
        return not file_obj.read(4096).strip()


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _format_command(command: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            process.kill()
    else:
        try:
            killpg = getattr(os, "killpg", None)
            sigkill = getattr(signal, "SIGKILL", 9)
            if callable(killpg):
                killpg(process.pid, sigkill)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            process.kill()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
