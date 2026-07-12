from __future__ import annotations

from typing import Any

from ramscope.parsers.base_parser import BaseParser, get_first, to_int
from ramscope.parsers.process_parser import _process_key
from ramscope.utils.forensic import boolish, text


def to_boolish(value: Any) -> bool | None:
    """Compatibility alias used by older tests and integrations."""
    return boolish(value)


def _identity(row: dict[str, Any]) -> tuple[int | None, str, str, str]:
    pid = to_int(get_first(row, ["PID", "Pid", "ProcessId", "process_id"]))
    offset = text(get_first(row, ["Offset(V)", "EPROCESS", "ProcessOffset", "eprocess_offset"]))
    create_time = text(get_first(row, ["CreateTime", "Created", "create_time"]))
    return pid, offset, create_time, _process_key(pid, offset, create_time)


def _normalized_raw_fields(row: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, value in row.items():
        key = str(raw_key).strip().casefold().replace(" ", "_").replace("-", "_")
        parsed_bool = boolish(value)
        result[key] = parsed_bool if parsed_bool is not None else value
    return result


class LdrModulesParser(BaseParser):
    source_plugin = "windows.ldrmodules"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        pid, offset, _, key = _identity(row)
        return {
            "pid": pid,
            "eprocess_offset": offset,
            "process_key": key,
            "process_name": text(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
            "base": text(get_first(row, ["Base", "base", "DllBase"])),
            "path": text(get_first(row, ["Path", "FullDllName", "File output", "MappedPath", "path"])),
            "in_load": boolish(get_first(row, ["InLoad", "Load", "InLoadOrderModuleList", "in_load"])),
            "in_init": boolish(get_first(row, ["InInit", "Init", "InInitializationOrderModuleList", "in_init"])),
            "in_mem": boolish(get_first(row, ["InMem", "Mem", "InMemoryOrderModuleList", "in_mem"])),
            "source_plugin": self.source_plugin,
            "raw_fields": _normalized_raw_fields(row),
        }


class VadInfoParser(BaseParser):
    source_plugin = "windows.vadinfo"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        pid, offset, _, key = _identity(row)
        return {
            "pid": pid,
            "eprocess_offset": offset,
            "process_key": key,
            "process_name": text(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
            "vad_start": text(get_first(row, ["Start VPN", "Start", "VadStart", "StartVpn", "vad_start"])),
            "vad_end": text(get_first(row, ["End VPN", "End", "VadEnd", "EndVpn", "vad_end"])),
            "protection": text(get_first(row, ["Protection", "protect", "protection"])),
            "tag": text(get_first(row, ["Tag", "tag"])),
            "file_output": text(get_first(row, ["File output", "FileName", "Path", "file_output"])),
            "private_memory": boolish(get_first(row, ["PrivateMemory", "Private", "private_memory"])),
            "source_plugin": self.source_plugin,
            "raw_fields": _normalized_raw_fields(row),
        }


class HandlesParser(BaseParser):
    source_plugin = "windows.handles"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        pid, offset, _, key = _identity(row)
        return {
            "pid": pid,
            "eprocess_offset": offset,
            "process_key": key,
            "process_name": text(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
            "handle_type": text(get_first(row, ["Type", "HandleType", "type"])),
            "name": text(get_first(row, ["Name", "Details", "Object", "name"])),
            "source_plugin": self.source_plugin,
            "raw_fields": _normalized_raw_fields(row),
        }


class PrivsParser(BaseParser):
    source_plugin = "windows.privs"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        pid, offset, _, key = _identity(row)
        return {
            "pid": pid,
            "eprocess_offset": offset,
            "process_key": key,
            "process_name": text(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
            "privilege": text(get_first(row, ["Privilege", "Name", "privilege"])),
            "present": boolish(get_first(row, ["Present", "present"])),
            "enabled": boolish(get_first(row, ["Enabled", "enabled"])),
            "source_plugin": self.source_plugin,
            "raw_fields": _normalized_raw_fields(row),
        }


class ProcessCrossViewParser(BaseParser):
    def __init__(self, source_plugin: str) -> None:
        self.source_plugin = source_plugin

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        pid, offset, create_time, key = _identity(row)
        normalized: dict[str, Any] = {
            "pid": pid,
            "ppid": to_int(get_first(row, ["PPID", "ParentPID", "InheritedFromUniqueProcessId", "ppid"])),
            "name": text(get_first(row, ["ImageFileName", "Process", "Name", "process_name"])),
            "image_path": text(get_first(row, ["ImagePath", "Path", "File output", "image_path"])),
            "create_time": create_time,
            "exit_time": text(get_first(row, ["ExitTime", "Exited", "exit_time"])),
            "eprocess_offset": offset,
            "process_key": key,
            "source_plugin": self.source_plugin,
            "raw_fields": _normalized_raw_fields(row),
        }
        normalized.update({key: value for key, value in normalized["raw_fields"].items() if isinstance(value, bool)})
        normalized["details"] = " ".join(f"{raw_key}={value}" for raw_key, value in row.items() if value not in (None, ""))
        return normalized


class ProcessSignalParser(BaseParser):
    def __init__(self, source_plugin: str) -> None:
        self.source_plugin = source_plugin

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        pid, offset, _, key = _identity(row)
        raw_fields = _normalized_raw_fields(row)
        normalized: dict[str, Any] = {
            "pid": pid,
            "eprocess_offset": offset,
            "process_key": key,
            "process_name": text(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
            "address": text(get_first(row, ["Address", "Start", "Offset", "Base", "address"])),
            "path": text(get_first(row, ["Path", "ImagePath", "FileName", "MappedPath", "path"])),
            "notes": text(get_first(row, ["Notes", "Note", "Reason", "Description", "Status"])),
            "file_object": text(get_first(row, ["FILE_OBJECT", "FileObject", "File Object"])),
            "delete_pending": boolish(get_first(row, ["DeletePending", "Delete Pending", "delete_pending"])),
            "delete_on_close": boolish(get_first(row, ["DeleteOnClose", "Delete On Close", "delete_on_close"])),
            "details": " ".join(f"{raw_key}={value}" for raw_key, value in row.items() if value not in (None, "")),
            "source_plugin": self.source_plugin,
            "raw_fields": raw_fields,
        }
        for raw_key, value in raw_fields.items():
            if isinstance(value, bool):
                normalized[raw_key] = value
        return normalized


class GenericDeepParser(BaseParser):
    def __init__(self, source_plugin: str) -> None:
        self.source_plugin = source_plugin

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        pid, offset, _, key = _identity(row)
        normalized = dict(row)
        normalized.update(
            {
                "pid": pid,
                "eprocess_offset": offset,
                "process_key": key,
                "process_name": text(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
                "details": " ".join(f"{raw_key}={value}" for raw_key, value in row.items() if value not in (None, "")),
                "source_plugin": self.source_plugin,
                "raw_fields": _normalized_raw_fields(row),
            }
        )
        return normalized
