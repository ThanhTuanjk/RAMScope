from __future__ import annotations

from typing import Any

from ramscope.parsers.base_parser import BaseParser, get_first, to_int
from ramscope.parsers.process_parser import _process_key


def _common(row: dict[str, Any], source_plugin: str) -> dict[str, Any]:
    pid = to_int(get_first(row, ["PID", "Pid", "ProcessId", "process_id"]))
    offset = str(get_first(row, ["ProcessOffset", "EPROCESS", "Offset(V)", "eprocess_offset"]))
    create_time = str(get_first(row, ["CreateTime", "Created", "create_time"]))
    return {
        "pid": pid,
        "process_name": str(get_first(row, ["Process", "ImageFileName", "Owner", "process_name"])),
        "eprocess_offset": offset,
        "process_key": _process_key(pid, offset, create_time),
        "source_plugin": source_plugin,
        "details": " ".join(f"{key}={value}" for key, value in row.items() if value not in (None, "")),
    }


class GenericFullParser(BaseParser):
    def __init__(self, source_plugin: str) -> None:
        self.source_plugin = source_plugin

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(row)
        normalized.update(_common(row, self.source_plugin))
        normalized["name"] = str(get_first(row, ["Name", "FileName", "ModuleName", "DriverName", "Symbol", "Routine", "Detail", "name"]))
        normalized["path"] = str(get_first(row, ["Path", "FileName", "ImagePath", "FullDllName", "MappedPath", "File output", "path"]))
        normalized["module"] = str(get_first(row, ["Module", "ModuleName", "Owner", "module"]))
        normalized["offset"] = str(get_first(row, ["Offset", "Offset(V)", "Offset(P)", "Virtual", "Physical", "Address", "Start", "offset"]))
        normalized["address"] = str(get_first(row, ["Address", "Start", "Virtual", "Offset", "address"]))
        return normalized


class ModuleParser(BaseParser):
    def __init__(self, source_plugin: str) -> None:
        self.source_plugin = source_plugin

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = _common(row, self.source_plugin)
        item.update({
            "name": str(get_first(row, ["Name", "ModuleName", "BaseDllName", "FileName"])),
            "path": str(get_first(row, ["Path", "FullDllName", "FileName", "ImagePath"])),
            "base": str(get_first(row, ["Base", "DllBase", "Start", "Offset"])),
            "size": to_int(get_first(row, ["Size", "SizeOfImage", "ImageSize"])),
        })
        return item


class DriverParser(ModuleParser):
    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = super().normalize(row)
        item["service_key"] = str(get_first(row, ["ServiceKey", "Service Key", "RegistryPath"] ))
        item["driver_start"] = str(get_first(row, ["DriverStart", "Start", "Base"] ))
        return item


class CallbackParser(BaseParser):
    def __init__(self, source_plugin: str = "windows.callbacks") -> None:
        self.source_plugin = source_plugin

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = _common(row, self.source_plugin)
        item.update({
            "callback_type": str(get_first(row, ["Type", "CallbackType", "Notification"])),
            "address": str(get_first(row, ["Callback", "Address", "Routine", "Offset"])),
            "module": str(get_first(row, ["Module", "ModuleName", "Owner"])),
            "symbol": str(get_first(row, ["Symbol", "Detail", "Function"])),
        })
        return item


class SsdtParser(CallbackParser):
    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = super().normalize(row)
        item["index"] = to_int(get_first(row, ["Index", "Entry", "Syscall"] ))
        return item


class VadYaraParser(BaseParser):
    source_plugin = "windows.vadyarascan"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = _common(row, self.source_plugin)
        item.update({
            "rule": str(get_first(row, ["Rule", "RuleName", "Name"])),
            "component": str(get_first(row, ["Component", "Namespace"])),
            "address": str(get_first(row, ["Offset", "Address", "Start"])),
            "string": str(get_first(row, ["Value", "String", "Hexdump"])),
        })
        return item


class EvasionParser(BaseParser):
    def __init__(self, source_plugin: str) -> None:
        self.source_plugin = source_plugin

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = _common(row, self.source_plugin)
        item.update({
            "module": str(get_first(row, ["Module", "ModuleName", "DLL"])),
            "function": str(get_first(row, ["Function", "Symbol", "Name", "API"])),
            "address": str(get_first(row, ["Address", "Offset", "Target"])),
            "state": str(get_first(row, ["State", "Result", "Status", "Patched"])),
        })
        return item


class ServiceDiffParser(BaseParser):
    source_plugin = "windows.svcdiff"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = _common(row, self.source_plugin)
        item.update({
            "service_name": str(get_first(row, ["Name", "ServiceName"])),
            "display_name": str(get_first(row, ["Display", "DisplayName"])),
            "binary": str(get_first(row, ["Binary", "BinaryPath", "ImagePath"])),
            "list_present": get_first(row, ["List", "InList", "list_present"]),
            "scan_present": get_first(row, ["Scan", "InScan", "scan_present"]),
        })
        return item


class TimelineParser(BaseParser):
    def __init__(self, source_plugin: str = "timeliner") -> None:
        self.source_plugin = source_plugin

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = _common(row, self.source_plugin)
        item.update({
            "timestamp": str(get_first(row, ["Created Date", "Modified Date", "Accessed Date", "Changed Date", "Time", "Timestamp"])),
            "event_type": str(get_first(row, ["Plugin", "Type", "Description"])),
            "description": str(get_first(row, ["Description", "Item", "Details"])),
        })
        return item


class ScheduledTaskParser(BaseParser):
    source_plugin = "windows.registry.scheduled_tasks"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        item = _common(row, self.source_plugin)
        item.update(
            {
                "task_name": str(get_first(row, ["TaskName", "Task Name", "Name", "Path"])),
                "action": str(get_first(row, ["Action", "Actions", "Command", "Execute", "Program"])),
                "arguments": str(get_first(row, ["Arguments", "Args", "Parameters"])),
                "working_directory": str(get_first(row, ["WorkingDirectory", "Working Directory"])),
                "enabled": get_first(row, ["Enabled", "enabled"]),
                "last_run_time": str(get_first(row, ["LastRunTime", "Last Run Time", "LastRun"])),
                "next_run_time": str(get_first(row, ["NextRunTime", "Next Run Time", "NextRun"])),
            }
        )
        return item
