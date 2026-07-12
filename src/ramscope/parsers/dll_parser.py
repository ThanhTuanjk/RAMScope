from __future__ import annotations

from typing import Any

from ramscope.parsers.base_parser import BaseParser, get_first, to_int


class DllParser(BaseParser):
    source_plugin = "windows.dlllist"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "pid": to_int(get_first(row, ["PID", "Pid", "ProcessId", "process_id"])),
            "process_name": str(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
            "base": str(get_first(row, ["Base", "base"])),
            "size": str(get_first(row, ["Size", "size"])),
            "path": str(get_first(row, ["Path", "FullDllName", "File output", "path"])),
            "source_plugin": self.source_plugin,
        }
