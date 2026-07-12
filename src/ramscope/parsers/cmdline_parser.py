from __future__ import annotations

from typing import Any

from ramscope.parsers.base_parser import BaseParser, get_first, to_int


class CmdlineParser(BaseParser):
    source_plugin = "windows.cmdline"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "pid": to_int(get_first(row, ["PID", "Pid", "ProcessId", "process_id"])),
            "process_name": str(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
            "command_line": str(get_first(row, ["Args", "CommandLine", "CommandLineString", "command_line"])),
            "source_plugin": self.source_plugin,
        }
