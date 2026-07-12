from __future__ import annotations

from typing import Any

from ramscope.parsers.base_parser import BaseParser, get_first, to_int


class ServiceParser(BaseParser):
    source_plugin = "windows.svcscan"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "pid": to_int(get_first(row, ["PID", "Pid", "process_id"])),
            "process_name": str(get_first(row, ["Process", "ImageFileName", "process_name"])),
            "service_name": str(get_first(row, ["Name", "ServiceName", "name"])),
            "display_name": str(get_first(row, ["Display", "DisplayName", "display_name"])),
            "binary": str(get_first(row, ["Binary", "Binary Path", "ImagePath", "binary"])),
            "state": str(get_first(row, ["State", "state"])),
            "start": str(get_first(row, ["Start", "StartType", "start"])),
            "source_plugin": self.source_plugin,
        }
