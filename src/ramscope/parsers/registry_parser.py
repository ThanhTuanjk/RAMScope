from __future__ import annotations

from typing import Any

from ramscope.parsers.base_parser import BaseParser, get_first, to_int


class RegistryParser(BaseParser):
    source_plugin = "windows.registry.printkey"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        key = str(get_first(row, ["Key", "key", "Path", "Hive Offset", "Last Write Time"]))
        value_name = str(get_first(row, ["Name", "Value", "value_name"]))
        value_data = str(get_first(row, ["Data", "ValueData", "value_data"]))
        text = " ".join([key, value_name, value_data])
        return {
            "pid": to_int(get_first(row, ["PID", "Pid", "process_id"])),
            "process_name": str(get_first(row, ["Process", "ImageFileName", "process_name"])),
            "key": key,
            "value_name": value_name,
            "value_data": value_data,
            "is_run_key": "\\run" in text.lower() or "runonce" in text.lower(),
            "source_plugin": self.source_plugin,
        }
