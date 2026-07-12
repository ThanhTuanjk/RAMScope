from __future__ import annotations

from typing import Any

from ramscope.parsers.base_parser import BaseParser, get_first, to_int
from ramscope.parsers.process_parser import _process_key


class PstreeParser(BaseParser):
    source_plugin = "windows.pstree"

    def normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        pid = to_int(get_first(row, ["PID", "Pid", "ProcessId", "process_id"]))
        create_time = str(get_first(row, ["CreateTime", "Created", "create_time"]))
        offset = str(get_first(row, ["Offset(V)", "Offset", "EPROCESS", "Offset(P)", "eprocess_offset"]))
        return {
            "pid": pid,
            "ppid": to_int(get_first(row, ["PPID", "ParentPID", "InheritedFromUniqueProcessId", "ppid"])),
            "name": str(get_first(row, ["ImageFileName", "Name", "Process", "process_name"])),
            "image_path": str(get_first(row, ["ImagePath", "Path", "File output", "image_path"])),
            "create_time": create_time,
            "exit_time": str(get_first(row, ["ExitTime", "Exited", "exit_time"])),
            "eprocess_offset": offset,
            "process_key": _process_key(pid, offset, create_time),
            "source_plugin": self.source_plugin,
        }
