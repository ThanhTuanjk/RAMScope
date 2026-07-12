from __future__ import annotations

from typing import Any

from ramscope.models import MalfindArtifact
from ramscope.parsers.base_parser import BaseParser, get_first, to_int


class MalfindParser(BaseParser):
    source_plugin = "windows.malfind"

    def normalize(self, row: dict[str, Any]) -> MalfindArtifact:
        hexdump = str(get_first(row, ["Hexdump", "Disasm", "Data", "hexdump"]))
        return MalfindArtifact(
            pid=to_int(get_first(row, ["PID", "Pid", "ProcessId", "process_id"])),
            process_name=str(get_first(row, ["Process", "ImageFileName", "Name", "process_name"])),
            vad_start=str(get_first(row, ["Start VPN", "Start", "VadStart", "vad_start"])),
            vad_end=str(get_first(row, ["End VPN", "End", "VadEnd", "vad_end"])),
            protection=str(get_first(row, ["Protection", "protect", "protection"])),
            tag=str(get_first(row, ["Tag", "tag"])),
            has_pe_header=("MZ" in hexdump[:128] or "4d 5a" in hexdump.lower()[:256]),
            source_plugin=self.source_plugin,
        )
