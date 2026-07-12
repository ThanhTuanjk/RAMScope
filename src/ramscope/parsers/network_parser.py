from __future__ import annotations

from typing import Any

from ramscope.models import NetworkArtifact
from ramscope.parsers.base_parser import BaseParser, get_first, to_int


class NetworkParser(BaseParser):
    source_plugin = "windows.netscan"

    def normalize(self, row: dict[str, Any]) -> NetworkArtifact:
        return NetworkArtifact(
            pid=to_int(get_first(row, ["PID", "Pid", "OwnerPid", "process_id"])),
            process_name=str(get_first(row, ["Owner", "Process", "ImageFileName", "process_name"])),
            protocol=str(get_first(row, ["Proto", "Protocol", "protocol"])),
            local_addr=str(get_first(row, ["LocalAddr", "Local Address", "local_addr"])),
            local_port=to_int(get_first(row, ["LocalPort", "Local Port", "local_port"])),
            remote_addr=str(get_first(row, ["ForeignAddr", "RemoteAddr", "Foreign Address", "remote_addr"])),
            remote_port=to_int(get_first(row, ["ForeignPort", "RemotePort", "Foreign Port", "remote_port"])),
            state=str(get_first(row, ["State", "state"])),
            source_plugin=self.source_plugin,
        )
