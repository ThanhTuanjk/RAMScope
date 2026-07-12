from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class VolatilityCommandBuilder:
    command: str = "vol"
    renderer: str = "json"
    quiet: bool = True

    def build(self, input_file: Path, plugin: str, extra_args: list[str] | None = None) -> list[str]:
        argv = [self.command]
        if self.quiet:
            argv.append("-q")
        argv.extend(["-f", str(input_file), "-r", self.renderer, plugin])
        if extra_args:
            argv.extend(extra_args)
        return argv
