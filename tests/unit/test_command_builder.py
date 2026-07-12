from pathlib import Path
from ramscope.volatility.command_builder import VolatilityCommandBuilder


def test_command_builder() -> None:
    command = VolatilityCommandBuilder().build(Path("memory.raw"), "windows.pslist")
    assert command == ["vol", "-q", "-f", "memory.raw", "-r", "json", "windows.pslist"]
