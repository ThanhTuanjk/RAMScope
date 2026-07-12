from pathlib import Path

from ramscope.volatility.command_builder import VolatilityCommandBuilder
from ramscope.volatility.runner import VolatilityRunner
import ramscope.volatility.runner as runner_module


def test_command_builder_accepts_plugin_args() -> None:
    command = VolatilityCommandBuilder().build(
        Path("memory.raw"),
        "windows.registry.printkey",
        extra_args=["--key", "Microsoft\\Windows\\CurrentVersion\\Run"],
    )

    assert command[-3:] == ["windows.registry.printkey", "--key", "Microsoft\\Windows\\CurrentVersion\\Run"]


def test_runner_availability_handles_permission_error(monkeypatch) -> None:
    def raise_permission_error(*args, **kwargs):
        raise PermissionError("blocked")

    monkeypatch.setattr(runner_module.subprocess, "run", raise_permission_error)
    runner = VolatilityRunner(VolatilityCommandBuilder())

    assert runner.is_available() is False
    assert runner.version_text() == "unavailable"
