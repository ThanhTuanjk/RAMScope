from ramscope.config import DEFAULT_CONFIG, enabled_plugins, plugin_dump_args_for
from ramscope.volatility.plugin_plan import resolve_plugin


def test_full_profile_adds_full_plugins_without_dump_plugins_by_default() -> None:
    plugins = enabled_plugins(DEFAULT_CONFIG, include_full=True)
    assert "windows.dlllist" in enabled_plugins(DEFAULT_CONFIG)
    assert "windows.vadyarascan" in plugins
    assert "windows.modules" in plugins
    assert "windows.psscan" in plugins
    assert "windows.psxview" in plugins
    assert "windows.hollowprocesses" in plugins
    assert "windows.apihooks" not in plugins
    assert "windows.dumpfiles" not in plugins


def test_full_profile_can_enable_dump_plugins() -> None:
    plugins = enabled_plugins(DEFAULT_CONFIG, include_full=True, include_dump_artifacts=True)
    assert "windows.dumpfiles" in plugins
    assert "windows.memmap" in plugins
    assert plugin_dump_args_for(DEFAULT_CONFIG, "windows.memmap") == ["--dump"]


def test_plugin_resolver_uses_current_canonical_aliases() -> None:
    available = {"windows.privileges.Privs", "windows.malware.psxview.PsXView", "windows.pslist.PsList"}
    assert resolve_plugin("windows.privs", available) == "windows.privileges.Privs"
    assert resolve_plugin("windows.psxview", available) == "windows.malware.psxview.PsXView"
    assert resolve_plugin("windows.pslist", available) == "windows.pslist.PsList"
    assert resolve_plugin("windows.apihooks", available) is None
