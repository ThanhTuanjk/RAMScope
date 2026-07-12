from __future__ import annotations


CORE_PLUGINS = (
    "windows.info", "windows.pslist", "windows.pstree", "windows.cmdline",
    "windows.dlllist", "windows.netscan", "windows.malfind",
)

REGISTRY_JOBS = (
    "windows.registry.printkey_run",
    "windows.registry.printkey_runonce",
    "windows.registry.printkey_wow64_run",
    "windows.registry.printkey_wow64_runonce",
)

EXTENDED_PLUGINS = (
    "windows.psscan", "windows.psxview", "windows.handles", "windows.threads",
    "windows.ldrmodules", "windows.vadinfo", "windows.privs", "windows.envars",
    "windows.getsids", "windows.registry.hivelist", *REGISTRY_JOBS,
    "windows.svcscan", "windows.registry.scheduled_tasks",
)

DEEP_PLUGINS = EXTENDED_PLUGINS + (
    "windows.hollowprocesses", "windows.processghosting", "windows.pebmasquerade",
    "windows.suspicious_threads", "windows.suspended_threads",
)

FULL_PLUGINS = (
    "windows.filescan", "windows.mutantscan", "windows.modules", "windows.modscan",
    "windows.driverscan", "windows.drivermodule", "windows.driverirp", "windows.callbacks",
    "windows.ssdt", "windows.timers", "windows.devicetree", "windows.symlinkscan",
    "windows.unloadedmodules", "windows.svcdiff", "windows.etwpatch",
    "windows.unhooked_system_calls", "windows.skeleton_key_check", "windows.vadyarascan",
    "windows.iat", "timeliner",
)

FULL_DUMP_PLUGINS = ("windows.dumpfiles", "windows.dlllist", "windows.memmap")

PLUGIN_CANDIDATES: dict[str, tuple[str, ...]] = {
    "windows.malfind": ("windows.malware.malfind", "windows.malfind"),
    "windows.ldrmodules": ("windows.malware.ldrmodules", "windows.ldrmodules"),
    "windows.privs": ("windows.privileges",),
    "windows.psxview": ("windows.malware.psxview", "windows.psxview"),
    "windows.hollowprocesses": ("windows.malware.hollowprocesses", "windows.hollowprocesses"),
    "windows.processghosting": ("windows.malware.processghosting", "windows.processghosting"),
    "windows.pebmasquerade": ("windows.malware.pebmasquerade",),
    "windows.suspicious_threads": ("windows.malware.suspicious_threads", "windows.suspicious_threads"),
    "windows.suspended_threads": ("windows.suspended_threads",),
    "windows.drivermodule": ("windows.malware.drivermodule", "windows.drivermodule"),
    "windows.svcdiff": ("windows.malware.svcdiff", "windows.svcdiff"),
    "windows.unhooked_system_calls": ("windows.malware.unhooked_system_calls", "windows.unhooked_system_calls"),
    "windows.skeleton_key_check": ("windows.malware.skeleton_key_check", "windows.skeleton_key_check"),
    "windows.registry.scheduled_tasks": ("windows.registry.scheduled_tasks", "windows.scheduled_tasks"),
    "timeliner": ("timeliner",),
    **{job: ("windows.registry.printkey",) for job in REGISTRY_JOBS},
}


def all_known_plugins() -> tuple[str, ...]:
    return tuple(dict.fromkeys(CORE_PLUGINS + EXTENDED_PLUGINS + DEEP_PLUGINS + FULL_PLUGINS + FULL_DUMP_PLUGINS))


def resolve_plugin(logical_name: str, available_plugins: set[str]) -> str | None:
    candidates = PLUGIN_CANDIDATES.get(logical_name, (logical_name,))
    for candidate in candidates:
        if candidate in available_plugins:
            return candidate
        matches = sorted(name for name in available_plugins if name.startswith(candidate + "."))
        if len(matches) == 1:
            return matches[0]
    return None
