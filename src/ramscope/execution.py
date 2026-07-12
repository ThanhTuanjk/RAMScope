from __future__ import annotations

import ctypes
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, TypeVar


HEAVY = {
    "windows.malfind",
    "windows.psscan",
    "windows.vadinfo",
    "windows.filescan",
    "windows.modscan",
    "windows.driverscan",
    "windows.vadyarascan",
    "windows.callbacks",
    "windows.ssdt",
    "windows.timers",
    "windows.dumpfiles",
    "windows.memmap",
}
T = TypeVar("T")


def lane(plugin: str) -> str:
    return "heavy" if plugin in HEAVY or ".targeted." in plugin or ".dumpall" in plugin else "light"


def workers(value: str | int, cfg: dict[str, object]) -> int:
    max_parallel = max(1, min(2, int(str(cfg.get("max_parallel_light", 2)))))
    if str(value).casefold() != "auto":
        return max(1, min(max_parallel, int(value)))
    cpu = os.cpu_count() or 1
    memory_gb = _physical_memory_gb()
    if memory_gb is None:
        return 1
    enough_cpu = cpu >= int(str(cfg.get("auto_min_cpus", 4)))
    enough_memory = memory_gb >= float(str(cfg.get("auto_min_memory_gb", 8)))
    return max_parallel if enough_cpu and enough_memory else 1


def _physical_memory_gb() -> float | None:
    """Return installed memory without adding a platform dependency; fail closed on errors."""
    try:
        if os.name == "nt":
            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(status)
            windll = getattr(ctypes, "windll", None)
            if windll is None or not windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return None
            return float(status.ullTotalPhys) / (1024**3)
        sysconf = getattr(os, "sysconf", None)
        if not callable(sysconf):
            return None
        return float(sysconf("SC_PAGE_SIZE") * sysconf("SC_PHYS_PAGES")) / (1024**3)
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def run_jobs(jobs: list[str], worker_count: int, run: Callable[[str], T]) -> list[tuple[str, T]]:
    heavy = [job for job in jobs if lane(job) == "heavy"]
    light = [job for job in jobs if lane(job) == "light"]
    completed: dict[str, T] = {}
    if worker_count > 1 and len(light) > 1:
        with ThreadPoolExecutor(max_workers=min(2, worker_count)) as pool:
            futures = {pool.submit(run, job): job for job in light}
            for future in as_completed(futures):
                completed[futures[future]] = future.result()
    else:
        for job in light:
            completed[job] = run(job)
    for job in heavy:
        completed[job] = run(job)
    return [(job, completed[job]) for job in jobs]
