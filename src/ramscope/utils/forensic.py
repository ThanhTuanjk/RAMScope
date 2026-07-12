from __future__ import annotations

import ipaddress
import re
from typing import Any


UNKNOWN_TEXT = {"", "-", "n/a", "na", "none", "null", "unknown", "unreadable", "notavailable", "not applicable", "notapplicable", "<none>", "<not recovered>", "disabled"}
DEVICE_VOLUME = re.compile(r"^\\device\\harddiskvolume\d+", re.IGNORECASE)
DRIVE_PATH = re.compile(r"^[a-z]:\\", re.IGNORECASE)
ROOT_ALIAS = re.compile(r"^(?:%systemroot%|\\systemroot)(?=\\|$)", re.IGNORECASE)


def optional(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return None if text.casefold() in UNKNOWN_TEXT else text
    return value


def text(value: Any) -> str:
    value = optional(value)
    return "" if value is None else str(value)


def boolish(value: Any) -> bool | None:
    value = optional(value)
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().casefold()
    if lowered in {"true", "yes", "1", "present", "enabled"}:
        return True
    if lowered in {"false", "no", "0", "absent", "disabled"}:
        return False
    return None


def canonical_windows_path(value: Any) -> str:
    candidate = text(value).strip().strip('"').replace("/", "\\")
    candidate = re.sub(r"\\+", r"\\", candidate).casefold()
    candidate = re.sub(r"^\\\\\?\\unc\\", "\\\\", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"^\\\\\?\\", "", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"^\\\?\\\?\\", "", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"^\\\?\\", "", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"^\\\\\.\\", "", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"^%systemroot%", r"c:\\windows", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"^\\systemroot", r"c:\\windows", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"^\\device\\mup", r"\\\\", candidate, flags=re.IGNORECASE)
    candidate = DEVICE_VOLUME.sub("", candidate)
    candidate = re.sub(r"^[a-z]:", "", candidate)
    return candidate.strip("\\")


def is_absolute_windows_path(value: Any) -> bool:
    candidate = text(value)
    return bool(DRIVE_PATH.match(candidate) or DEVICE_VOLUME.match(candidate) or ROOT_ALIAS.match(candidate) or candidate.startswith("\\\\") or candidate.startswith("\\??\\") or candidate.startswith("\\\\?\\"))


def same_windows_path(left: Any, right: Any) -> bool:
    one, two = canonical_windows_path(left), canonical_windows_path(right)
    return bool(one and two and one == two)


def is_system_path(value: Any) -> bool:
    candidate = canonical_windows_path(value)
    return candidate.startswith(("windows\\system32\\", "windows\\syswow64\\"))


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def is_security_or_jit_process(name: str) -> bool:
    value = name.casefold()
    return any(token in value for token in ("msedge", "chrome", "firefox", "webview", "msmpeng", "sysmon", "runtimebroker"))


def truncated_image_name(name: str) -> bool:
    return bool(name and len(name) >= 15 and "." not in name[-4:])
