from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from ramscope.models import MalfindArtifact, NetworkArtifact, ProcessProfile


class Correlator:
    def build_profiles(
        self,
        processes: list[dict[str, Any]],
        cmdlines: list[dict[str, Any]],
        dlls: list[dict[str, Any]],
        network: list[NetworkArtifact],
        malfind: list[MalfindArtifact],
        pstree: list[dict[str, Any]] | None = None,
        persistence: list[dict[str, Any]] | None = None,
        dump_files: list[str] | None = None,
        psscan: list[dict[str, Any]] | None = None,
        psxview: list[dict[str, Any]] | None = None,
        context_artifacts: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[ProcessProfile]:
        profiles: dict[str, ProcessProfile] = {}
        pid_index: dict[int, list[ProcessProfile]] = defaultdict(list)

        def create_or_get(row: dict[str, Any], default_source: str) -> ProcessProfile | None:
            pid = row.get("pid")
            if pid is None:
                return None
            key = str(row.get("process_key") or _identity_key(pid, str(row.get("eprocess_offset", "")), str(row.get("create_time", ""))))
            profile = profiles.get(key)
            create_time = str(row.get("create_time", ""))
            if profile is None and create_time:
                compatible = [
                    item for item in pid_index[int(pid)]
                    if item.create_time == create_time
                    and (not item.name or not row.get("name", row.get("process_name", "")) or item.name.lower() == str(row.get("name", row.get("process_name", ""))).lower())
                ]
                if len(compatible) == 1:
                    profile = compatible[0]
                    if key.startswith("eprocess:") and profile.process_key != key:
                        profiles.pop(profile.process_key, None)
                        profile.process_key = key
                        profiles[key] = profile
            if profile is None:
                profile = ProcessProfile(
                    pid=int(pid),
                    name=str(row.get("name", row.get("process_name", ""))),
                    eprocess_offset=str(row.get("eprocess_offset", "")),
                    process_key=key,
                )
                profiles[key] = profile
                pid_index[int(pid)].append(profile)
            profile.ppid = row.get("ppid") if row.get("ppid") is not None else profile.ppid
            profile.image_path = str(row.get("image_path", row.get("path", ""))) or profile.image_path
            profile.create_time = create_time or profile.create_time
            profile.exit_time = str(row.get("exit_time", "")) or profile.exit_time
            profile.eprocess_offset = str(row.get("eprocess_offset", "")) or profile.eprocess_offset
            source = str(row.get("source_plugin", default_source))
            profile.source_plugins.append(source)
            profile.observed_in.append(source)
            return profile

        for rows, source in (
            (processes, "windows.pslist"),
            (pstree or [], "windows.pstree"),
            (psscan or [], "windows.psscan"),
            (psxview or [], "windows.psxview"),
        ):
            for row in rows:
                create_or_get(row, source)

        def resolve(pid: int | None, name: str = "", process_key: str = "", offset: str = "") -> ProcessProfile | None:
            if process_key and process_key in profiles:
                return profiles[process_key]
            if offset:
                key = _identity_key(pid, offset, "")
                if key in profiles:
                    return profiles[key]
            if pid is None:
                return None
            candidates = list(pid_index.get(int(pid), []))
            if name:
                named = [item for item in candidates if item.name.lower() == name.lower()]
                if named:
                    candidates = named
            active = [item for item in candidates if not item.exit_time]
            if len(active) == 1:
                return active[0]
            if len(candidates) == 1:
                return candidates[0]
            if len(candidates) > 1:
                for item in candidates:
                    item.identity_ambiguous = True
                unresolved_key = f"pid:{pid}|unresolved"
                if unresolved_key not in profiles:
                    unresolved = ProcessProfile(pid=int(pid), name=name, process_key=unresolved_key, identity_ambiguous=True)
                    profiles[unresolved_key] = unresolved
                    pid_index[int(pid)].append(unresolved)
                return profiles[unresolved_key]
            unresolved_key = f"pid:{pid}"
            profile = ProcessProfile(pid=int(pid), name=name, process_key=unresolved_key)
            profiles[unresolved_key] = profile
            pid_index[int(pid)].append(profile)
            return profile

        for profile in list(profiles.values()):
            parents = [item for item in pid_index.get(profile.ppid or -1, []) if item.process_key != profile.process_key]
            if profile.create_time:
                temporal = [item for item in parents if not item.create_time or item.create_time <= profile.create_time]
                parents = temporal or parents
            active_parents = [item for item in parents if not item.exit_time or not profile.create_time or item.exit_time >= profile.create_time]
            parents = active_parents or parents
            if len(parents) == 1:
                profile.parent_name = parents[0].name
                profile.parent_process_key = parents[0].process_key

        for cmd in cmdlines:
            resolved_profile = resolve(cmd.get("pid"), str(cmd.get("process_name", "")), str(cmd.get("process_key", "")), str(cmd.get("eprocess_offset", "")))
            if resolved_profile:
                resolved_profile.command_line = str(cmd.get("command_line", ""))
                resolved_profile.source_plugins.append(str(cmd.get("source_plugin", "windows.cmdline")))
        for dll in dlls:
            resolved_profile = resolve(dll.get("pid"), str(dll.get("process_name", "")), str(dll.get("process_key", "")), str(dll.get("eprocess_offset", "")))
            if resolved_profile:
                dll["process_key"] = resolved_profile.process_key
                resolved_profile.dlls.append(dll)
                resolved_profile.source_plugins.append(str(dll.get("source_plugin", "windows.dlllist")))
        for network_item in network:
            resolved_profile = resolve(network_item.pid, network_item.process_name, network_item.process_key)
            if resolved_profile:
                network_item.process_key = resolved_profile.process_key
                resolved_profile.network_connections.append(network_item)
                resolved_profile.source_plugins.append(network_item.source_plugin)
        for malfind_item in malfind:
            resolved_profile = resolve(malfind_item.pid, malfind_item.process_name, malfind_item.process_key, malfind_item.eprocess_offset)
            if resolved_profile:
                malfind_item.process_key = resolved_profile.process_key
                if not malfind_item.dump_file:
                    malfind_item.dump_file = _guess_dump_for_region(malfind_item.pid, malfind_item.vad_start, dump_files or [])
                resolved_profile.malfind_regions.append(malfind_item)
                resolved_profile.source_plugins.append(malfind_item.source_plugin)
        for persistence_item in persistence or []:
            resolved_profile = resolve(persistence_item.get("pid"), str(persistence_item.get("process_name", "")), str(persistence_item.get("process_key", "")), str(persistence_item.get("eprocess_offset", "")))
            if resolved_profile:
                persistence_item["process_key"] = resolved_profile.process_key
                resolved_profile.persistence_links.append(persistence_item)
        for artifact_name, rows in (context_artifacts or {}).items():
            for context_item in rows:
                resolved_profile = resolve(context_item.get("pid"), str(context_item.get("process_name", context_item.get("name", ""))), str(context_item.get("process_key", "")), str(context_item.get("eprocess_offset", "")))
                if resolved_profile:
                    context_item["process_key"] = resolved_profile.process_key
                    resolved_profile.artifact_context.setdefault(artifact_name, []).append(context_item)
                    resolved_profile.source_plugins.append(str(context_item.get("source_plugin", artifact_name)))
        for profile in profiles.values():
            profile.source_plugins = sorted(set(profile.source_plugins))
            profile.observed_in = sorted(set(profile.observed_in))
        return sorted(profiles.values(), key=lambda item: (item.pid, item.create_time, item.process_key))


def _identity_key(pid: int | None, offset: str, create_time: str) -> str:
    if offset:
        return f"eprocess:{offset.lower()}"
    if pid is None:
        return ""
    return f"pid:{pid}|created:{create_time}" if create_time else f"pid:{pid}"


def _guess_dump_for_region(pid: int | None, address: str, dump_files: list[str]) -> str:
    if pid is None:
        return ""
    pid_pattern = re.compile(rf"(?<!\d){pid}(?!\d)")
    address_tokens = {address.lower(), address.lower().removeprefix("0x")} if address else set()
    pid_matches = []
    for path in dump_files:
        name = Path(path).name.lower()
        if pid_pattern.search(name):
            pid_matches.append(path)
            if any(token and token in name for token in address_tokens):
                return path
    return pid_matches[0] if len(pid_matches) == 1 else ""
