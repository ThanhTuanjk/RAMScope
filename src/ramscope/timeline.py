from __future__ import annotations

from typing import Any

from ramscope.models import ProcessProfile, TimelineEvent


def build_timeline(profiles: list[ProcessProfile], plugin_events: list[dict[str, Any]] | None = None) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for profile in profiles:
        if profile.create_time:
            events.append(TimelineEvent(profile.create_time, "process_start", profile.pid, profile.name, profile.command_line or profile.image_path, "process cross-view", profile.process_key))
        if profile.exit_time:
            events.append(TimelineEvent(profile.exit_time, "process_exit", profile.pid, profile.name, "", "process cross-view", profile.process_key))
        for conn in profile.network_connections:
            events.append(TimelineEvent("", "network", profile.pid, profile.name, f"{conn.protocol} {conn.remote_addr}:{conn.remote_port} {conn.state}", conn.source_plugin, profile.process_key))
        for region in profile.malfind_regions:
            events.append(TimelineEvent("", "malfind", profile.pid, profile.name, f"{region.vad_start}-{region.vad_end} {region.protection}", region.source_plugin, profile.process_key))
        for item in profile.persistence_links:
            events.append(TimelineEvent("", "persistence", profile.pid, profile.name, str(item), str(item.get("source_plugin", "memory")), profile.process_key))
    for row in plugin_events or []:
        events.append(TimelineEvent(
            str(row.get("timestamp", "")), str(row.get("event_type", "timeline")), row.get("pid"),
            str(row.get("process_name", "")), str(row.get("description", row.get("details", ""))),
            str(row.get("source_plugin", "timeliner")), str(row.get("process_key", "")),
        ))
    deduped: dict[tuple[str, str, int | None, str], TimelineEvent] = {}
    for event in events:
        key = (event.timestamp, event.event_type, event.pid, event.detail)
        deduped[key] = event
    return sorted(deduped.values(), key=lambda event: event.timestamp or "9999")
