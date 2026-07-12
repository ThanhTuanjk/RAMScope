from __future__ import annotations

from pathlib import Path
from typing import Any

from ramscope.utils.json_utils import read_json


def get_first(row: dict[str, Any], keys: list[str], default: Any = "") -> Any:
    lower_map = {str(key).lower(): value for key, value in row.items()}
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
        value = lower_map.get(key.lower())
        if value not in (None, ""):
            return value
    return default


def to_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        return None


def extract_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data if all(isinstance(item, dict) for item in data) else []
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("data"), list):
        return extract_rows(data["data"])
    if "columns" in data and "rows" in data:
        if not isinstance(data["columns"], list) or not isinstance(data["rows"], list):
            raise ValueError("Volatility table envelope requires list-valued columns and rows.")
        columns = [col.get("name", col) if isinstance(col, dict) else col for col in data["columns"]]
        rows = []
        for item in data["rows"]:
            if isinstance(item, dict):
                rows.append(item)
            elif isinstance(item, list):
                rows.append({str(columns[index]): value for index, value in enumerate(item) if index < len(columns)})
        return rows
    if isinstance(data.get("rows"), list):
        return extract_rows(data["rows"])
    return []


class BaseParser:
    source_plugin = ""

    def parse_file(self, path: Path) -> list:
        if not path.exists():
            return []
        return [self.normalize(row) for row in extract_rows(read_json(path))]

    def normalize(self, row: dict[str, Any]):
        return row
