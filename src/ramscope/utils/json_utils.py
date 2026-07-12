from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from ramscope.models import to_jsonable


MAX_JSON_BYTES = 256 * 1024 * 1024


def read_json(path: Path, max_bytes: int = MAX_JSON_BYTES) -> Any:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"JSON artifact is too large to decode safely: {size} bytes (limit {max_bytes}).")
    with path.open("r", encoding="utf-8") as file_obj:
        return json.load(file_obj)


def write_json(path: Path, data: Any) -> Path:
    """Write JSON atomically so interrupted analysis cannot leave a truncated artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file_obj:
            json.dump(to_jsonable(data), file_obj, indent=2, ensure_ascii=False)
            file_obj.write("\n")
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return path
