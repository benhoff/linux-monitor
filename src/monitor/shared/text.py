from __future__ import annotations

import re
from pathlib import Path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_lines(path: Path, limit: int | None = None) -> list[str]:
    lines = read_text(path).splitlines()
    if limit is not None:
        return lines[-limit:]
    return lines


def parse_int(value: str, default: int = 0) -> int:
    match = re.search(r"-?\d+", value)
    if not match:
        return default
    return int(match.group(0))


def parse_float(value: str) -> float | None:
    match = re.search(r"-?\d+(?:\.\d+)?", value)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def line_list(text: str, limit: int | None = None, *, skip_no_entries: bool = False) -> list[str]:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if skip_no_entries and line == "-- No entries --":
            continue
        lines.append(line)
    if limit is not None:
        return lines[:limit]
    return lines
