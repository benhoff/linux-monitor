from __future__ import annotations

import re
from collections import OrderedDict
from typing import Sequence

from monitor.shared.command import CommandResult, run_command
from monitor.shared.text import line_list, shorten
from monitor.shared.formatting import single_line


def journal_line_list(text: str, limit: int | None = None) -> list[str]:
    lines = [line for line in line_list(text) if line != "-- No entries --"]
    if limit is not None:
        return lines[:limit]
    return lines


def _journal_summary_key(line: str) -> str:
    normalized = line.strip()
    normalized = re.sub(
        r"^\[\s*\d+(?:\.\d+)?\]\s+",
        "",
        normalized,
    )
    normalized = re.sub(
        r"^\d{4}-\d{2}-\d{2}(?:T| )\d{2}:\d{2}(?::\d{2})?(?:[.,]\d+)?(?:[+-]\d{2}:\d{2})?\s+",
        "",
        normalized,
    )
    match = re.match(r"^(?:\S+\s+)?([A-Za-z0-9_.@/-]+)(?:\[\d+\])?:\s*(.*)$", normalized)
    if match:
        unit, message = match.groups()
        if message:
            return f"{unit}: {message}"
        return f"{unit}:"
    return normalized


def summarize_journal_entries(entries: Sequence[str], limit: int | None = None) -> list[str]:
    grouped: OrderedDict[str, int] = OrderedDict()
    for raw in entries:
        key = _journal_summary_key(raw)
        if not key:
            continue
        grouped[key] = grouped.get(key, 0) + 1

    summaries: list[str] = []
    for item, count in grouped.items():
        summary = shorten(item, 150)
        if count > 1:
            summary = f"{summary} showed up {count} times"
        summaries.append(summary)
        if limit is not None and len(summaries) >= limit:
            break
    return summaries


def detect_ro_mounts() -> list[str]:
    mounts = []
    result = run_command(["findmnt", "-rn", "-o", "TARGET,OPTIONS"], timeout=3)
    if not result.stdout:
        return mounts
    for raw in result.stdout.splitlines():
        parts = raw.split(None, 1)
        if len(parts) != 2:
            continue
        target, options = parts
        option_list = set(options.split(","))
        if "ro" in option_list:
            mounts.append(target)
    return mounts


def parse_journal_lines(result: CommandResult, limit: int = 8) -> list[str]:
    if result.stdout:
        entries = summarize_journal_entries(journal_line_list(result.stdout), limit)
        if entries:
            return entries
        return ["No matching entries."]
    if result.missing:
        return [f"{result.args[0]} not found."]
    if result.timed_out:
        return [f"{result.args[0]} timed out."]
    if result.stderr:
        return [shorten(single_line(result.stderr), 150)]
    return ["No matching entries."]
