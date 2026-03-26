from __future__ import annotations

from monitor.shared.command import CommandResult, run_command
from monitor.shared.text import line_list, shorten
from monitor.shared.formatting import single_line


def journal_line_list(text: str, limit: int | None = None) -> list[str]:
    lines = [line for line in line_list(text) if line != "-- No entries --"]
    if limit is not None:
        return lines[:limit]
    return lines


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
        entries = journal_line_list(result.stdout, limit)
        if entries:
            return [shorten(line, 150) for line in entries]
        return ["No matching entries."]
    if result.missing:
        return [f"{result.args[0]} not found."]
    if result.timed_out:
        return [f"{result.args[0]} timed out."]
    if result.stderr:
        return [shorten(single_line(result.stderr), 150)]
    return ["No matching entries."]
