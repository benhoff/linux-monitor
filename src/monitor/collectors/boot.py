from __future__ import annotations

import re
import time
from datetime import datetime
from pathlib import Path

from monitor.shared.command import run_command
from monitor.shared.formatting import format_duration_compact
from monitor.shared.text import line_list, read_text, shorten


class BootCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    @staticmethod
    def permission_unavailable(text: str) -> bool:
        lowered = text.lower()
        return "failed to connect to system scope bus" in lowered or "operation not permitted" in lowered

    @staticmethod
    def blame_seconds(line: str) -> float | None:
        match = re.match(r"([0-9]+(?:\.[0-9]+)?)(ms|s|min)\s+", line.strip())
        if not match:
            return None
        value = float(match.group(1))
        unit = match.group(2)
        if unit == "ms":
            return value / 1000.0
        if unit == "min":
            return value * 60.0
        return value

    def interesting_blame(self, rows: list[str]) -> list[str]:
        interesting = []
        for row in rows:
            seconds = self.blame_seconds(row)
            if seconds is None or seconds >= 1.0:
                interesting.append(row)
        return interesting[:6]

    def boot_time(self) -> str:
        result = run_command(["systemd-analyze"], timeout=4.0)
        if result.stdout:
            return result.stdout.splitlines()[0]
        if result.missing:
            return "systemd-analyze not found"
        if result.stderr:
            return shorten(result.stderr, 140)
        return "unavailable"

    def boot_blame(self) -> list[str]:
        result = run_command(["systemd-analyze", "blame", "--no-pager"], timeout=5.0)
        return line_list(result.stdout, limit=8)

    def uptime_summary(self) -> str:
        raw = read_text(Path("/proc/uptime")).strip().split()
        if not raw:
            return "Uptime: unavailable"
        try:
            uptime_seconds = float(raw[0])
        except ValueError:
            return "Uptime: unavailable"
        booted_at = datetime.fromtimestamp(time.time() - uptime_seconds).strftime("%Y-%m-%d %H:%M")
        return f"Uptime: {format_duration_compact(uptime_seconds)} | booted {booted_at}"

    def collect_uptime(self) -> list[str]:
        return [self.uptime_summary()]

    def collect(self) -> list[str]:
        boot_time = str(self.backend.cached("boot_time", 300.0, self.boot_time))
        blame = self.interesting_blame(self.backend.cached("boot_blame", 300.0, self.boot_blame))
        if self.permission_unavailable(boot_time) and not blame:
            return [
                self.uptime_summary(),
                "Boot timing: unavailable without system bus access.",
            ]

        lines = [f"Boot time: {boot_time}"]
        if blame:
            lines.append("Slowest boot services:")
            for item in blame:
                lines.append(f"  {item}")
        elif not self.permission_unavailable(boot_time):
            lines.append("Slowest boot services: nothing above 1s.")
        return lines
