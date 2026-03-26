from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from monitor.shared.command import run_command
from monitor.shared.formatting import format_duration_compact
from monitor.shared.text import line_list, read_text, shorten


class BootCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

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
        lines = [
            f"Boot time: {self.backend.cached('boot_time', 300.0, self.boot_time)}",
            "Slowest boot services:",
        ]
        blame = self.backend.cached("boot_blame", 300.0, self.boot_blame)
        for item in blame[:6]:
            lines.append(f"  {item}")
        if not blame:
            lines.append("  unavailable")
        return lines
