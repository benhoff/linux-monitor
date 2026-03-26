from __future__ import annotations

from monitor.shared.command import run_command
from monitor.shared.constants import HARDWARE_LOG_PATTERN
from monitor.shared.parsing_journal import parse_journal_lines, summarize_journal_entries
from monitor.shared.text import shorten


class LogsCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def collect(self) -> list[str]:
        privileged = self.backend._privileged_section("logs")
        if privileged:
            lines: list[str] = []
            snapshot_line = self.backend._privileged_snapshot_line()
            if snapshot_line:
                lines.append(snapshot_line)
            lines.append("Journal errors since boot:")
            for item in summarize_journal_entries(privileged.get("journal_errors", []), limit=5):
                lines.append(f"  {shorten(str(item), 150)}")
            if not privileged.get("journal_errors"):
                lines.append("  No matching entries.")
            lines.append("Kernel warnings since boot:")
            for item in summarize_journal_entries(privileged.get("kernel_warnings", []), limit=5):
                lines.append(f"  {shorten(str(item), 150)}")
            if not privileged.get("kernel_warnings"):
                lines.append("  No matching entries.")
            lines.append("Hardware / driver hints:")
            for item in summarize_journal_entries(privileged.get("hardware_warnings", []), limit=5):
                lines.append(f"  {shorten(str(item), 150)}")
            if not privileged.get("hardware_warnings"):
                lines.append("  No matching entries.")
            return lines

        lines: list[str] = []
        journal_errors = run_command(
            ["journalctl", "-b", "-p", "err", "-n", "10", "--no-pager", "-o", "short-iso"],
            timeout=5.0,
        )
        kernel_warnings = run_command(
            ["journalctl", "-k", "-b", "-p", "warning", "-n", "10", "--no-pager", "-o", "short-monotonic"],
            timeout=5.0,
        )
        hardware_warnings = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={HARDWARE_LOG_PATTERN}",
                "-n",
                "10",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )

        lines.append("Journal errors since boot:")
        for item in parse_journal_lines(journal_errors, limit=5):
            lines.append(f"  {item}")

        lines.append("Kernel warnings since boot:")
        for item in parse_journal_lines(kernel_warnings, limit=5):
            lines.append(f"  {item}")

        lines.append("Hardware / driver hints:")
        for item in parse_journal_lines(hardware_warnings, limit=5):
            lines.append(f"  {item}")
        return lines
