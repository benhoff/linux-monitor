from __future__ import annotations

import re

from monitor.shared.command import run_command
from monitor.shared.constants import HARDWARE_LOG_PATTERN
from monitor.shared.parsing_journal import parse_journal_lines, summarize_journal_entries
from monitor.shared.text import shorten


class LogsCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    @staticmethod
    def filtered_entries(entries: list[str], category: str) -> list[str]:
        filtered: list[str] = []
        for item in entries:
            text = str(item).strip()
            if not text or text == "No matching entries.":
                continue
            lowered = text.lower()
            if lowered.startswith("stack trace of thread") or re.match(r"^#\d+\b", text):
                continue
            if category == "journal_errors" and (
                "pam_unix(sudo:auth): conversation failed" in lowered
                or "pam_unix(sudo:auth): auth could not identify password" in lowered
            ):
                continue
            if category == "hardware_warnings":
                if not any(
                    token in lowered
                    for token in (
                        "error",
                        "warn",
                        "fail",
                        "timeout",
                        "reset",
                        "disconnect",
                        "missing",
                        "invalid",
                        "denied",
                        "hung",
                    )
                ):
                    continue
                if not any(
                    token in lowered
                    for token in ("usb", "pci", "gpu", "drm", "nvme", "sata", "libata", "camera", "v4l2", "hdmi", "edid")
                ):
                    continue
            filtered.append(text)
        return filtered

    def extend_section(self, lines: list[str], title: str, entries: list[str], category: str) -> None:
        filtered = self.filtered_entries(entries, category)
        lines.append(title)
        if filtered:
            for item in filtered[:3]:
                lines.append(f"  {shorten(item, 150)}")
        else:
            lines.append("  No high-signal entries.")

    def collect(self) -> list[str]:
        privileged = self.backend._privileged_section("logs")
        if privileged:
            lines: list[str] = []
            snapshot_line = self.backend._privileged_snapshot_line()
            if snapshot_line:
                lines.append(snapshot_line)
            journal_errors = summarize_journal_entries(privileged.get("journal_errors", []), limit=8)
            kernel_warnings = summarize_journal_entries(privileged.get("kernel_warnings", []), limit=8)
            hardware_warnings = summarize_journal_entries(privileged.get("hardware_warnings", []), limit=8)
            self.extend_section(lines, "Journal errors since boot:", journal_errors, "journal_errors")
            self.extend_section(lines, "Kernel warnings since boot:", kernel_warnings, "kernel_warnings")
            self.extend_section(lines, "Hardware / driver hints:", hardware_warnings, "hardware_warnings")
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

        self.extend_section(lines, "Journal errors since boot:", parse_journal_lines(journal_errors, limit=8), "journal_errors")
        self.extend_section(lines, "Kernel warnings since boot:", parse_journal_lines(kernel_warnings, limit=8), "kernel_warnings")
        self.extend_section(lines, "Hardware / driver hints:", parse_journal_lines(hardware_warnings, limit=8), "hardware_warnings")
        return lines
