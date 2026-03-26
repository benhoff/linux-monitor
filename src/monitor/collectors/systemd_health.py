from __future__ import annotations

from monitor.shared.command import run_command
from monitor.shared.parsing_journal import journal_line_list
from monitor.shared.text import line_list, shorten


class SystemdHealthCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def systemd_state(self) -> str:
        result = run_command(["systemctl", "is-system-running"], timeout=3.0)
        if result.stdout:
            return result.stdout.splitlines()[0]
        if result.missing:
            return "systemctl not found"
        if result.stderr:
            return shorten(result.stderr, 120)
        return "unknown"

    def failed_services(self) -> list[str]:
        result = run_command(
            ["systemctl", "--failed", "--type=service", "--no-legend", "--no-pager"],
            timeout=5.0,
        )
        return line_list(result.stdout)

    def restart_hints(self) -> list[str]:
        result = run_command(
            [
                "journalctl",
                "-b",
                "--grep=Scheduled restart job|Start request repeated too quickly",
                "-n",
                "8",
                "--no-pager",
            ],
            timeout=5.0,
        )
        return journal_line_list(result.stdout)

    def service_count(self, state: str) -> tuple[int | None, str | None]:
        return self.backend.count_command_lines(
            ["systemctl", "list-unit-files", "--type=service", f"--state={state}", "--no-legend", "--no-pager"],
            timeout=5.0,
        )

    def collect(self) -> list[str]:
        privileged = self.backend._privileged_section("systemd")
        if privileged:
            lines = []
            snapshot_line = self.backend._privileged_snapshot_line()
            if snapshot_line:
                lines.append(snapshot_line)
            failed = privileged.get("failed_services", [])
            restart_hints = privileged.get("restart_hints", [])
            lines.append(f"System state: {privileged.get('state', 'unknown')}")
            lines.append(f"Failed services: {len(failed) if isinstance(failed, list) else 0}")
            if isinstance(failed, list):
                for item in failed[:6]:
                    lines.append(f"  {shorten(str(item), 140)}")
            enabled_count = privileged.get("enabled_count", "n/a")
            disabled_count = privileged.get("disabled_count", "n/a")
            lines.append(f"Service unit files: {enabled_count} enabled | {disabled_count} disabled")
            if isinstance(restart_hints, list) and restart_hints:
                lines.append("Restart loops / flapping hints:")
                for item in restart_hints[:4]:
                    lines.append(f"  {shorten(str(item), 140)}")
            else:
                lines.append("Restart loops / flapping hints: none in current boot journal.")
            return lines

        lines: list[str] = []
        state = self.systemd_state()
        failed = self.failed_services()
        enabled_count, enabled_error = self.backend.cached(
            "systemd_enabled_count",
            600.0,
            lambda: self.service_count("enabled"),
        )
        disabled_count, disabled_error = self.backend.cached(
            "systemd_disabled_count",
            600.0,
            lambda: self.service_count("disabled"),
        )
        restart_hints = self.restart_hints()

        lines.append(f"System state: {state}")
        lines.append(f"Failed services: {len(failed)}")
        for item in failed[:6]:
            lines.append(f"  {shorten(item, 140)}")

        enabled_display = str(enabled_count) if enabled_count is not None else "n/a"
        disabled_display = str(disabled_count) if disabled_count is not None else "n/a"
        note = ", ".join(note for note in (enabled_error, disabled_error) if note)
        lines.append(
            f"Service unit files: {enabled_display} enabled | {disabled_display} disabled"
            + (f" ({note})" if note else "")
        )

        if restart_hints:
            lines.append("Restart loops / flapping hints:")
            for item in restart_hints[:4]:
                lines.append(f"  {shorten(item, 140)}")
        else:
            lines.append("Restart loops / flapping hints: none in current boot journal.")
        return lines
