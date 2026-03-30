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

    def collect(self) -> list[str]:
        privileged = self.backend._privileged_section("systemd")
        if privileged:
            lines = []
            snapshot_line = self.backend._privileged_snapshot_line()
            if snapshot_line:
                lines.append(snapshot_line)
            failed = privileged.get("failed_services", [])
            restart_hints = privileged.get("restart_hints", [])
            failed_count = len(failed) if isinstance(failed, list) else 0
            state = str(privileged.get("state", "unknown"))
            if failed_count == 0:
                lines.append(f"System state: {state} | no failed services")
            else:
                lines.append(f"System state: {state} | {failed_count} failed services")
            if isinstance(failed, list):
                for item in failed[:6]:
                    lines.append(f"  {shorten(str(item), 140)}")
            if isinstance(restart_hints, list) and restart_hints:
                lines.append("Restart loops / flapping hints:")
                for item in restart_hints[:4]:
                    lines.append(f"  {shorten(str(item), 140)}")
            return lines

        lines: list[str] = []
        state = self.systemd_state()
        failed = self.failed_services()
        restart_hints = self.restart_hints()

        if not failed:
            lines.append(f"System state: {state} | no failed services")
        else:
            lines.append(f"System state: {state} | {len(failed)} failed services")
        for item in failed[:6]:
            lines.append(f"  {shorten(item, 140)}")

        if restart_hints:
            lines.append("Restart loops / flapping hints:")
            for item in restart_hints[:4]:
                lines.append(f"  {shorten(item, 140)}")
        return lines
