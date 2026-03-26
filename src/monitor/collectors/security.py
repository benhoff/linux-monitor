from __future__ import annotations

from pathlib import Path

from monitor.shared.command import run_command
from monitor.shared.formatting import first_nonempty_line, is_loopback_endpoint
from monitor.shared.parsing_journal import journal_line_list
from monitor.shared.text import line_list, shorten


class SecurityCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def listener_rows(self) -> tuple[list[tuple[str, str, str]], str | None]:
        result = run_command(["ss", "-ltnupH"], timeout=4.0)
        rows: list[tuple[str, str, str]] = []
        if result.stdout or result.ok:
            for raw in line_list(result.stdout):
                parts = raw.split()
                if len(parts) < 5:
                    continue
                proto = parts[0]
                local = parts[4]
                process = parts[-1] if len(parts) >= 6 else ""
                rows.append((proto, local, process))
            return rows, None
        if result.missing:
            return [], "ss not found."
        if result.timed_out:
            return [], "ss timed out."
        if result.stderr:
            return [], shorten(first_nonempty_line(result.stderr), 140)
        return [], None

    def listening_sockets(self) -> list[str]:
        rows, error = self.listener_rows()
        sockets = [f"{local} {process}".strip() for _proto, local, process in rows]
        if sockets:
            return sockets[:8]
        if error:
            return [error]
        return ["No listening sockets."]

    def non_loopback_listeners(self) -> tuple[list[str], str | None]:
        rows, error = self.listener_rows()
        exposed = [
            f"{proto} {local} {process}".strip()
            for proto, local, process in rows
            if not is_loopback_endpoint(local)
        ]
        return exposed[:8], error

    def failed_logins(self) -> list[str]:
        result = run_command(
            [
                "journalctl",
                "-b",
                "--grep=Failed password|authentication failure|FAILED LOGIN",
                "-n",
                "8",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        return journal_line_list(result.stdout, limit=5)

    def sudo_usage(self) -> list[str]:
        result = run_command(
            ["journalctl", "-b", "SYSLOG_IDENTIFIER=sudo", "-n", "5", "--no-pager", "-o", "short-iso"],
            timeout=5.0,
        )
        return journal_line_list(result.stdout, limit=5)

    def collect(self) -> list[str]:
        exposed, exposed_error = self.backend.cached("non_loopback_listeners", 30.0, self.non_loopback_listeners)
        privileged = self.backend._privileged_section("security")
        if privileged:
            snapshot_line = self.backend._privileged_snapshot_line()
            listeners = privileged.get("listeners", [])
            failed_logins = privileged.get("failed_logins", [])
            sudo_usage = privileged.get("sudo_usage", [])
            lines = []
            if snapshot_line:
                lines.append(snapshot_line)
            lines.append(f"Non-loopback listeners: {len(exposed)}" + (f" ({exposed_error})" if exposed_error else ""))
            if exposed:
                for item in exposed[:4]:
                    lines.append(f"  {shorten(item, 140)}")
            lines.append("Listening sockets:")
            if isinstance(listeners, list) and listeners:
                for item in listeners[:6]:
                    lines.append(f"  {item}")
            else:
                lines.append("  No listening sockets.")
            failed_count = len(failed_logins) if isinstance(failed_logins, list) else 0
            lines.append(f"Failed login attempts this boot: {failed_count}")
            if isinstance(failed_logins, list):
                for item in failed_logins[:4]:
                    lines.append(f"  {shorten(str(item), 140)}")
            lines.append("Recent sudo usage:")
            if isinstance(sudo_usage, list) and sudo_usage:
                for item in sudo_usage[:4]:
                    lines.append(f"  {shorten(str(item), 140)}")
            else:
                lines.append("  No sudo entries in current boot journal.")
            return lines

        listeners = self.listening_sockets()
        failed_logins = self.failed_logins()
        sudo_usage = self.sudo_usage()
        lines = [f"Non-loopback listeners: {len(exposed)}" + (f" ({exposed_error})" if exposed_error else "")]
        if exposed:
            for item in exposed[:4]:
                lines.append(f"  {shorten(item, 140)}")
        lines.append("Listening sockets:")
        for item in listeners[:6]:
            lines.append(f"  {item}")
        lines.append(f"Failed login attempts this boot: {len(failed_logins)}")
        for item in failed_logins[:4]:
            lines.append(f"  {shorten(item, 140)}")
        lines.append("Recent sudo usage:")
        if sudo_usage:
            for item in sudo_usage[:4]:
                lines.append(f"  {shorten(item, 140)}")
        else:
            lines.append("  No sudo entries in current boot journal.")
        return lines
