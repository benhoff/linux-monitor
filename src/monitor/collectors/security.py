from __future__ import annotations

from pathlib import Path
import re

from monitor.shared.command import run_command
from monitor.shared.formatting import first_nonempty_line, is_loopback_endpoint
from monitor.shared.parsing_journal import journal_line_list
from monitor.shared.text import line_list, shorten


class SecurityCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    @staticmethod
    def _listener_process_name(process: str) -> str:
        match = re.search(r'"([^"]+)"', process)
        if match:
            return match.group(1)
        return "unknown"

    @staticmethod
    def _listener_endpoint(line: str) -> str:
        return line.split(None, 1)[0] if line else ""

    def exposed_listener_lines(self, listeners: list[str]) -> list[str]:
        exposed = []
        for raw in listeners:
            line = str(raw).strip()
            endpoint = self._listener_endpoint(line)
            if endpoint and not is_loopback_endpoint(endpoint):
                exposed.append(line)
        return exposed[:8]

    @staticmethod
    def interesting_auth_failures(entries: list[str]) -> list[str]:
        filtered = []
        for entry in entries:
            lowered = entry.lower()
            if "sudo:auth" in lowered:
                continue
            filtered.append(entry)
        return filtered

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
        return self.interesting_auth_failures(journal_line_list(result.stdout, limit=5))

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
            failed_logins = self.interesting_auth_failures(
                [str(item) for item in privileged.get("failed_logins", []) if str(item).strip()]
            )
            exposed_lines = self.exposed_listener_lines(
                [str(item) for item in listeners] if isinstance(listeners, list) else []
            )
            lines = []
            if snapshot_line:
                lines.append(snapshot_line)
            lines.append(
                f"Exposure: {len(exposed_lines)} non-loopback listener(s)"
                + (f" ({exposed_error})" if exposed_error else "")
            )
            if exposed_lines:
                for item in exposed_lines[:4]:
                    lines.append(f"  {shorten(item, 140)}")
            else:
                lines.append("Auth failures: none notable this boot.")
            if failed_logins:
                lines.append(f"Auth failures: {len(failed_logins)} this boot")
                for item in failed_logins[:4]:
                    lines.append(f"  {shorten(str(item), 140)}")
            elif not exposed_lines:
                lines.append("Auth failures: none notable this boot.")
            return lines

        failed_logins = self.failed_logins()
        lines = [f"Exposure: {len(exposed)} non-loopback listener(s)" + (f" ({exposed_error})" if exposed_error else "")]
        if exposed:
            for item in exposed[:4]:
                lines.append(f"  {shorten(item, 140)}")
        if failed_logins:
            lines.append(f"Auth failures: {len(failed_logins)} this boot")
            for item in failed_logins[:4]:
                lines.append(f"  {shorten(item, 140)}")
        elif not exposed:
            lines.append("Auth failures: none notable this boot.")
        return lines
