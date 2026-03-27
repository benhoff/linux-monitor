from __future__ import annotations

import curses
import re
import signal
import textwrap
import time

from monitor.model.dashboard import DashboardModel
from monitor.shared.text import parse_int, shorten


class DashboardUI:
    def __init__(self, model: DashboardModel, initial_tab: str = "tier1") -> None:
        self.model = model
        initial = initial_tab if initial_tab in self.model.tab_order else self.model.tab_order[0]
        self.active_tab_index = max(self.model.tab_order.index(initial), 0)
        self.scroll_offsets = {tab: 0 for tab in self.model.tab_order}

    @property
    def active_tab(self) -> str:
        return self.model.tab_order[self.active_tab_index]

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr: curses.window) -> None:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        stdscr.nodelay(True)
        stdscr.keypad(True)
        if curses.has_colors():
            curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(2, curses.COLOR_CYAN, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
            curses.init_pair(4, curses.COLOR_GREEN, -1)
            curses.init_pair(5, curses.COLOR_YELLOW, -1)
            curses.init_pair(6, curses.COLOR_GREEN, -1)
            curses.init_pair(7, curses.COLOR_BLUE, -1)
            curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_YELLOW)
            curses.init_pair(9, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(10, curses.COLOR_BLACK, curses.COLOR_GREEN)

        while True:
            self.draw(stdscr)
            key = stdscr.getch()
            if key == -1:
                time.sleep(0.05)
                continue
            if key in (ord("q"), ord("Q")):
                break
            if key in (curses.KEY_RIGHT, ord("l"), ord("\t")):
                self.active_tab_index = (self.active_tab_index + 1) % len(self.model.tab_order)
            elif key in (curses.KEY_LEFT, ord("h")):
                self.active_tab_index = (self.active_tab_index - 1) % len(self.model.tab_order)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.scroll_offsets[self.active_tab] += 1
            elif key in (curses.KEY_UP, ord("k")):
                self.scroll_offsets[self.active_tab] = max(0, self.scroll_offsets[self.active_tab] - 1)
            elif key == curses.KEY_NPAGE:
                self.scroll_offsets[self.active_tab] += 10
            elif key == curses.KEY_PPAGE:
                self.scroll_offsets[self.active_tab] = max(0, self.scroll_offsets[self.active_tab] - 10)
            elif key == curses.KEY_HOME:
                self.scroll_offsets[self.active_tab] = 0
            elif key == curses.KEY_END:
                self.scroll_offsets[self.active_tab] = 10**9
            elif key in (ord("r"), ord("R")):
                self.model.request_refresh()
            elif key in (ord("s"), ord("S")) and self.active_tab in {"packages", "aur"}:
                self.model.toggle_package_sort()

    def draw(self, stdscr: curses.window) -> None:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        self._draw_tabs(stdscr, width)
        self._draw_help(stdscr, width)
        body_top = 2
        body_height = max(height - 3, 1)
        lines = self._tab_lines(width - 1)
        max_offset = max(len(lines) - body_height, 0)
        if self.scroll_offsets[self.active_tab] > max_offset:
            self.scroll_offsets[self.active_tab] = max_offset
        offset = self.scroll_offsets[self.active_tab]
        visible = lines[offset : offset + body_height]
        current_section = ""
        for row, line in enumerate(visible, start=body_top):
            if line.startswith("[") and "]" in line:
                current_section = line.split("]", 1)[0].lstrip("[")
            attr = self._line_attr(line, current_section)
            self._safe_addstr(stdscr, row, 0, line[: max(width - 1, 1)], attr)
        footer = (
            f"{self.model.overall_status()} | {self.model.tab_titles[self.active_tab]} "
            f"| scroll {offset}/{max_offset}"
        )
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))
        stdscr.refresh()

    def _draw_tabs(self, stdscr: curses.window, width: int) -> None:
        col = 0
        for index, tab in enumerate(self.model.tab_order):
            label = f" {self.model.tab_titles[tab]} "
            attr = self._tab_attr(tab, index == self.active_tab_index)
            self._safe_addstr(stdscr, 0, col, label[: max(width - col, 0)], attr)
            col += len(label) + 1

    def _draw_help(self, stdscr: curses.window, width: int) -> None:
        help_text = "Left/Right switch tabs | Up/Down scroll | r refresh | s sort package tabs | q quit | green ok | yellow watch | red problem"
        self._safe_addstr(stdscr, 1, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

    def _tab_lines(self, width: int) -> list[str]:
        lines: list[str] = []
        for collector, state in self.model.snapshot(self.active_tab):
            status_parts = []
            if state.loading:
                status_parts.append("loading")
            elif state.last_updated:
                age = max(int(time.time() - state.last_updated), 0)
                status_parts.append(f"{age}s ago")
            if state.last_error:
                status_parts.append(shorten(state.last_error, 60))
            lines.append(f"[{state.title}] {' | '.join(status_parts) if status_parts else 'idle'}")
            for raw in state.lines:
                wrapped = textwrap.wrap(raw, width=max(width - 2, 20)) or [""]
                for item in wrapped:
                    lines.append(f"  {item}")
            lines.append("")
        return lines

    @staticmethod
    def _safe_addstr(
        window: curses.window,
        y: int,
        x: int,
        text: str,
        attr: int = curses.A_NORMAL,
    ) -> None:
        try:
            window.addnstr(y, x, text, max(len(text), 0), attr)
        except curses.error:
            pass

    def _tab_attr(self, tab: str, active: bool) -> int:
        if not active:
            return curses.A_NORMAL
        if not curses.has_colors():
            return curses.A_REVERSE | curses.A_BOLD
        palette = {
            "tier1": curses.color_pair(8),
            "tier2": curses.color_pair(9),
            "tier3": curses.color_pair(10),
            "packages": curses.color_pair(1),
        }
        return palette.get(tab, curses.color_pair(1)) | curses.A_BOLD

    def _line_attr(self, line: str, section: str) -> int:
        stripped = line.strip()
        lowered = stripped.lower()
        if line.startswith("[") and "]" in line:
            return curses.color_pair(2) | curses.A_BOLD
        if not stripped:
            return curses.A_NORMAL
        if stripped.startswith("Snapshot:"):
            return curses.color_pair(7)
        if stripped.startswith("Compared with"):
            return curses.color_pair(7)
        if stripped.startswith("! "):
            return curses.color_pair(3) | curses.A_BOLD
        if stripped.startswith("? "):
            return curses.color_pair(5) | curses.A_BOLD
        if section == "Logs / Errors" and line.startswith("  ") and stripped != "No matching entries.":
            return curses.color_pair(3)
        if section == "Filesystem Integrity" and line.startswith("  ") and stripped != "No matching entries.":
            return curses.color_pair(3)
        if self._is_ok_line(stripped, lowered, section):
            return curses.color_pair(6)
        if self._is_critical_line(stripped, lowered, section):
            return curses.color_pair(3) | curses.A_BOLD
        if self._is_warning_line(stripped, lowered, section):
            return curses.color_pair(5) | curses.A_BOLD
        if "connected" in lowered and "disconnected" not in lowered:
            return curses.color_pair(6)
        if "disconnected" in lowered:
            return curses.A_DIM
        if stripped.startswith("V....") or stripped.startswith("V....."):
            return curses.color_pair(7)
        return curses.A_NORMAL

    def _is_ok_line(self, stripped: str, lowered: str, section: str) -> bool:
        if stripped == "No matching entries.":
            return True
        if stripped == "No major problems detected right now.":
            return True
        if stripped == "No high-signal changes since the last diff snapshot.":
            return True
        if stripped == "Updates: none":
            return True
        if stripped.startswith("Uptime:"):
            return True
        if lowered.endswith(" current"):
            return True
        if "none configured" in lowered:
            return True
        if stripped == "No sudo entries in current boot journal.":
            return True
        if stripped == "No AVMatrix warnings in current boot journal.":
            return True
        if stripped.startswith("System state:") and "running" in lowered:
            return True
        if stripped.startswith("Official repo updates:") and "0 pending" in lowered:
            return True
        if stripped.startswith("AUR updates:") and "0 pending" in lowered:
            return True
        if stripped.startswith("Pending updates:") and parse_int(stripped) == 0:
            return True
        if stripped.startswith("Repo backlog:") and "unavailable" not in lowered and parse_int(stripped) == 0:
            return True
        if stripped.startswith("AUR backlog:") and "unavailable" not in lowered and parse_int(stripped) == 0:
            return True
        if stripped.startswith("Tracked critical packages outdated:") and parse_int(stripped) == 0:
            return True
        if stripped.startswith("Failed services:") and parse_int(stripped) == 0:
            return True
        if stripped.startswith("Failed login attempts this boot:") and parse_int(stripped) == 0:
            return True
        if stripped.startswith("Read-only mounts:") and stripped.endswith("none"):
            return True
        if stripped.startswith("Restart loops / flapping hints:") and "none" in lowered:
            return True
        if stripped.startswith("AVMatrix health:") and "ready" in lowered:
            return True
        if section == "Privileged Snapshot" and stripped.startswith("Status: healthy"):
            return True
        if section == "Privileged Snapshot" and stripped == "Mode: privileged sections are using the snapshot":
            return True
        if stripped.startswith("OOM events:"):
            return False
        if section == "Memory / Pressure" and stripped.startswith("PSI memory:") and "0.00/0.00/0.00" in stripped:
            return True
        if section == "Storage / Capacity":
            if stripped.startswith("Filesystems:") and "| 0 watch | 0 critical" in stripped:
                return True
            if stripped == "Disk IO: idle":
                return True
            pct = self._percent_value(stripped)
            if pct is not None and pct < 75:
                return True
        if "no readable thermal zones" in lowered:
            return False
        return False

    def _is_warning_line(self, stripped: str, lowered: str, section: str) -> bool:
        if " -> " in stripped:
            return True
        if stripped.startswith("Pending updates:") and "unknown" in lowered:
            return True
        if any(token in lowered for token in ("not found", "timed out", "operation not permitted")):
            return True
        if "unavailable" in lowered:
            return True
        if stripped.startswith("Background refresh: syncing"):
            return True
        if "resolution failed" in lowered:
            return True
        if section == "Privileged Snapshot" and stripped.startswith("Schema version:") and "unavailable" in lowered:
            return True
        if section == "Device-Specific Signals" and stripped.startswith("No V4L2 devices listed despite"):
            return True
        if section == "Device-Specific Signals" and "/dev/video" in lowered and " missing" in lowered:
            return True
        if stripped.startswith("Official repo updates:"):
            count = parse_int(stripped)
            return 0 < count < 50
        if stripped.startswith("AUR updates:"):
            count = parse_int(stripped)
            return 0 < count < 25
        if stripped.startswith("Pending updates:"):
            count = parse_int(stripped)
            return 0 < count < 50
        if stripped.startswith("Tracked critical packages outdated:"):
            count = parse_int(stripped)
            return 0 < count < 3
        if stripped.startswith("Orphans:"):
            count = parse_int(stripped)
            return 0 < count < 50
        if stripped.startswith("Foreign packages:"):
            count = parse_int(stripped)
            return 0 < count < 75
        if stripped.startswith("Connections: unavailable"):
            return True
        if stripped.startswith("DNS lookup:") and "resolution failed" in lowered:
            return True
        if section == "Privileged Snapshot" and stripped.startswith("Status:") and any(token in lowered for token in ("stale", "missing")):
            return True
        if stripped.startswith("Boot time:") and ("failed to connect" in lowered or "unavailable" in lowered):
            return True
        if section in {"Thermal / Power", "Hardware Health"} and self._temperature_value(stripped) >= 70:
            return True
        if section == "Storage / Capacity":
            if stripped.startswith("Filesystems:"):
                return " | 0 critical" in stripped and " | 0 watch" not in stripped
            pct = self._percent_value(stripped)
            if pct is not None and 75 <= pct < 90:
                return True
        if section == "Memory / Pressure":
            pct = self._percent_value(stripped)
            if pct is not None and 75 <= pct < 90:
                return True
            if stripped.startswith("PSI memory:") and "0.00/0.00/0.00" not in stripped:
                return True
        if section == "CPU / System Load":
            match = re.search(r"iowait (\d+(?:\.\d+)?)%", stripped)
            if match and float(match.group(1)) >= 10.0:
                return True
        if stripped.startswith("Read-only mounts:") and not stripped.endswith("none"):
            return True
        return False

    def _is_critical_line(self, stripped: str, lowered: str, section: str) -> bool:
        if stripped.startswith("Failed services:") and parse_int(stripped) > 0:
            return True
        if stripped.startswith("Failed login attempts this boot:") and parse_int(stripped) > 0:
            return True
        if stripped.startswith("Official repo updates:") and parse_int(stripped) >= 50:
            return True
        if stripped.startswith("AUR updates:") and parse_int(stripped) >= 25:
            return True
        if stripped.startswith("Pending updates:") and parse_int(stripped) >= 50:
            return True
        if stripped.startswith("Tracked critical packages outdated:") and parse_int(stripped) >= 3:
            return True
        if stripped.startswith("Orphans:") and parse_int(stripped) >= 50:
            return True
        if stripped.startswith("Foreign packages:") and parse_int(stripped) >= 75:
            return True
        if stripped.startswith("System state:") and any(token in lowered for token in ("degraded", "failed")):
            return True
        if section == "Privileged Snapshot" and stripped.startswith("Status:") and any(token in lowered for token in ("invalid", "unreadable", "version drift")):
            return True
        if section == "Storage / Capacity":
            if stripped.startswith("Filesystems:"):
                return "critical" in lowered and not stripped.endswith("0 critical")
            pct = self._percent_value(stripped)
            if pct is not None and pct >= 90:
                return True
        if section == "Memory / Pressure":
            pct = self._percent_value(stripped)
            if pct is not None and pct >= 90:
                return True
        if section in {"Thermal / Power", "Hardware Health"} and self._temperature_value(stripped) >= 85:
            return True
        if section == "CPU / System Load":
            match = re.search(r"iowait (\d+(?:\.\d+)?)%", stripped)
            if match and float(match.group(1)) >= 25.0:
                return True
        if stripped.startswith("DNS lookup:") and "resolution failed" in lowered:
            return True
        return False

    @staticmethod
    def _percent_value(text: str) -> float | None:
        matches = re.findall(r"(\d+(?:\.\d+)?)%", text)
        if not matches:
            return None
        try:
            return float(matches[0])
        except ValueError:
            return None

    @staticmethod
    def _temperature_value(text: str) -> float:
        match = re.search(r"(-?\d+(?:\.\d+)?)\s*C", text)
        if not match:
            return -1.0
        return float(match.group(1))


def print_once(model: DashboardModel, tab: str) -> None:
    tabs = model.tab_order if tab == "all" else ((tab,) if tab in model.tab_order else ())
    if tab != "all" and not tabs:
        print(f"Tab '{tab}' is not available on this system.")
        return
    for name in tabs:
        print(f"=== {model.tab_titles[name]} ===")
        for _collector, state in model.snapshot(name):
            print(f"[{state.title}]")
            for line in state.lines:
                print(f"  {line}")
            print()
