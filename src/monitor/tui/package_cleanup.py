from __future__ import annotations

import curses
import shlex
import signal
import subprocess
import textwrap
import time
from typing import Iterable

from monitor.packages.common import (
    REFRESH_POLL_INTERVAL,
    TREE_MAX_DEPTH,
    CandidatePreview,
    PackageInfo,
    RefreshSnapshot,
    RemovalPlan,
    built_in_protected,
    format_bytes,
    format_count,
    format_name_list,
)
from monitor.packages.model import PackageCleanupModel
from monitor.packages.removal import (
    preview_tree_lines,
    removal_plan_error,
    removal_preview,
    shell_command_for_removal,
    validate_removal_plan,
)


class PackageCleanupUI:
    def __init__(self, model: PackageCleanupModel) -> None:
        self.model = model
        self.mode = "main"
        self.sort_mode = "reclaim"
        self.main_index = 0
        self.main_offset = 0
        self.orphan_index = 0
        self.orphan_offset = 0
        self.protected_index = 0
        self.protected_offset = 0
        self.selected_roots: set[str] = set()
        self.orphan_deselected: set[str] = set()
        self.detail_root: str | None = None
        self.confirm_plan: RemovalPlan | None = None

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
        stdscr.keypad(True)
        stdscr.nodelay(True)
        if curses.has_colors():
            curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(2, curses.COLOR_CYAN, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
            curses.init_pair(4, curses.COLOR_GREEN, -1)
            curses.init_pair(5, curses.COLOR_YELLOW, -1)
            curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_YELLOW)

        while True:
            self.draw(stdscr)
            key = stdscr.getch()
            if key == -1:
                time.sleep(REFRESH_POLL_INTERVAL)
                continue
            if self.confirm_plan is not None:
                if key in (ord("y"), ord("Y")):
                    self._perform_removal(stdscr)
                elif key in (ord("n"), ord("N"), 27):
                    self.confirm_plan = None
                continue
            if key in (ord("q"), ord("Q")):
                if self.mode == "main":
                    break
                self.mode = "main"
                self.detail_root = None
                continue
            if key in (ord("r"), ord("R")):
                self.model.request_refresh("Refreshing package catalog...")
                continue
            if self.mode == "main":
                if not self._handle_main_key(key):
                    continue
            elif self.mode == "detail":
                if not self._handle_detail_key(key):
                    continue
            elif self.mode == "orphans":
                if not self._handle_orphan_key(key):
                    continue
            elif self.mode == "protected":
                if not self._handle_protected_key(key):
                    continue

    def _sorted_candidates(self, snapshot: RefreshSnapshot) -> list[CandidatePreview]:
        candidates = list(snapshot.candidates.values())
        if self.sort_mode == "name":
            candidates.sort(key=lambda item: item.root)
        elif self.sort_mode == "size":
            candidates.sort(
                key=lambda item: (
                    snapshot.packages.get(item.root).installed_size if item.root in snapshot.packages else 0,
                    item.root,
                ),
                reverse=True,
            )
        else:
            candidates.sort(key=lambda item: (item.reclaimable_size, item.root), reverse=True)
        return candidates

    def _handle_main_key(self, key: int) -> bool:
        snapshot, _message = self.model.current_snapshot()
        candidates = self._sorted_candidates(snapshot)
        if key in (curses.KEY_DOWN, ord("j")):
            if candidates:
                self.main_index = min(self.main_index + 1, len(candidates) - 1)
        elif key in (curses.KEY_UP, ord("k")):
            self.main_index = max(self.main_index - 1, 0)
        elif key == curses.KEY_NPAGE:
            self.main_index = min(self.main_index + 15, max(len(candidates) - 1, 0))
        elif key == curses.KEY_PPAGE:
            self.main_index = max(self.main_index - 15, 0)
        elif key == curses.KEY_HOME:
            self.main_index = 0
        elif key == curses.KEY_END:
            self.main_index = max(len(candidates) - 1, 0)
        elif key in (10, 13, curses.KEY_ENTER):
            if candidates:
                self.detail_root = candidates[self.main_index].root
                self.mode = "detail"
        elif key == ord(" "):
            if candidates:
                root = candidates[self.main_index].root
                if root in self.selected_roots:
                    self.selected_roots.remove(root)
                else:
                    self.selected_roots.add(root)
        elif key in (ord("c"), ord("C")):
            self.selected_roots.clear()
        elif key in (ord("s"), ord("S")):
            self.sort_mode = {"reclaim": "size", "size": "name", "name": "reclaim"}[self.sort_mode]
        elif key in (ord("m"), ord("M")):
            if candidates:
                root = candidates[self.main_index].root
                self.selected_roots.discard(root)
                self.model.protect_package(root)
        elif key in (ord("o"), ord("O")):
            self.mode = "orphans"
        elif key in (ord("p"), ord("P")):
            self.mode = "protected"
        elif key in (ord("x"), ord("X")):
            roots = [root for root in self.selected_roots if root in snapshot.candidates]
            if not roots and candidates:
                roots = [candidates[self.main_index].root]
            if roots:
                self._open_confirmation(snapshot, roots)
        return True

    def _handle_detail_key(self, key: int) -> bool:
        snapshot, _message = self.model.current_snapshot()
        if self.detail_root not in snapshot.candidates:
            self.mode = "main"
            self.detail_root = None
            return True
        if key in (27, curses.KEY_BACKSPACE, ord("h")):
            self.mode = "main"
            self.detail_root = None
        elif key == ord(" ") and self.detail_root:
            if self.detail_root in self.selected_roots:
                self.selected_roots.remove(self.detail_root)
            else:
                self.selected_roots.add(self.detail_root)
        elif key in (ord("m"), ord("M")) and self.detail_root:
            self.selected_roots.discard(self.detail_root)
            self.model.protect_package(self.detail_root)
            self.mode = "main"
            self.detail_root = None
        elif key in (ord("x"), ord("X")):
            self._open_confirmation(snapshot, [self.detail_root])
        return True

    def _orphan_rows(self, snapshot: RefreshSnapshot) -> list[PackageInfo]:
        protected = set(self.model.user_protected)
        rows = [
            pkg
            for pkg in snapshot.packages.values()
            if pkg.install_reason == "dependency"
            and not pkg.required_by
            and pkg.name not in protected
            and not built_in_protected(pkg.name)
        ]
        rows.sort(key=lambda item: (0 if item.official else 1, -item.installed_size, item.name))
        return rows

    def _selected_orphan_names(self, rows: list[PackageInfo]) -> list[str]:
        return [pkg.name for pkg in rows if pkg.name not in self.orphan_deselected]

    def _handle_orphan_key(self, key: int) -> bool:
        snapshot, _message = self.model.current_snapshot()
        rows = self._orphan_rows(snapshot)
        if key in (27, curses.KEY_BACKSPACE, ord("h"), ord("q"), ord("Q")):
            self.mode = "main"
            return True
        if key in (curses.KEY_DOWN, ord("j")):
            if rows:
                self.orphan_index = min(self.orphan_index + 1, len(rows) - 1)
        elif key in (curses.KEY_UP, ord("k")):
            self.orphan_index = max(self.orphan_index - 1, 0)
        elif key == curses.KEY_NPAGE:
            self.orphan_index = min(self.orphan_index + 15, max(len(rows) - 1, 0))
        elif key == curses.KEY_PPAGE:
            self.orphan_index = max(self.orphan_index - 15, 0)
        elif key == curses.KEY_HOME:
            self.orphan_index = 0
        elif key == curses.KEY_END:
            self.orphan_index = max(len(rows) - 1, 0)
        elif key == ord(" ") and rows:
            name = rows[self.orphan_index].name
            if name in self.orphan_deselected:
                self.orphan_deselected.remove(name)
            else:
                self.orphan_deselected.add(name)
        elif key in (ord("a"), ord("A")):
            self.orphan_deselected.clear()
        elif key in (ord("c"), ord("C")):
            self.orphan_deselected.update(pkg.name for pkg in rows)
        elif key in (ord("m"), ord("M")) and rows:
            name = rows[self.orphan_index].name
            self.orphan_deselected.discard(name)
            self.model.protect_package(name)
        elif key in (ord("x"), ord("X")):
            roots = self._selected_orphan_names(rows)
            if roots:
                self._open_confirmation(snapshot, roots, official_only=False)
            else:
                self.model.set_message("No orphan packages selected.", ttl=12.0)
        return True

    def _handle_protected_key(self, key: int) -> bool:
        snapshot, _message = self.model.current_snapshot()
        names = self.model.protected_names(snapshot.packages)
        if key in (27, curses.KEY_BACKSPACE, ord("h"), ord("q"), ord("Q")):
            self.mode = "main"
            return True
        if key in (curses.KEY_DOWN, ord("j")):
            if names:
                self.protected_index = min(self.protected_index + 1, len(names) - 1)
        elif key in (curses.KEY_UP, ord("k")):
            self.protected_index = max(self.protected_index - 1, 0)
        elif key == curses.KEY_NPAGE:
            self.protected_index = min(self.protected_index + 15, max(len(names) - 1, 0))
        elif key == curses.KEY_PPAGE:
            self.protected_index = max(self.protected_index - 15, 0)
        elif key == curses.KEY_HOME:
            self.protected_index = 0
        elif key == curses.KEY_END:
            self.protected_index = max(len(names) - 1, 0)
        elif key in (ord("u"), ord("U")) and names:
            self.model.unprotect_package(names[self.protected_index])
        return True

    def draw(self, stdscr: curses.window) -> None:
        snapshot, message = self.model.current_snapshot()
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if self.mode == "main":
            self._draw_main(stdscr, snapshot, message, height, width)
        elif self.mode == "detail":
            self._draw_detail(stdscr, snapshot, message, height, width)
        elif self.mode == "orphans":
            self._draw_orphans(stdscr, snapshot, message, height, width)
        else:
            self._draw_protected(stdscr, snapshot, message, height, width)
        if self.confirm_plan is not None:
            self._draw_confirmation(stdscr, height, width)
        stdscr.refresh()

    def _open_confirmation(
        self,
        snapshot: RefreshSnapshot,
        roots: Iterable[str],
        official_only: bool = True,
    ) -> None:
        selected_roots = tuple(dict.fromkeys(root for root in roots if root and root in snapshot.packages))
        if not selected_roots:
            self.model.set_message("No removable packages selected.")
            return
        try:
            removal_names = removal_preview(selected_roots)
        except RuntimeError as exc:
            self.model.set_message(str(exc), ttl=12.0)
            return
        plan = validate_removal_plan(
            selected_roots,
            removal_names,
            snapshot.packages,
            set(self.model.user_protected),
            official_only=official_only,
        )
        if plan is None:
            error = removal_plan_error(
                selected_roots,
                removal_names,
                snapshot.packages,
                set(self.model.user_protected),
                official_only=official_only,
            )
            if error is None:
                error = (
                    f"Selection {format_name_list(selected_roots)} is no longer a valid removable set. "
                    "Refresh with r and try again."
                )
            self.model.set_message(error, ttl=16.0)
            return
        self.confirm_plan = plan

    def _draw_main(self, stdscr: curses.window, snapshot: RefreshSnapshot, message: str, height: int, width: int) -> None:
        candidates = self._sorted_candidates(snapshot)
        if self.main_index >= len(candidates):
            self.main_index = max(len(candidates) - 1, 0)
        body_height = max(height - 6, 1)
        max_offset = max(len(candidates) - body_height, 0)
        if self.main_index < self.main_offset:
            self.main_offset = self.main_index
        elif self.main_index >= self.main_offset + body_height:
            self.main_offset = self.main_index - body_height + 1
        self.main_offset = min(self.main_offset, max_offset)

        title = "Package Cleanup TUI"
        subtitle = "Official installed packages only | unsafe packages hidden | multiselect bulk removal"
        help_text = "Space mark | x remove marked/current | c clear marks | o orphans | Enter inspect | m protect | p protected | s sort | r refresh | q quit"
        self._safe_addstr(stdscr, 0, 0, title[: max(width - 1, 1)], curses.color_pair(2) | curses.A_BOLD)
        self._safe_addstr(stdscr, 1, 0, subtitle[: max(width - 1, 1)], curses.A_DIM)
        self._safe_addstr(stdscr, 2, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

        marker_width = 3
        name_width = max(min(width // 4, 28), 18)
        size_width = 0
        size_label = ""
        if self.sort_mode == "size":
            size_width = 10
            size_label = "Size"
        elif self.sort_mode == "reclaim":
            size_width = 10
            size_label = "Reclaim"
        desc_width = max(width - marker_width - name_width - size_width - (3 if size_width else 2), 20)
        header_attr = curses.color_pair(5) | curses.A_BOLD
        self._safe_addstr(stdscr, 3, 0, "Sel"[:marker_width], header_attr)
        self._safe_addstr(stdscr, 3, marker_width + 1, "Package"[:name_width], header_attr)
        size_col = marker_width + name_width + 2
        desc_col = marker_width + name_width + 2
        if size_width:
            self._safe_addstr(stdscr, 3, size_col, size_label[:size_width], header_attr)
            desc_col = marker_width + name_width + size_width + 3
        self._safe_addstr(stdscr, 3, desc_col, "Description"[:desc_width], header_attr)
        visible = candidates[self.main_offset : self.main_offset + body_height]
        for row, preview in enumerate(visible, start=4):
            selected = candidates[self.main_index].root == preview.root if candidates else False
            pkg = snapshot.packages.get(preview.root)
            marker = "[x]" if preview.root in self.selected_roots else "[ ]"
            name = preview.root[: name_width - 1]
            desc = (pkg.description if pkg else "")[: desc_width - 1]
            attr = curses.color_pair(1) | curses.A_BOLD if selected else curses.A_NORMAL
            self._safe_addstr(stdscr, row, 0, marker[:marker_width], attr)
            self._safe_addstr(stdscr, row, marker_width + 1, name.ljust(name_width), attr)
            if size_width:
                size_value = ""
                if self.sort_mode == "size" and pkg is not None:
                    size_value = format_bytes(pkg.installed_size)
                elif self.sort_mode == "reclaim":
                    size_value = format_bytes(preview.reclaimable_size)
                self._safe_addstr(stdscr, row, size_col, size_value.rjust(size_width), attr)
            self._safe_addstr(stdscr, row, desc_col, desc, attr)

        status_parts = [
            snapshot.status,
            f"sort {self.sort_mode}",
            format_count(len(candidates), "candidate"),
            f"selected {len(self.selected_roots)}",
            f"protected {len(self.model.user_protected)}",
        ]
        if candidates:
            selected = candidates[self.main_index]
            pkg = snapshot.packages.get(selected.root)
            if pkg is not None:
                status_parts.append(f"pkg {format_bytes(pkg.installed_size)}")
            status_parts.append(f"reclaim {format_bytes(selected.reclaimable_size)}")
        footer = " | ".join(status_parts)
        if message:
            footer = f"{footer} | {message}"
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))

    def _draw_detail(self, stdscr: curses.window, snapshot: RefreshSnapshot, message: str, height: int, width: int) -> None:
        if self.detail_root is None or self.detail_root not in snapshot.candidates:
            self.mode = "main"
            self.detail_root = None
            self._draw_main(stdscr, snapshot, message, height, width)
            return
        preview = snapshot.candidates[self.detail_root]
        pkg = snapshot.packages.get(preview.root)
        left_width = max(min(width // 4, 28), 22)
        right_width = max(min(width // 4, 32), 22)
        center_width = max(width - left_width - right_width - 2, 20)

        title = f"Inspect {preview.root}"
        marked = "yes" if preview.root in self.selected_roots else "no"
        help_text = "Space mark | x remove current | m protect/hide | Esc back | removal uses pacman with confirmation"
        self._safe_addstr(stdscr, 0, 0, title[: max(width - 1, 1)], curses.color_pair(2) | curses.A_BOLD)
        self._safe_addstr(stdscr, 1, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

        left_lines = [
            f"Package: {preview.root}",
            f"Marked: {marked}",
            f"Version: {pkg.version if pkg else '?'}",
            f"Installed size: {format_bytes(pkg.installed_size) if pkg else '?'}",
            f"Reclaimable: {format_bytes(preview.reclaimable_size)}",
            f"Removal set: {format_count(len(preview.removal_names), 'package')}",
            f"Install reason: {pkg.install_reason if pkg else '?'}",
            "",
            "Description:",
        ]
        if pkg:
            left_lines.extend(textwrap.wrap(pkg.description, width=max(left_width - 2, 16)) or [""])

        tree_lines = preview_tree_lines(preview, snapshot.packages, max(center_width - 1, 10))
        removal_items = sorted(
            (snapshot.packages[name] for name in preview.removal_names if name in snapshot.packages),
            key=lambda item: item.installed_size,
            reverse=True,
        )
        right_lines = ["Packages to remove:"]
        for item in removal_items[: max(height - 5, 1)]:
            size = format_bytes(item.installed_size)
            label = f"{item.name} ({size})"
            right_lines.extend(textwrap.wrap(label, width=max(right_width - 1, 16)) or [""])

        self._draw_panel(stdscr, 3, 0, height - 4, left_width, left_lines, title="Summary")
        self._draw_panel(stdscr, 3, left_width + 1, height - 4, center_width, tree_lines, title=f"Removal tree ({TREE_MAX_DEPTH} levels)")
        self._draw_panel(stdscr, 3, left_width + center_width + 2, height - 4, right_width, right_lines, title="Impact")

        footer = snapshot.status
        if message:
            footer = f"{footer} | {message}"
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))

    def _draw_orphans(self, stdscr: curses.window, snapshot: RefreshSnapshot, message: str, height: int, width: int) -> None:
        rows = self._orphan_rows(snapshot)
        if self.orphan_index >= len(rows):
            self.orphan_index = max(len(rows) - 1, 0)
        body_height = max(height - 6, 1)
        max_offset = max(len(rows) - body_height, 0)
        if self.orphan_index < self.orphan_offset:
            self.orphan_offset = self.orphan_index
        elif self.orphan_index >= self.orphan_offset + body_height:
            self.orphan_offset = self.orphan_index - body_height + 1
        self.orphan_offset = min(self.orphan_offset, max_offset)

        selected_names = self._selected_orphan_names(rows)
        selected_size = sum(snapshot.packages[name].installed_size for name in selected_names if name in snapshot.packages)
        title = "Orphan Packages"
        subtitle = "Dependency-installed packages with no reverse deps. All are selected by default."
        help_text = "Space unselect/reselect | x remove selected | a select all | c clear all | m protect | q back"
        self._safe_addstr(stdscr, 0, 0, title[: max(width - 1, 1)], curses.color_pair(2) | curses.A_BOLD)
        self._safe_addstr(stdscr, 1, 0, subtitle[: max(width - 1, 1)], curses.A_DIM)
        self._safe_addstr(stdscr, 2, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

        marker_width = 3
        repo_width = 4
        name_width = max(min(width // 4, 28), 18)
        size_width = 10
        desc_width = max(width - marker_width - repo_width - name_width - size_width - 5, 18)
        header_attr = curses.color_pair(5) | curses.A_BOLD
        self._safe_addstr(stdscr, 3, 0, "Sel"[:marker_width], header_attr)
        self._safe_addstr(stdscr, 3, marker_width + 1, "Repo"[:repo_width], header_attr)
        self._safe_addstr(stdscr, 3, marker_width + repo_width + 2, "Package"[:name_width], header_attr)
        size_col = marker_width + repo_width + name_width + 3
        desc_col = size_col + size_width + 1
        self._safe_addstr(stdscr, 3, size_col, "Size"[:size_width], header_attr)
        self._safe_addstr(stdscr, 3, desc_col, "Description"[:desc_width], header_attr)

        visible = rows[self.orphan_offset : self.orphan_offset + body_height]
        for row, pkg in enumerate(visible, start=4):
            selected = rows[self.orphan_index].name == pkg.name if rows else False
            marker = "[ ]" if pkg.name in self.orphan_deselected else "[x]"
            repo = "off" if pkg.official else "aur"
            attr = curses.color_pair(1) | curses.A_BOLD if selected else curses.A_NORMAL
            self._safe_addstr(stdscr, row, 0, marker[:marker_width], attr)
            self._safe_addstr(stdscr, row, marker_width + 1, repo[:repo_width], attr)
            self._safe_addstr(stdscr, row, marker_width + repo_width + 2, pkg.name[: name_width - 1].ljust(name_width), attr)
            self._safe_addstr(stdscr, row, size_col, format_bytes(pkg.installed_size).rjust(size_width), attr)
            self._safe_addstr(stdscr, row, desc_col, pkg.description[: desc_width - 1], attr)

        if not rows:
            self._safe_addstr(stdscr, 4, 0, "No orphan packages.", curses.A_DIM)

        status_parts = [
            snapshot.status,
            format_count(len(rows), "orphan"),
            f"selected {len(selected_names)}",
            f"size {format_bytes(selected_size)}",
        ]
        footer = " | ".join(status_parts)
        if message:
            footer = f"{footer} | {message}"
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))

    def _draw_protected(self, stdscr: curses.window, snapshot: RefreshSnapshot, message: str, height: int, width: int) -> None:
        names = self.model.protected_names(snapshot.packages)
        if self.protected_index >= len(names):
            self.protected_index = max(len(names) - 1, 0)
        body_top = 3
        body_height = max(height - 5, 1)
        max_offset = max(len(names) - body_height, 0)
        if self.protected_index < self.protected_offset:
            self.protected_offset = self.protected_index
        elif self.protected_index >= self.protected_offset + body_height:
            self.protected_offset = self.protected_index - body_height + 1
        self.protected_offset = min(self.protected_offset, max_offset)

        title = "Protected Packages"
        help_text = "u unprotect | q back"
        subtitle = f"Built-in protected defaults are always hidden. User protected: {len(names)}"
        self._safe_addstr(stdscr, 0, 0, title[: max(width - 1, 1)], curses.color_pair(2) | curses.A_BOLD)
        self._safe_addstr(stdscr, 1, 0, subtitle[: max(width - 1, 1)], curses.A_DIM)
        self._safe_addstr(stdscr, 2, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

        visible = names[self.protected_offset : self.protected_offset + body_height]
        for row, name in enumerate(visible, start=body_top):
            selected = names[self.protected_index] == name if names else False
            pkg = snapshot.packages.get(name)
            label = name if pkg is None else f"{name}  {pkg.description}"
            attr = curses.color_pair(1) | curses.A_BOLD if selected else curses.A_NORMAL
            self._safe_addstr(stdscr, row, 0, label[: max(width - 1, 1)], attr)
        if not names:
            self._safe_addstr(stdscr, body_top, 0, "No user-protected packages.", curses.A_DIM)

        footer = snapshot.status
        if message:
            footer = f"{footer} | {message}"
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))

    def _draw_panel(self, stdscr: curses.window, top: int, left: int, height: int, width: int, lines: list[str], title: str) -> None:
        if height <= 1 or width <= 2:
            return
        self._safe_addstr(stdscr, top, left, f"[{title}]"[:width], curses.color_pair(5) | curses.A_BOLD)
        for row_offset, line in enumerate(lines[: max(height - 1, 1)], start=1):
            self._safe_addstr(stdscr, top + row_offset, left, line[: max(width - 1, 1)], curses.A_NORMAL)

    def _draw_confirmation(self, stdscr: curses.window, height: int, width: int) -> None:
        if self.confirm_plan is None:
            return
        roots = ", ".join(self.confirm_plan.roots[:3])
        if len(self.confirm_plan.roots) > 3:
            roots = f"{roots}, ..."
        box_width = min(max(width - 8, 30), 70)
        box_height = 9
        top = max((height - box_height) // 2, 0)
        left = max((width - box_width) // 2, 0)
        for row in range(box_height):
            self._safe_addstr(stdscr, top + row, left, " " * box_width, curses.color_pair(6) | curses.A_BOLD)
        lines = [
            "Confirm removal",
            f"Selected roots: {len(self.confirm_plan.roots)}",
            f"Roots: {roots}",
            f"Packages removed: {len(self.confirm_plan.removal_names)}",
            f"Reclaimable size: {format_bytes(self.confirm_plan.reclaimable_size)}",
            "Press y to run pacman, n to cancel.",
        ]
        for offset, line in enumerate(lines, start=1):
            self._safe_addstr(
                stdscr,
                top + offset,
                left + 2,
                line[: max(box_width - 4, 1)],
                curses.A_BOLD if offset == 1 else curses.A_NORMAL,
            )

    def _perform_removal(self, stdscr: curses.window) -> None:
        plan = self.confirm_plan
        if plan is None:
            return
        command = shell_command_for_removal(plan.roots)
        self.confirm_plan = None
        curses.def_prog_mode()
        curses.endwin()
        print(f"Running: {' '.join(shlex.quote(part) for part in command)}")
        print("pacman will ask for confirmation before removing anything.")
        print()
        try:
            completed = subprocess.run(command, check=False)
            returncode = completed.returncode
        except FileNotFoundError as exc:
            returncode = 127
            print(str(exc))
        input("\nPress Enter to return to the TUI...")
        curses.reset_prog_mode()
        stdscr.keypad(True)
        stdscr.nodelay(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        if returncode == 0:
            self.selected_roots.difference_update(plan.roots)
            self.orphan_deselected.difference_update(plan.roots)
            self.mode = "main"
            self.detail_root = None
            self.model.apply_local_removal(plan)
        else:
            self.model.set_message(f"Removal exited with code {returncode}.", ttl=12.0)

    @staticmethod
    def _safe_addstr(window: curses.window, y: int, x: int, text: str, attr: int = curses.A_NORMAL) -> None:
        try:
            window.addnstr(y, x, text, max(len(text), 0), attr)
        except curses.error:
            pass

