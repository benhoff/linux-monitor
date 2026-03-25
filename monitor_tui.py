#!/usr/bin/env python3

from __future__ import annotations

import argparse
import curses
import json
import os
import re
import shutil
import signal
import subprocess
import textwrap
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence


TAB_ORDER = ("tier1", "tier2", "tier3")
TAB_TITLES = {
    "tier1": "Tier 1",
    "tier2": "Tier 2",
    "tier3": "Tier 3",
}
PACKAGE_REFRESH_INTERVAL = 900
DIFF_SNAPSHOT_INTERVAL = 120
DEFAULT_PRIVILEGED_SNAPSHOT = "/run/monitor/privileged_snapshot.json"
PSEUDO_FILESYSTEMS = {
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "overlay",
    "proc",
    "pstore",
    "securityfs",
    "selinuxfs",
    "squashfs",
    "sysfs",
    "tmpfs",
    "tracefs",
}
WATCHED_DIRS = (
    Path("/var/log"),
    Path("/var/cache"),
    Path("/var/tmp"),
    Path("/tmp"),
    Path("/var/lib/docker"),
    Path("/var/lib/systemd/coredump"),
    Path.home() / ".cache",
)
ENCODER_KEYWORDS = ("nvenc", "vaapi", "v4l2m2m", "qsv", "amf", "rkmpp")
DEVICE_LOG_PATTERN = r"HDMI|EDID|drm|v4l2|CSI|camera|encoder|nvenc|mpp|video"
FS_LOG_PATTERN = (
    r"EXT4-fs error|BTRFS|XFS|Buffer I/O error|I/O error|"
    r"read-only file system|Remounting filesystem read-only|mount failure|corrupt"
)
THROTTLE_LOG_PATTERN = r"throttl|thermal"
HARDWARE_LOG_PATTERN = r"gpu|drm|hdmi|edid|nvme|ata|usb|pci|v4l2|camera|csi"
KERNEL_PACKAGE_NAMES = (
    "linux",
    "linux-lts",
    "linux-zen",
    "linux-hardened",
)
FIRMWARE_PACKAGE_PREFIXES = ("linux-firmware",)
FIRMWARE_PACKAGE_NAMES = ("intel-ucode", "amd-ucode")
NVIDIA_PACKAGE_NAMES = (
    "nvidia",
    "nvidia-open",
    "nvidia-dkms",
    "nvidia-open-dkms",
    "nvidia-utils",
    "lib32-nvidia-utils",
)


@dataclass
class CommandResult:
    args: Sequence[str]
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    missing: bool = False
    timed_out: bool = False


@dataclass
class SectionState:
    title: str
    lines: list[str] = field(default_factory=lambda: ["Loading..."])
    loading: bool = True
    last_updated: float = 0.0
    duration: float = 0.0
    last_error: str | None = None


@dataclass(frozen=True)
class Collector:
    key: str
    tab: str
    title: str
    interval: int
    func: Callable[[], list[str]]


@dataclass
class PackageRefreshState:
    loading: bool = False
    last_updated: float = 0.0
    official_updates: dict[str, tuple[str, str]] = field(default_factory=dict)
    aur_updates: dict[str, tuple[str, str]] = field(default_factory=dict)
    official_error: str | None = None
    aur_error: str | None = None


def run_command(args: Sequence[str], timeout: float = 5.0) -> CommandResult:
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(args, False, 127, "", "command not found", missing=True)
    except subprocess.TimeoutExpired:
        return CommandResult(args, False, 124, "", "command timed out", timed_out=True)
    return CommandResult(
        args=args,
        ok=completed.returncode == 0,
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_lines(path: Path, limit: int | None = None) -> list[str]:
    text = read_text(path)
    lines = text.splitlines()
    if limit is not None:
        return lines[-limit:]
    return lines


def format_bytes(value: float | int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    size = float(value)
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            if size >= 100:
                return f"{size:.0f} {unit}"
            if size >= 10:
                return f"{size:.1f} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PiB"


def format_percent(numerator: float, denominator: float) -> str:
    if denominator <= 0:
        return "n/a"
    return f"{(numerator / denominator) * 100:.1f}%"


def format_duration_compact(seconds: int | float) -> str:
    total = max(int(seconds), 0)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def shorten(value: str, limit: int = 120) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def single_line(value: str) -> str:
    return " ".join(value.split())


def first_nonempty_line(value: str) -> str:
    for line in value.splitlines():
        if line.strip():
            return line.strip()
    return ""


def parse_int(value: str, default: int = 0) -> int:
    match = re.search(r"-?\d+", value)
    if not match:
        return default
    return int(match.group(0))


def line_list(text: str, limit: int | None = None) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if limit is not None:
        return lines[:limit]
    return lines


def journal_line_list(text: str, limit: int | None = None) -> list[str]:
    lines = [line for line in line_list(text) if line != "-- No entries --"]
    if limit is not None:
        return lines[:limit]
    return lines


def detect_ro_mounts() -> list[str]:
    mounts = []
    result = run_command(["findmnt", "-rn", "-o", "TARGET,OPTIONS"], timeout=3)
    if not result.stdout:
        return mounts
    for raw in result.stdout.splitlines():
        parts = raw.split(None, 1)
        if len(parts) != 2:
            continue
        target, options = parts
        option_list = set(options.split(","))
        if "ro" in option_list:
            mounts.append(target)
    return mounts


def parse_journal_lines(result: CommandResult, limit: int = 8) -> list[str]:
    if result.stdout:
        entries = journal_line_list(result.stdout, limit)
        if entries:
            return [shorten(line, 150) for line in entries]
        return ["No matching entries."]
    if result.missing:
        return [f"{result.args[0]} not found."]
    if result.timed_out:
        return [f"{result.args[0]} timed out."]
    if result.stderr:
        return [shorten(single_line(result.stderr), 150)]
    return ["No matching entries."]


class MonitorBackend:
    def __init__(self) -> None:
        self.cache: dict[str, tuple[float, object]] = {}
        self.cpu_prev: tuple[float, dict[str, int]] | None = None
        self.disk_prev: tuple[float, dict[str, tuple[int, int]]] | None = None
        self.package_state = PackageRefreshState()
        self.package_lock = threading.Lock()
        self.package_force_event = threading.Event()
        self.package_stop_event = threading.Event()
        self.package_worker: threading.Thread | None = None
        self.package_worker_started = False

    def cached(self, key: str, ttl: float, producer: Callable[[], object]) -> object:
        now = time.time()
        cached = self.cache.get(key)
        if cached and cached[0] > now:
            return cached[1]
        value = producer()
        self.cache[key] = (now + ttl, value)
        return value

    @staticmethod
    def _privileged_snapshot_path() -> Path:
        return Path(os.environ.get("MONITOR_PRIVILEGED_SNAPSHOT", DEFAULT_PRIVILEGED_SNAPSHOT))

    def _load_privileged_snapshot(self) -> dict[str, object]:
        path = self._privileged_snapshot_path()
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _privileged_snapshot(self) -> dict[str, object]:
        return self.cached("privileged_snapshot", 2.0, self._load_privileged_snapshot)

    def _privileged_section(self, name: str) -> dict[str, object] | None:
        snapshot = self._privileged_snapshot()
        section = snapshot.get(name)
        if isinstance(section, dict):
            return section
        return None

    def _privileged_snapshot_line(self) -> str | None:
        snapshot = self._privileged_snapshot()
        generated = snapshot.get("generated_at")
        if not isinstance(generated, (int, float)):
            return None
        timestamp = datetime.fromtimestamp(generated).strftime("%H:%M:%S")
        age = max(int(time.time() - generated), 0)
        return f"Privileged snapshot: {timestamp} ({age}s ago)"

    @staticmethod
    def _diff_snapshot_path() -> Path:
        override = os.environ.get("MONITOR_DIFF_SNAPSHOT")
        if override:
            return Path(override)
        state_root = os.environ.get("XDG_STATE_HOME")
        if state_root:
            return Path(state_root) / "monitor" / "diff_snapshot.json"
        return Path.cwd() / ".monitor_state" / "diff_snapshot.json"

    def _load_diff_snapshot(self) -> dict[str, object] | None:
        path = self._diff_snapshot_path()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if isinstance(data, dict):
            return data
        return None

    def _write_diff_snapshot(self, payload: dict[str, object]) -> None:
        path = self._diff_snapshot_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _age_label(seconds: int) -> str:
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m"
        return f"{seconds // 3600}h"

    def _current_state_digest(self) -> dict[str, object]:
        return self.cached("current_state_digest", 10.0, self._build_state_digest)

    def _build_state_digest(self) -> dict[str, object]:
        now = time.time()
        installed = self.cached("installed_packages", 30.0, self._installed_packages)
        with self.package_lock:
            package_state = PackageRefreshState(
                loading=self.package_state.loading,
                last_updated=self.package_state.last_updated,
                official_updates=dict(self.package_state.official_updates),
                aur_updates=dict(self.package_state.aur_updates),
                official_error=self.package_state.official_error,
                aur_error=self.package_state.aur_error,
            )

        kernel_updates = {**package_state.aur_updates, **package_state.official_updates}
        tracked_rows = [
            *self._tracked_kernel_packages(installed),
            *self._tracked_firmware_versions(installed),
            *self._tracked_nvidia_packages(installed),
        ]
        tracked_outdated = sum(
            1
            for name, version in tracked_rows
            if (latest := self._latest_version_for(name, kernel_updates)) is not None and latest != version
        )

        fs_entries = self._filesystem_usage()
        inode_usage = self._inode_usage()
        dir_sizes = self.cached("dir_sizes", 300.0, self._directory_sizes)
        root_entry = next((entry for entry in fs_entries if entry["target"] == "/"), None)
        healthy_count = 0
        watch_count = 0
        critical_count = 0
        for entry in fs_entries:
            severity = self._storage_severity(int(entry["pct"]), inode_usage.get(str(entry["target"])))
            if severity == "critical":
                critical_count += 1
            elif severity == "watch":
                watch_count += 1
            else:
                healthy_count += 1

        privileged_systemd = self._privileged_section("systemd")
        system_state = "unknown"
        failed_services = None
        if privileged_systemd:
            system_state = str(privileged_systemd.get("state", "unknown"))
            failed = privileged_systemd.get("failed_services", [])
            failed_services = len(failed) if isinstance(failed, list) else None
        else:
            system_state = self._systemd_state()
            failed_services = len(self._failed_services())

        privileged_logs = self._privileged_section("logs")
        journal_error_count = None
        if privileged_logs:
            errors = privileged_logs.get("journal_errors", [])
            journal_error_count = len(errors) if isinstance(errors, list) else None

        meminfo = self._meminfo()
        mem_total = meminfo.get("MemTotal", 0) * 1024
        mem_available = meminfo.get("MemAvailable", 0) * 1024
        mem_used = max(mem_total - mem_available, 0)
        psi = self._psi(Path("/proc/pressure/memory"))
        psi_full10 = float(psi.get("full", {}).get("avg10", 0.0))

        max_temp = 0.0
        for item in self._thermal_zones():
            match = re.search(r"(-?\d+(?:\.\d+)?)\s*C", item)
            if match:
                max_temp = max(max_temp, float(match.group(1)))

        growth = {
            self._abbreviate_path(path): size
            for path, size in dir_sizes[:5]
        }

        return {
            "captured_at": now,
            "packages": {
                "repo_pending": None if package_state.official_error else len(package_state.official_updates),
                "aur_pending": None if package_state.aur_error else len(package_state.aur_updates),
                "tracked_outdated": tracked_outdated,
            },
            "storage": {
                "root_pct": int(root_entry["pct"]) if root_entry else None,
                "root_free": int(root_entry["avail"]) if root_entry else None,
                "healthy_count": healthy_count,
                "watch_count": watch_count,
                "critical_count": critical_count,
                "growth": growth,
            },
            "systemd": {
                "state": system_state,
                "failed_services": failed_services,
            },
            "logs": {
                "journal_errors": journal_error_count,
            },
            "memory": {
                "used_pct": (mem_used / mem_total * 100.0) if mem_total else None,
                "psi_full10": psi_full10,
            },
            "thermal": {
                "max_temp_c": max_temp if max_temp > 0 else None,
            },
        }

    def collect_diff_snapshot(self) -> list[str]:
        current = self._current_state_digest()
        previous = self._load_diff_snapshot()
        lines: list[str] = []

        if not previous:
            lines.append("No prior diff snapshot yet. A baseline will be written automatically.")
            self._write_diff_snapshot(current)
            return lines

        captured_at = previous.get("captured_at")
        if isinstance(captured_at, (int, float)):
            age = max(int(current["captured_at"] - captured_at), 0)
            lines.append(f"Compared with {self._age_label(age)} ago")
        else:
            lines.append("Compared with previous snapshot")

        changes: list[str] = []
        current_packages = current.get("packages", {})
        previous_packages = previous.get("packages", {})
        if isinstance(current_packages, dict) and isinstance(previous_packages, dict):
            current_total = None
            previous_total = None
            if isinstance(current_packages.get("repo_pending"), int) and isinstance(current_packages.get("aur_pending"), int):
                current_total = int(current_packages["repo_pending"]) + int(current_packages["aur_pending"])
            if isinstance(previous_packages.get("repo_pending"), int) and isinstance(previous_packages.get("aur_pending"), int):
                previous_total = int(previous_packages["repo_pending"]) + int(previous_packages["aur_pending"])
            if current_total is not None and previous_total is not None and current_total != previous_total:
                delta = current_total - previous_total
                changes.append(f"Packages: {delta:+d} pending updates ({current_total} now)")
            current_tracked = current_packages.get("tracked_outdated")
            previous_tracked = previous_packages.get("tracked_outdated")
            if isinstance(current_tracked, int) and isinstance(previous_tracked, int) and current_tracked != previous_tracked:
                delta = current_tracked - previous_tracked
                changes.append(f"Tracked critical packages: {delta:+d} outdated ({current_tracked} now)")

        current_storage = current.get("storage", {})
        previous_storage = previous.get("storage", {})
        if isinstance(current_storage, dict) and isinstance(previous_storage, dict):
            current_root_pct = current_storage.get("root_pct")
            previous_root_pct = previous_storage.get("root_pct")
            if isinstance(current_root_pct, int) and isinstance(previous_root_pct, int) and current_root_pct != previous_root_pct:
                changes.append(f"Root usage: {current_root_pct - previous_root_pct:+d}% ({current_root_pct}% now)")
            current_root_free = current_storage.get("root_free")
            previous_root_free = previous_storage.get("root_free")
            if isinstance(current_root_free, int) and isinstance(previous_root_free, int):
                delta = current_root_free - previous_root_free
                if abs(delta) >= 1024**3:
                    changes.append(f"Root free space: {format_bytes(delta)} change ({format_bytes(current_root_free)} now)")
            current_growth = current_storage.get("growth", {})
            previous_growth = previous_storage.get("growth", {})
            if isinstance(current_growth, dict) and isinstance(previous_growth, dict):
                growth_deltas = []
                for path, size in current_growth.items():
                    previous_size = previous_growth.get(path)
                    if isinstance(size, int) and isinstance(previous_size, int):
                        delta = size - previous_size
                        if abs(delta) >= 1024**3:
                            growth_deltas.append((path, delta))
                growth_deltas.sort(key=lambda item: abs(item[1]), reverse=True)
                if growth_deltas:
                    changes.append(
                        "Growth: "
                        + ", ".join(
                            f"{path} {format_bytes(delta)}"
                            for path, delta in growth_deltas[:2]
                        )
                    )

        current_systemd = current.get("systemd", {})
        previous_systemd = previous.get("systemd", {})
        if isinstance(current_systemd, dict) and isinstance(previous_systemd, dict):
            current_failed = current_systemd.get("failed_services")
            previous_failed = previous_systemd.get("failed_services")
            if isinstance(current_failed, int) and isinstance(previous_failed, int) and current_failed != previous_failed:
                changes.append(f"Failed services: {current_failed - previous_failed:+d} ({current_failed} now)")

        if not changes:
            lines.append("No high-signal changes since the last diff snapshot.")
        else:
            lines.extend(changes[:5])

        if not isinstance(captured_at, (int, float)) or current["captured_at"] - captured_at >= DIFF_SNAPSHOT_INTERVAL:
            self._write_diff_snapshot(current)
        return lines

    def collect_top_problems(self) -> list[str]:
        current = self._current_state_digest()
        previous = self._load_diff_snapshot()
        problems: list[tuple[int, str]] = []

        packages = current.get("packages", {})
        if isinstance(packages, dict):
            repo_pending = packages.get("repo_pending")
            aur_pending = packages.get("aur_pending")
            tracked_outdated = packages.get("tracked_outdated")
            if isinstance(repo_pending, int) and isinstance(aur_pending, int):
                pending_total = repo_pending + aur_pending
                if pending_total > 0:
                    severity = 90 if pending_total >= 50 else 60
                    problems.append((severity, f"? {pending_total} pending package updates ({aur_pending} AUR)"))
            if isinstance(tracked_outdated, int) and tracked_outdated > 0:
                severity = 95 if tracked_outdated >= 3 else 70
                problems.append((severity, f"? {tracked_outdated} tracked kernel/firmware/NVIDIA packages are outdated"))

        storage = current.get("storage", {})
        if isinstance(storage, dict):
            root_pct = storage.get("root_pct")
            critical_count = storage.get("critical_count")
            watch_count = storage.get("watch_count")
            if isinstance(root_pct, int) and root_pct >= 90:
                problems.append((100, f"! Root filesystem is {root_pct}% full"))
            elif isinstance(root_pct, int) and root_pct >= 75:
                problems.append((70, f"? Root filesystem is {root_pct}% full"))
            if isinstance(critical_count, int) and critical_count > 0:
                problems.append((95, f"! {critical_count} filesystems are in critical capacity"))
            elif isinstance(watch_count, int) and watch_count > 0:
                problems.append((60, f"? {watch_count} filesystems are approaching capacity"))

        systemd_state = current.get("systemd", {})
        if isinstance(systemd_state, dict):
            failed_services = systemd_state.get("failed_services")
            state_value = str(systemd_state.get("state", "unknown"))
            if isinstance(failed_services, int) and failed_services > 0:
                severity = 100 if failed_services >= 3 else 80
                problems.append((severity, f"! {failed_services} failed services ({state_value})"))
            elif state_value in {"degraded", "failed"}:
                problems.append((75, f"? System state is {state_value}"))

        memory = current.get("memory", {})
        if isinstance(memory, dict):
            used_pct = memory.get("used_pct")
            psi_full10 = memory.get("psi_full10")
            if isinstance(used_pct, (int, float)) and used_pct >= 90:
                problems.append((85, f"! RAM usage is {used_pct:.0f}%"))
            if isinstance(psi_full10, (int, float)) and psi_full10 >= 0.1:
                problems.append((90, f"! Memory full PSI avg10 is {psi_full10:.2f}"))
            elif isinstance(psi_full10, (int, float)) and psi_full10 > 0.0:
                problems.append((55, f"? Memory full PSI avg10 is {psi_full10:.2f}"))

        thermal = current.get("thermal", {})
        if isinstance(thermal, dict):
            max_temp_c = thermal.get("max_temp_c")
            if isinstance(max_temp_c, (int, float)) and max_temp_c >= 85:
                problems.append((85, f"! Max observed system temperature is {max_temp_c:.1f} C"))
            elif isinstance(max_temp_c, (int, float)) and max_temp_c >= 75:
                problems.append((55, f"? Max observed system temperature is {max_temp_c:.1f} C"))

        logs = current.get("logs", {})
        if isinstance(logs, dict):
            journal_errors = logs.get("journal_errors")
            if isinstance(journal_errors, int) and journal_errors > 0:
                severity = 65 if journal_errors < 10 else 80
                problems.append((severity, f"? Journal shows {journal_errors} error entries this boot"))

        if previous and isinstance(previous, dict):
            previous_storage = previous.get("storage", {})
            current_storage = current.get("storage", {})
            if isinstance(previous_storage, dict) and isinstance(current_storage, dict):
                current_root_free = current_storage.get("root_free")
                previous_root_free = previous_storage.get("root_free")
                if isinstance(current_root_free, int) and isinstance(previous_root_free, int):
                    delta = current_root_free - previous_root_free
                    if delta <= -(5 * 1024**3):
                        problems.append((75, f"? Root free space dropped by {format_bytes(abs(delta))} since the last diff snapshot"))

        if not problems:
            return ["No major problems detected right now."]

        deduped: list[str] = []
        for _severity, message in sorted(problems, key=lambda item: item[0], reverse=True):
            if message not in deduped:
                deduped.append(message)
        return deduped[:5]

    def start_package_worker(self) -> None:
        if self.package_worker_started:
            return
        self.package_worker_started = True
        self.package_stop_event.clear()
        self.package_force_event.set()
        self.package_worker = threading.Thread(target=self._package_refresh_loop, daemon=True)
        self.package_worker.start()

    def stop_background_tasks(self) -> None:
        self.package_stop_event.set()
        self.package_force_event.set()
        if self.package_worker is not None:
            self.package_worker.join(timeout=1.0)
            self.package_worker = None
        self.package_worker_started = False

    def request_package_refresh(self) -> None:
        self.package_force_event.set()

    def _package_refresh_loop(self) -> None:
        next_refresh = 0.0
        while not self.package_stop_event.is_set():
            now = time.time()
            if self.package_force_event.is_set() or now >= next_refresh:
                self.package_force_event.clear()
                self.refresh_package_state_sync()
                next_refresh = time.time() + PACKAGE_REFRESH_INTERVAL
                continue
            timeout = max(min(next_refresh - now, 1.0), 0.1)
            self.package_force_event.wait(timeout=timeout)

    @staticmethod
    def _parse_update_map(lines: Sequence[str]) -> dict[str, tuple[str, str]]:
        updates: dict[str, tuple[str, str]] = {}
        for raw in lines:
            match = re.match(r"^(\S+)\s+(\S+)\s+->\s+(\S+)$", raw)
            if not match:
                continue
            name, current, latest = match.groups()
            updates[name] = (current, latest)
        return updates

    def refresh_package_state_sync(self) -> None:
        with self.package_lock:
            previous = self.package_state
            self.package_state = PackageRefreshState(
                loading=True,
                last_updated=previous.last_updated,
                official_updates=previous.official_updates,
                aur_updates=previous.aur_updates,
                official_error=previous.official_error,
                aur_error=previous.aur_error,
            )
        official_lines, official_error = self._official_updates()
        aur_lines, aur_error = self._aur_updates()
        with self.package_lock:
            self.package_state = PackageRefreshState(
                loading=False,
                last_updated=time.time(),
                official_updates=self._parse_update_map(official_lines),
                aur_updates=self._parse_update_map(aur_lines),
                official_error=official_error,
                aur_error=aur_error,
            )

    def _installed_packages(self) -> dict[str, str]:
        result = run_command(["pacman", "-Q"], timeout=6.0)
        packages: dict[str, str] = {}
        for raw in line_list(result.stdout):
            parts = raw.split(None, 1)
            if len(parts) != 2:
                continue
            packages[parts[0]] = parts[1]
        return packages

    def _running_kernel_version(self) -> str:
        result = run_command(["uname", "-r"], timeout=2.0)
        return result.stdout.splitlines()[0] if result.stdout else "unavailable"

    def _nvidia_module_version(self) -> str:
        text = read_text(Path("/proc/driver/nvidia/version"))
        match = re.search(r"NVRM version: .*?\s(\d+\.\d+\.\d+)\s+Release Build", text)
        if match:
            return match.group(1)
        return "unavailable"

    @staticmethod
    def _tracked_kernel_packages(installed: dict[str, str]) -> list[tuple[str, str]]:
        return [(name, installed[name]) for name in KERNEL_PACKAGE_NAMES if name in installed]

    @staticmethod
    def _tracked_firmware_versions(installed: dict[str, str]) -> list[tuple[str, str]]:
        versions = sorted(
            {
                version
                for name, version in installed.items()
                if name.startswith(FIRMWARE_PACKAGE_PREFIXES)
            }
        )
        rows: list[tuple[str, str]] = []
        if versions:
            if len(versions) == 1:
                rows.append(("linux-firmware*", versions[0]))
            else:
                rows.append(("linux-firmware*", ", ".join(versions)))
        for name in FIRMWARE_PACKAGE_NAMES:
            if name in installed:
                rows.append((name, installed[name]))
        return rows

    @staticmethod
    def _tracked_nvidia_packages(installed: dict[str, str]) -> list[tuple[str, str]]:
        return [(name, installed[name]) for name in NVIDIA_PACKAGE_NAMES if name in installed]

    @staticmethod
    def _package_line(name: str, installed_version: str, latest_version: str | None) -> str:
        if latest_version and latest_version != installed_version:
            return f"{name}: {installed_version} -> {latest_version}"
        return f"{name}: {installed_version} current"

    @staticmethod
    def _latest_version_for(name: str, updates: dict[str, tuple[str, str]]) -> str | None:
        if name in updates:
            return updates[name][1]
        if name == "linux-firmware*" and "linux-firmware" in updates:
            return updates["linux-firmware"][1]
        return None

    def command_lines(
        self,
        primary: Sequence[str],
        fallback: Sequence[str] | None = None,
        timeout: float = 6.0,
    ) -> tuple[list[str], str | None]:
        attempts = [primary]
        if fallback is not None:
            attempts.append(fallback)
        errors: list[str] = []
        for args in attempts:
            result = run_command(args, timeout=timeout)
            if result.stdout or result.ok:
                return line_list(result.stdout), None
            if result.missing:
                errors.append(f"{args[0]} not found")
                continue
            if result.timed_out:
                errors.append(f"{args[0]} timed out")
                continue
            if result.stderr:
                errors.append(shorten(single_line(result.stderr), 100))
        if errors:
            return [], "; ".join(errors)
        return [], None

    def count_command_lines(self, args: Sequence[str], timeout: float = 5.0) -> tuple[int | None, str | None]:
        result = run_command(args, timeout=timeout)
        if result.stdout or result.ok:
            return len(line_list(result.stdout)), None
        if result.missing:
            return None, f"{args[0]} not found"
        if result.timed_out:
            return None, f"{args[0]} timed out"
        if result.stderr:
            return None, shorten(single_line(result.stderr), 120)
        return 0, None

    def _official_updates(self) -> tuple[list[str], str | None]:
        return self.command_lines(
            ["checkupdates"],
            fallback=["pacman", "-Qu"],
            timeout=8.0,
        )

    def _aur_updates(self) -> tuple[list[str], str | None]:
        return self.command_lines(["yay", "-Qua"], timeout=12.0)

    def _count_explicit(self) -> tuple[int | None, str | None]:
        return self.count_command_lines(["pacman", "-Qe"])

    def _count_dependencies(self) -> tuple[int | None, str | None]:
        return self.count_command_lines(["pacman", "-Qd"])

    def _orphan_packages(self) -> tuple[list[str], str | None]:
        return self.command_lines(["pacman", "-Qtdq"])

    def _foreign_packages(self) -> tuple[list[str], str | None]:
        return self.command_lines(["pacman", "-Qm"])

    def _ignored_packages(self) -> list[str]:
        ignored: list[str] = []
        for raw in read_lines(Path("/etc/pacman.conf")):
            line = raw.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if key in {"IgnorePkg", "IgnoreGroup"} and value:
                ignored.extend(value.split())
        return ignored

    def _recent_upgrades(self) -> list[str]:
        pacman_log = Path("/var/log/pacman.log")
        if not pacman_log.exists():
            return []
        upgrades: list[str] = []
        for line in reversed(read_lines(pacman_log, limit=2500)):
            if "[ALPM] upgraded " in line:
                upgrades.append(line.split("upgraded ", 1)[1].strip())
            elif "[ALPM] installed " in line:
                upgrades.append(line.split("installed ", 1)[1].strip())
            if len(upgrades) >= 6:
                break
        return upgrades

    def collect_packages(self) -> list[str]:
        if not self.package_worker_started and self.package_state.last_updated == 0.0:
            self.refresh_package_state_sync()

        installed = self.cached("installed_packages", 30.0, self._installed_packages)
        foreign, foreign_error = self.cached("foreign", 900.0, self._foreign_packages)
        ignored = self.cached("ignored", 1800.0, self._ignored_packages)
        running_kernel = self._running_kernel_version()
        nvidia_module = self._nvidia_module_version()
        with self.package_lock:
            state = PackageRefreshState(
                loading=self.package_state.loading,
                last_updated=self.package_state.last_updated,
                official_updates=dict(self.package_state.official_updates),
                aur_updates=dict(self.package_state.aur_updates),
                official_error=self.package_state.official_error,
                aur_error=self.package_state.aur_error,
            )

        lines: list[str] = []
        total_pending = len(state.official_updates) + len(state.aur_updates)
        if state.loading and state.last_updated == 0.0:
            lines.append("Background refresh: syncing latest package metadata...")
        elif state.loading:
            last = datetime.fromtimestamp(state.last_updated).strftime("%H:%M:%S")
            lines.append(f"Background refresh: syncing latest package metadata (last refresh {last})")
        elif state.last_updated:
            last = datetime.fromtimestamp(state.last_updated).strftime("%H:%M:%S")
            age = max(int(time.time() - state.last_updated), 0)
            lines.append(f"Background refresh: last refresh {last} ({age}s ago)")
        else:
            lines.append("Background refresh: not started")

        warnings = [item for item in (state.official_error, state.aur_error) if item]
        if warnings:
            lines.append("Refresh warnings: " + " | ".join(warnings))

        kernel_updates = {**state.aur_updates, **state.official_updates}
        kernel_packages = self._tracked_kernel_packages(installed)
        firmware_packages = self._tracked_firmware_versions(installed)
        nvidia_packages = self._tracked_nvidia_packages(installed)
        tracked_rows = [
            *[(name, version) for name, version in kernel_packages],
            *[(name, version) for name, version in firmware_packages],
            *[(name, version) for name, version in nvidia_packages],
        ]
        tracked_outdated = sum(
            1
            for name, version in tracked_rows
            if (latest := self._latest_version_for(name, kernel_updates)) is not None and latest != version
        )

        lines.append("Summary:")
        repo_summary = "?" if state.official_error else str(len(state.official_updates))
        aur_summary = "?" if state.aur_error else str(len(state.aur_updates))
        total_summary = (
            "unknown"
            if state.official_error or state.aur_error
            else str(total_pending)
        )
        lines.append(
            f"  Pending updates: {total_summary} total | {repo_summary} repo | {aur_summary} AUR"
        )
        lines.append(
            f"  Installed foreign packages: {len(foreign)}"
            + (f" ({foreign_error})" if foreign_error else "")
            + f" | ignored packages: {len(ignored)}"
        )
        lines.append(f"  Tracked critical packages outdated: {tracked_outdated}/{len(tracked_rows)}")

        lines.append("Kernel:")
        lines.append(f"  running kernel: {running_kernel}")
        if kernel_packages:
            for name, version in kernel_packages:
                latest = self._latest_version_for(name, kernel_updates)
                lines.append(f"  {self._package_line(name, version, latest)}")
        else:
            lines.append("  no tracked kernel package installed")

        lines.append("Firmware:")
        if firmware_packages:
            for name, version in firmware_packages:
                latest = self._latest_version_for(name, kernel_updates)
                lines.append(f"  {self._package_line(name, version, latest)}")
        else:
            lines.append("  no tracked firmware package installed")

        lines.append("NVIDIA:")
        lines.append(f"  loaded module: {nvidia_module}")
        if nvidia_packages:
            for name, version in nvidia_packages:
                latest = self._latest_version_for(name, kernel_updates)
                lines.append(f"  {self._package_line(name, version, latest)}")
        else:
            lines.append("  no tracked NVIDIA package installed")
        return lines

    def _filesystem_usage(self) -> list[dict[str, str | int]]:
        result = run_command(["df", "-PT", "-B1"], timeout=4.0)
        entries: list[dict[str, str | int]] = []
        if not result.stdout:
            return entries
        for raw in result.stdout.splitlines()[1:]:
            parts = raw.split()
            if len(parts) < 7:
                continue
            source, fstype, size, used, avail, pct, target = parts[:7]
            if fstype in PSEUDO_FILESYSTEMS:
                continue
            entries.append(
                {
                    "source": source,
                    "fstype": fstype,
                    "size": int(size),
                    "used": int(used),
                    "avail": int(avail),
                    "pct": parse_int(pct),
                    "target": target,
                }
            )
        return entries

    def _inode_usage(self) -> dict[str, int]:
        result = run_command(["df", "-Pi"], timeout=4.0)
        usage: dict[str, int] = {}
        if not result.stdout:
            return usage
        for raw in result.stdout.splitlines()[1:]:
            parts = raw.split()
            if len(parts) < 6:
                continue
            pct = parse_int(parts[4])
            target = parts[5]
            usage[target] = pct
        return usage

    def _mount_summary(self) -> list[str]:
        result = run_command(["findmnt", "-rn", "-o", "TARGET,FSTYPE,OPTIONS"], timeout=3.0)
        mounts: list[str] = []
        if not result.stdout:
            return mounts
        for raw in result.stdout.splitlines():
            parts = raw.split(None, 2)
            if len(parts) != 3:
                continue
            target, fstype, options = parts
            if fstype in PSEUDO_FILESYSTEMS:
                continue
            if target.startswith("/run/user/") or target.endswith("/.git") or "/gvfs" in target or "/doc" in target:
                continue
            state = "ro" if "ro" in options.split(",") else "rw"
            mounts.append(f"{target} {fstype} {state}")
        mounts.sort(key=self._mount_sort_key)
        return mounts

    @staticmethod
    def _mount_sort_key(item: str) -> tuple[int, str]:
        target = item.split()[0]
        home_target = str(Path.home())
        priority = {
            "/": 0,
            home_target: 1,
            "/home": 2,
            "/var": 3,
            "/boot": 4,
            "/boot/efi": 5,
            "/tmp": 6,
        }.get(target, 50)
        return (priority, target)

    @staticmethod
    def _filesystem_sort_key(entry: dict[str, str | int]) -> tuple[int, str]:
        target = str(entry["target"])
        home_target = str(Path.home())
        priority = {
            "/": 0,
            home_target: 1,
            "/home": 2,
            "/var": 3,
            "/boot": 4,
            "/boot/efi": 5,
            "/tmp": 6,
        }.get(target, 50)
        return (priority, target)

    @staticmethod
    def _storage_severity(pct: int, inode_pct: int | None) -> str:
        inode_value = inode_pct if inode_pct is not None else 0
        highest = max(pct, inode_value)
        if highest >= 90:
            return "critical"
        if highest >= 75:
            return "watch"
        return "healthy"

    @staticmethod
    def _abbreviate_path(path: str) -> str:
        home = str(Path.home())
        if path.startswith(home):
            return "~" + path[len(home):]
        return path

    def _directory_sizes(self) -> list[tuple[str, int]]:
        sizes: list[tuple[str, int]] = []
        for path in WATCHED_DIRS:
            if not path.exists():
                continue
            result = run_command(["du", "-sx", "-B1", str(path)], timeout=10.0)
            if not result.stdout:
                continue
            parts = result.stdout.split()
            if not parts:
                continue
            size = parse_int(parts[0], default=-1)
            if size < 0:
                continue
            sizes.append((str(path), size))
        sizes.sort(key=lambda item: item[1], reverse=True)
        return sizes

    def _read_diskstats(self) -> dict[str, tuple[int, int]]:
        devices = {path.name for path in Path("/sys/block").iterdir() if path.is_dir()}
        stats: dict[str, tuple[int, int]] = {}
        for raw in read_lines(Path("/proc/diskstats")):
            parts = raw.split()
            if len(parts) < 14:
                continue
            name = parts[2]
            if name not in devices:
                continue
            if name.startswith(("loop", "ram", "zram", "sr")):
                continue
            read_sectors = int(parts[5])
            write_sectors = int(parts[9])
            stats[name] = (read_sectors, write_sectors)
        return stats

    def _disk_rates(self) -> tuple[float, float, list[tuple[str, float]]]:
        now = time.time()
        current = self._read_diskstats()
        if self.disk_prev is None:
            previous = current
            time.sleep(0.15)
            now = time.time()
            current = self._read_diskstats()
            previous_time = now - 0.15
        else:
            previous_time, previous = self.disk_prev
        self.disk_prev = (now, current)
        elapsed = max(now - previous_time, 0.1)
        total_read = 0.0
        total_write = 0.0
        per_device: list[tuple[str, float]] = []
        for name, (read_sectors, write_sectors) in current.items():
            old_read, old_write = previous.get(name, (read_sectors, write_sectors))
            read_rate = max(read_sectors - old_read, 0) * 512 / elapsed
            write_rate = max(write_sectors - old_write, 0) * 512 / elapsed
            total_read += read_rate
            total_write += write_rate
            per_device.append((name, read_rate + write_rate))
        per_device.sort(key=lambda item: item[1], reverse=True)
        return total_read, total_write, per_device[:3]

    def collect_storage(self) -> list[str]:
        lines: list[str] = []
        fs_entries = self._filesystem_usage()
        inode_usage = self._inode_usage()
        dir_sizes = self.cached("dir_sizes", 300.0, self._directory_sizes)
        read_rate, write_rate, busy_devices = self._disk_rates()

        root_entry = next((entry for entry in fs_entries if entry["target"] == "/"), None)
        if root_entry:
            root_used = int(root_entry["used"])
            root_size = int(root_entry["size"])
            root_free = int(root_entry["avail"])
            root_pct = int(root_entry["pct"])
            prefix = "! " if root_pct >= 85 else ""
            lines.append(
                f"{prefix}Root filesystem: {format_bytes(root_used)} used / "
                f"{format_bytes(root_size)} total ({root_pct}%) | {format_bytes(root_free)} free"
            )

        ordered_entries = sorted(fs_entries, key=self._filesystem_sort_key)
        by_target = {str(entry["target"]): entry for entry in ordered_entries}
        display_entries: list[dict[str, str | int]] = []
        for target in (str(Path.home()), "/var", "/boot", "/boot/efi", "/tmp"):
            entry = by_target.get(target)
            if entry is not None:
                display_entries.append(entry)

        for entry in ordered_entries:
            target = str(entry["target"])
            if target == "/" or entry in display_entries:
                continue
            inode_pct = inode_usage.get(target)
            if self._storage_severity(int(entry["pct"]), inode_pct) != "healthy":
                display_entries.append(entry)

        healthy_count = 0
        watch_count = 0
        critical_count = 0
        for entry in fs_entries:
            severity = self._storage_severity(int(entry["pct"]), inode_usage.get(str(entry["target"])))
            if severity == "critical":
                critical_count += 1
            elif severity == "watch":
                watch_count += 1
            else:
                healthy_count += 1

        lines.append(
            f"Filesystems: {healthy_count} healthy | {watch_count} watch | {critical_count} critical"
        )

        lines.append("Key filesystems:")
        for entry in display_entries[:5]:
            target = str(entry["target"])
            inode_pct = inode_usage.get(target)
            free = int(entry["avail"])
            inode_suffix = ""
            if inode_pct is not None and inode_pct >= 75:
                inode_suffix = f" | inodes {inode_pct}%"
            lines.append(
                f"  {target}: {entry['pct']}% used | {format_bytes(free)} free | {entry['fstype']}{inode_suffix}"
            )

        if read_rate < 128 * 1024 and write_rate < 128 * 1024:
            lines.append("Disk IO: idle")
        else:
            lines.append(
                f"Disk IO: read {format_bytes(read_rate)}/s | write {format_bytes(write_rate)}/s"
            )
        active_devices = [(name, rate) for name, rate in busy_devices if rate >= 512 * 1024]
        if active_devices:
            lines.append(
                "Active devices: "
                + ", ".join(f"{name} {format_bytes(rate)}/s" for name, rate in active_devices)
            )

        noisy_dirs = [(path, size) for path, size in dir_sizes if size >= 1024**3]
        if noisy_dirs:
            lines.append(
                "Growth suspects: "
                + ", ".join(
                    f"{self._abbreviate_path(path)} {format_bytes(size)}" for path, size in noisy_dirs[:3]
                )
            )
        else:
            lines.append("Growth suspects: none above 1 GiB in watched paths.")
        return lines

    def _systemd_state(self) -> str:
        result = run_command(["systemctl", "is-system-running"], timeout=3.0)
        if result.stdout:
            return result.stdout.splitlines()[0]
        if result.missing:
            return "systemctl not found"
        if result.stderr:
            return shorten(result.stderr, 120)
        return "unknown"

    def _failed_services(self) -> list[str]:
        result = run_command(
            ["systemctl", "--failed", "--type=service", "--no-legend", "--no-pager"],
            timeout=5.0,
        )
        return line_list(result.stdout)

    def _restart_hints(self) -> list[str]:
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

    def _service_count(self, state: str) -> tuple[int | None, str | None]:
        return self.count_command_lines(
            ["systemctl", "list-unit-files", "--type=service", f"--state={state}", "--no-legend", "--no-pager"],
            timeout=5.0,
        )

    def collect_systemd(self) -> list[str]:
        privileged = self._privileged_section("systemd")
        if privileged:
            lines = []
            snapshot_line = self._privileged_snapshot_line()
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
        state = self._systemd_state()
        failed = self._failed_services()
        enabled_count, enabled_error = self.cached(
            "systemd_enabled_count", 600.0, lambda: self._service_count("enabled")
        )
        disabled_count, disabled_error = self.cached(
            "systemd_disabled_count", 600.0, lambda: self._service_count("disabled")
        )
        restart_hints = self._restart_hints()

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

    def collect_logs(self) -> list[str]:
        privileged = self._privileged_section("logs")
        if privileged:
            lines: list[str] = []
            snapshot_line = self._privileged_snapshot_line()
            if snapshot_line:
                lines.append(snapshot_line)
            lines.append("Journal errors since boot:")
            for item in privileged.get("journal_errors", [])[:5]:
                lines.append(f"  {shorten(str(item), 150)}")
            if not privileged.get("journal_errors"):
                lines.append("  No matching entries.")
            lines.append("Kernel warnings since boot:")
            for item in privileged.get("kernel_warnings", [])[:5]:
                lines.append(f"  {shorten(str(item), 150)}")
            if not privileged.get("kernel_warnings"):
                lines.append("  No matching entries.")
            lines.append("Hardware / driver hints:")
            for item in privileged.get("hardware_warnings", [])[:5]:
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

    def _meminfo(self) -> dict[str, int]:
        info: dict[str, int] = {}
        for raw in read_lines(Path("/proc/meminfo")):
            if ":" not in raw:
                continue
            key, rest = raw.split(":", 1)
            info[key] = parse_int(rest)
        return info

    def _psi(self, path: Path) -> dict[str, dict[str, float]]:
        data: dict[str, dict[str, float]] = {}
        for raw in read_lines(path):
            parts = raw.split()
            if not parts:
                continue
            category = parts[0]
            metrics: dict[str, float] = {}
            for part in parts[1:]:
                if "=" not in part:
                    continue
                key, value = part.split("=", 1)
                try:
                    metrics[key] = float(value)
                except ValueError:
                    continue
            data[category] = metrics
        return data

    def collect_memory(self) -> list[str]:
        info = self._meminfo()
        total = info.get("MemTotal", 0) * 1024
        available = info.get("MemAvailable", 0) * 1024
        free = info.get("MemFree", 0) * 1024
        buffers = info.get("Buffers", 0) * 1024
        cached = (info.get("Cached", 0) + info.get("SReclaimable", 0)) * 1024
        used = max(total - available, 0)
        swap_total = info.get("SwapTotal", 0) * 1024
        swap_free = info.get("SwapFree", 0) * 1024
        swap_used = max(swap_total - swap_free, 0)
        psi = self._psi(Path("/proc/pressure/memory"))
        oom_events = run_command(
            [
                "journalctl",
                "-b",
                "--grep=Out of memory|Killed process",
                "-n",
                "8",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )

        lines = [
            f"RAM: {format_bytes(used)} used / {format_bytes(total)} total ({format_percent(used, total)})",
            f"Available: {format_bytes(available)} | Free: {format_bytes(free)} | Buffers/cache: {format_bytes(buffers + cached)}",
            f"Swap: {format_bytes(swap_used)} used / {format_bytes(swap_total)} total ({format_percent(swap_used, swap_total)})",
        ]

        some = psi.get("some", {})
        full = psi.get("full", {})
        if some or full:
            lines.append(
                "PSI memory: "
                f"some {some.get('avg10', 0.0):.2f}/{some.get('avg60', 0.0):.2f}/{some.get('avg300', 0.0):.2f} "
                f"| full {full.get('avg10', 0.0):.2f}/{full.get('avg60', 0.0):.2f}/{full.get('avg300', 0.0):.2f}"
            )
        else:
            lines.append("PSI memory: unavailable.")

        lines.append("OOM events:")
        for item in parse_journal_lines(oom_events, limit=4):
            lines.append(f"  {item}")
        return lines

    def _read_cpu_stat(self) -> dict[str, int]:
        raw = read_text(Path("/proc/stat"))
        line = raw.splitlines()
        if not line:
            return {}
        parts = line[0].split()
        fields = [int(value) for value in parts[1:9]]
        return {
            "user": fields[0] + fields[1],
            "system": fields[2] + fields[5] + fields[6],
            "idle": fields[3],
            "iowait": fields[4],
            "total": sum(fields),
        }

    def _cpu_percentages(self) -> tuple[float, float, float]:
        now = time.time()
        current = self._read_cpu_stat()
        if not current:
            return 0.0, 0.0, 0.0
        if self.cpu_prev is None:
            previous = current
            time.sleep(0.15)
            now = time.time()
            current = self._read_cpu_stat()
            previous_time = now - 0.15
        else:
            previous_time, previous = self.cpu_prev
        self.cpu_prev = (now, current)
        _ = max(now - previous_time, 0.1)
        total_delta = max(current["total"] - previous.get("total", current["total"]), 1)
        user_pct = (current["user"] - previous.get("user", current["user"])) * 100.0 / total_delta
        system_pct = (current["system"] - previous.get("system", current["system"])) * 100.0 / total_delta
        iowait_pct = (current["iowait"] - previous.get("iowait", current["iowait"])) * 100.0 / total_delta
        return user_pct, system_pct, iowait_pct

    def _cpu_frequency(self) -> str:
        freqs = []
        max_freqs = []
        for cpu_path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*"):
            current = cpu_path / "cpufreq" / "scaling_cur_freq"
            maximum = cpu_path / "cpufreq" / "cpuinfo_max_freq"
            if current.exists():
                freqs.append(parse_int(read_text(current)))
            if maximum.exists():
                max_freqs.append(parse_int(read_text(maximum)))
        if freqs:
            avg = sum(freqs) / len(freqs)
            if max_freqs and max(max_freqs) > 0:
                return f"{avg / 1000:.0f} MHz avg ({avg / max(max_freqs) * 100:.0f}% of max)"
            return f"{avg / 1000:.0f} MHz avg"
        lscpu = run_command(["lscpu"], timeout=3.0)
        for raw in lscpu.stdout.splitlines():
            if raw.startswith("CPU MHz:"):
                return raw.split(":", 1)[1].strip() + " MHz"
        return "unavailable"

    def _top_processes(self) -> list[str]:
        result = run_command(
            ["ps", "-eo", "pid,comm,%cpu,%mem", "--sort=-%cpu", "--no-headers"],
            timeout=3.0,
        )
        return line_list(result.stdout, limit=5)

    def collect_cpu(self) -> list[str]:
        loadavg = read_text(Path("/proc/loadavg")).split()
        user_pct, system_pct, iowait_pct = self._cpu_percentages()
        top_processes = self._top_processes()
        throttle_hints = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={THROTTLE_LOG_PATTERN}",
                "-n",
                "6",
                "--no-pager",
                "-o",
                "short-monotonic",
            ],
            timeout=4.0,
        )

        lines = [
            f"Load average: {' '.join(loadavg[:3]) if loadavg else 'unavailable'}",
            f"CPU usage: user {user_pct:.1f}% | system {system_pct:.1f}% | iowait {iowait_pct:.1f}%",
            f"CPU frequency: {self._cpu_frequency()}",
            "Top CPU processes:",
        ]
        for item in top_processes[:5]:
            lines.append(f"  {item}")

        lines.append("Throttle hints:")
        for item in parse_journal_lines(throttle_hints, limit=4):
            lines.append(f"  {item}")
        return lines

    def _thermal_zones(self) -> list[str]:
        lines: list[str] = []
        for temp_path in sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp")):
            value = parse_int(read_text(temp_path))
            if value <= 0:
                continue
            type_path = temp_path.parent / "type"
            zone_type = read_text(type_path).strip() or temp_path.parent.name
            lines.append(f"{zone_type} {value / 1000:.1f} C")
        return lines

    def _fans(self) -> list[str]:
        fans: list[str] = []
        for fan_path in sorted(Path("/sys/class/hwmon").glob("hwmon*/fan*_input")):
            rpm = parse_int(read_text(fan_path))
            if rpm <= 0:
                continue
            name_path = fan_path.parent / "name"
            hwmon_name = read_text(name_path).strip() or fan_path.parent.name
            fans.append(f"{hwmon_name}/{fan_path.stem} {rpm} RPM")
        return fans

    def _power_state(self) -> list[str]:
        states: list[str] = []
        for supply in sorted(Path("/sys/class/power_supply").glob("*")):
            supply_type = read_text(supply / "type").strip()
            if not supply_type:
                continue
            if supply_type == "Mains":
                online = read_text(supply / "online").strip()
                states.append(f"{supply.name} {'online' if online == '1' else 'offline'}")
            elif supply_type == "Battery":
                status = read_text(supply / "status").strip() or "unknown"
                capacity = read_text(supply / "capacity").strip() or "n/a"
                states.append(f"{supply.name} {status} {capacity}%")
        return states

    def _gpu_telemetry(self) -> list[str]:
        result = run_command(
            [
                "nvidia-smi",
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,pstate",
                "--format=csv,noheader,nounits",
            ],
            timeout=4.0,
        )
        rows = line_list(result.stdout)
        telemetry: list[str] = []
        for row in rows:
            parts = [part.strip() for part in row.split(",")]
            if len(parts) < 7:
                continue
            name, util, mem_used, mem_total, temp, power, pstate = parts[:7]
            telemetry.append(
                f"{name}: {util}% util | {mem_used}/{mem_total} MiB | {temp} C | {power} W | {pstate}"
            )
        if telemetry:
            return telemetry
        if result.missing:
            return ["nvidia-smi not found."]
        if result.stderr:
            return [shorten(single_line(result.stderr), 140)]
        return ["No GPU telemetry available."]

    def collect_thermal(self) -> list[str]:
        lines = [
            "Thermal zones:",
        ]
        zones = self._thermal_zones()
        if zones:
            for item in zones[:6]:
                lines.append(f"  {item}")
        else:
            lines.append("  No readable thermal zones.")

        fans = self._fans()
        lines.append("Fan speeds:")
        if fans:
            for item in fans[:6]:
                lines.append(f"  {item}")
        else:
            lines.append("  No readable fan sensors.")

        power_states = self._power_state()
        lines.append("Power supplies:")
        if power_states:
            for item in power_states[:4]:
                lines.append(f"  {item}")
        else:
            lines.append("  No battery or AC state exposed.")

        lines.append("GPU thermal / power:")
        for item in self._gpu_telemetry()[:4]:
            lines.append(f"  {item}")
        return lines

    def _smart_devices(self) -> list[str]:
        result = run_command(["smartctl", "--scan"], timeout=4.0)
        devices = []
        for raw in line_list(result.stdout):
            parts = raw.split()
            if parts:
                devices.append(parts[0])
        return devices[:4]

    def _smart_summary(self) -> list[str]:
        if shutil.which("smartctl") is None:
            return ["smartctl not found."]
        summaries: list[str] = []
        for device in self.cached("smart_devices", 900.0, self._smart_devices):
            result = run_command(["smartctl", "-H", "-A", device], timeout=8.0)
            if result.stderr and not result.stdout:
                summaries.append(f"{device}: {shorten(result.stderr, 120)}")
                continue
            health = "unknown"
            temp = None
            wear = None
            media_errors = None
            for raw in result.stdout.splitlines():
                lower = raw.lower()
                if "overall-health" in lower or "health status" in lower or "smart health status" in lower:
                    health = raw.split(":", 1)[-1].strip()
                elif raw.strip().startswith("Temperature:"):
                    temp = raw.split(":", 1)[1].strip()
                elif "temperature_celsius" in lower or "temperature sensor" in lower:
                    fields = raw.split()
                    if fields and fields[-1].isdigit():
                        temp = fields[-1] + " C"
                elif "percentage used" in lower:
                    wear = raw.split(":", 1)[-1].strip()
                elif "media and data integrity errors" in lower:
                    media_errors = raw.split(":", 1)[-1].strip()
            summary = f"{device}: {health}"
            if temp:
                summary += f" | {temp}"
            if wear:
                summary += f" | wear {wear}"
            if media_errors:
                summary += f" | media errors {media_errors}"
            summaries.append(summary)
        if not summaries:
            summaries.append("No SMART devices detected or readable without extra permissions.")
        return summaries

    def _gpu_processes(self) -> list[str]:
        result = run_command(
            [
                "nvidia-smi",
                "--query-compute-apps=pid,process_name,used_memory",
                "--format=csv,noheader,nounits",
            ],
            timeout=4.0,
        )
        rows = []
        for raw in line_list(result.stdout):
            parts = [part.strip() for part in raw.split(",")]
            if len(parts) >= 3:
                rows.append(f"pid {parts[0]} {parts[1]} {parts[2]} MiB")
        return rows

    def _device_counts(self) -> list[str]:
        counts = []
        lsusb = run_command(["lsusb"], timeout=3.0)
        if lsusb.stdout:
            usb_lines = line_list(lsusb.stdout)
            counts.append(f"USB devices: {len(usb_lines)}")
        lspci = run_command(["lspci"], timeout=3.0)
        if lspci.stdout:
            pci_lines = line_list(lspci.stdout)
            counts.append(f"PCI devices: {len(pci_lines)}")
        return counts

    def collect_hardware(self) -> list[str]:
        privileged = self._privileged_section("hardware")
        if privileged:
            lines = []
            snapshot_line = self._privileged_snapshot_line()
            if snapshot_line:
                lines.append(snapshot_line)
            lines.append("SMART summary:")
            smart = privileged.get("smart_summary", [])
            if isinstance(smart, list) and smart:
                for item in smart[:4]:
                    lines.append(f"  {item}")
            else:
                lines.append("  No SMART devices detected or readable without extra permissions.")
            lines.append("GPU status:")
            gpu_status = privileged.get("gpu_status", [])
            if isinstance(gpu_status, list) and gpu_status:
                for item in gpu_status[:3]:
                    lines.append(f"  {item}")
            else:
                lines.append("  No GPU telemetry available.")
            gpu_processes = privileged.get("gpu_processes", [])
            if isinstance(gpu_processes, list) and gpu_processes:
                lines.append("GPU processes:")
                for item in gpu_processes[:4]:
                    lines.append(f"  {item}")
            device_counts = privileged.get("device_counts", [])
            if isinstance(device_counts, list) and device_counts:
                lines.append("Bus inventory:")
                for item in device_counts[:4]:
                    lines.append(f"  {item}")
            return lines

        lines = ["SMART summary:"]
        for item in self.cached("smart_summary", 300.0, self._smart_summary)[:4]:
            lines.append(f"  {item}")

        lines.append("GPU status:")
        for item in self._gpu_telemetry()[:3]:
            lines.append(f"  {item}")

        gpu_processes = self._gpu_processes()
        if gpu_processes:
            lines.append("GPU processes:")
            for item in gpu_processes[:4]:
                lines.append(f"  {item}")

        device_counts = self.cached("device_counts", 120.0, self._device_counts)
        if device_counts:
            lines.append("Bus inventory:")
            for item in device_counts[:4]:
                lines.append(f"  {item}")
        return lines

    def collect_fs_integrity(self) -> list[str]:
        privileged = self._privileged_section("fs_integrity")
        if privileged:
            ro_mounts = privileged.get("ro_mounts", [])
            hints = privileged.get("hints", [])
            lines = []
            snapshot_line = self._privileged_snapshot_line()
            if snapshot_line:
                lines.append(snapshot_line)
            lines.append("Read-only mounts: " + (", ".join(ro_mounts) if isinstance(ro_mounts, list) and ro_mounts else "none"))
            lines.append("Filesystem integrity hints:")
            if isinstance(hints, list) and hints:
                for item in hints[:6]:
                    lines.append(f"  {item}")
            else:
                lines.append("  No matching entries.")
            return lines

        ro_mounts = detect_ro_mounts()
        journal_fs = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={FS_LOG_PATTERN}",
                "-n",
                "10",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        lines = [
            "Read-only mounts: " + (", ".join(ro_mounts) if ro_mounts else "none"),
            "Filesystem integrity hints:",
        ]
        for item in parse_journal_lines(journal_fs, limit=6):
            lines.append(f"  {item}")
        return lines

    def _drm_connectors(self) -> list[str]:
        connectors = []
        for status_path in sorted(Path("/sys/class/drm").glob("card*-*/status")):
            connector = status_path.parent.name
            status = read_text(status_path).strip() or "unknown"
            connectors.append(f"{connector} {status}")
        return connectors

    def _video_nodes(self) -> list[str]:
        nodes = sorted(str(path) for path in Path("/dev").glob("video*"))
        media_nodes = sorted(str(path) for path in Path("/dev").glob("media*"))
        combined = []
        if nodes:
            combined.append("Video nodes: " + ", ".join(nodes[:8]))
        else:
            combined.append("Video nodes: none")
        if media_nodes:
            combined.append("Media nodes: " + ", ".join(media_nodes[:6]))
        return combined

    def _v4l2_devices(self) -> list[str]:
        result = run_command(["v4l2-ctl", "--list-devices"], timeout=4.0)
        if result.stdout:
            devices = []
            current = None
            for raw in result.stdout.splitlines():
                if raw and not raw.startswith("\t"):
                    current = raw.strip().rstrip(":")
                    devices.append(current)
            return devices[:5]
        if result.missing:
            return ["v4l2-ctl not found."]
        if result.stderr:
            return [shorten(single_line(result.stderr), 140)]
        return ["No V4L2 devices listed."]

    def _encoder_availability(self) -> list[str]:
        result = run_command(["ffmpeg", "-hide_banner", "-encoders"], timeout=6.0)
        encoders = []
        for raw in result.stdout.splitlines():
            lower = raw.lower()
            if any(keyword in lower for keyword in ENCODER_KEYWORDS):
                encoders.append(" ".join(raw.split()))
        if encoders:
            return encoders[:8]
        if result.missing:
            return ["ffmpeg not found."]
        return ["No known hardware encoders detected in ffmpeg output."]

    def collect_device_specific(self) -> list[str]:
        lines = ["DRM connector status:"]
        connectors = self._drm_connectors()
        if connectors:
            for item in connectors[:6]:
                lines.append(f"  {item}")
        else:
            lines.append("  No DRM connectors exposed.")

        for item in self._video_nodes():
            lines.append(item)

        lines.append("V4L2 devices:")
        for item in self._v4l2_devices()[:5]:
            lines.append(f"  {item}")

        lines.append("Encoder availability:")
        for item in self.cached("encoder_availability", 600.0, self._encoder_availability)[:5]:
            lines.append(f"  {item}")

        related_logs = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={DEVICE_LOG_PATTERN}",
                "-n",
                "8",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        lines.append("Recent device-specific log hints:")
        for item in parse_journal_lines(related_logs, limit=4):
            lines.append(f"  {item}")
        return lines

    def _interface_summary(self) -> list[str]:
        result = run_command(["ip", "-brief", "address"], timeout=3.0)
        if result.stdout:
            return line_list(result.stdout, limit=8)
        if result.missing:
            return ["ip not found."]
        return [shorten(single_line(result.stderr), 140) or "No interfaces available."]

    def _default_route(self) -> str:
        result = run_command(["ip", "route", "show", "default"], timeout=3.0)
        if result.stdout:
            return result.stdout.splitlines()[0]
        if result.missing:
            return "ip not found"
        if result.stderr:
            return shorten(single_line(result.stderr), 140)
        return "no default route"

    def _dns_servers(self) -> str:
        resolvectl = run_command(["resolvectl", "dns"], timeout=3.0)
        if resolvectl.stdout:
            servers = []
            for raw in resolvectl.stdout.splitlines():
                parts = raw.split(":", 1)
                if len(parts) == 2:
                    servers.append(parts[1].strip())
            if servers:
                return " | ".join(servers[:4])
        nameservers = []
        for raw in read_lines(Path("/etc/resolv.conf")):
            if raw.startswith("nameserver "):
                nameservers.append(raw.split(None, 1)[1])
        if nameservers:
            return ", ".join(nameservers)
        return "no nameservers found"

    def _dns_check(self) -> str:
        result = run_command(["getent", "ahosts", "archlinux.org"], timeout=3.0)
        if result.stdout:
            return result.stdout.splitlines()[0].split()[0]
        if result.stderr:
            return shorten(single_line(result.stderr), 120)
        return "resolution failed"

    def _socket_counts(self) -> tuple[int | None, int | None]:
        established = run_command(["ss", "-tun", "state", "established", "-H"], timeout=3.0)
        listening = run_command(["ss", "-ltnu", "-H"], timeout=3.0)
        established_count = None if established.stderr and not established.stdout else len(line_list(established.stdout))
        listening_count = None if listening.stderr and not listening.stdout else len(line_list(listening.stdout))
        return established_count, listening_count

    def collect_network(self) -> list[str]:
        privileged = self._privileged_section("network")
        if privileged:
            snapshot_line = self._privileged_snapshot_line()
            interfaces = privileged.get("interfaces", [])
            default_route = str(privileged.get("default_route", "no default route"))
            dns_servers = str(privileged.get("dns_servers", "no nameservers found"))
            dns_check = str(privileged.get("dns_check", "resolution failed"))
            connections = privileged.get("connections", {})
            established = None
            listening = None
            if isinstance(connections, dict):
                established = connections.get("established")
                listening = connections.get("listening")
            lines = []
            if snapshot_line:
                lines.append(snapshot_line)
            lines.append("Interfaces:")
            if isinstance(interfaces, list) and interfaces:
                for item in interfaces[:6]:
                    lines.append(f"  {item}")
            else:
                lines.append("  No interfaces available.")
            lines.append(f"Default route: {default_route}")
            lines.append(f"DNS servers: {dns_servers}")
            lines.append(f"DNS lookup: archlinux.org -> {dns_check}")
            if established is None or listening is None:
                lines.append("Connections: unavailable (socket inspection failed)")
            else:
                lines.append(f"Connections: {established} established | {listening} listening sockets")
            return lines

        interfaces = self._interface_summary()
        default_route = self._default_route()
        dns_servers = self._dns_servers()
        dns_check = self.cached("dns_check", 60.0, self._dns_check)
        established, listening = self._socket_counts()

        lines = ["Interfaces:"]
        for item in interfaces[:6]:
            lines.append(f"  {item}")
        lines.append(f"Default route: {default_route}")
        lines.append(f"DNS servers: {dns_servers}")
        lines.append(f"DNS lookup: archlinux.org -> {dns_check}")
        if established is None or listening is None:
            lines.append("Connections: unavailable (socket inspection failed)")
        else:
            lines.append(f"Connections: {established} established | {listening} listening sockets")
        return lines

    def _listening_sockets(self) -> list[str]:
        result = run_command(["ss", "-ltnupH"], timeout=4.0)
        sockets = []
        for raw in line_list(result.stdout):
            parts = raw.split()
            if len(parts) < 5:
                continue
            local = parts[4]
            process = parts[-1] if parts else ""
            sockets.append(f"{local} {process}")
        if sockets:
            return sockets[:8]
        if result.missing:
            return ["ss not found."]
        if result.stderr:
            return [shorten(first_nonempty_line(result.stderr), 140)]
        return ["No listening sockets."]

    def _failed_logins(self) -> list[str]:
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

    def _sudo_usage(self) -> list[str]:
        result = run_command(
            ["journalctl", "-b", "SYSLOG_IDENTIFIER=sudo", "-n", "5", "--no-pager", "-o", "short-iso"],
            timeout=5.0,
        )
        return journal_line_list(result.stdout, limit=5)

    def collect_security(self) -> list[str]:
        privileged = self._privileged_section("security")
        if privileged:
            snapshot_line = self._privileged_snapshot_line()
            listeners = privileged.get("listeners", [])
            failed_logins = privileged.get("failed_logins", [])
            sudo_usage = privileged.get("sudo_usage", [])
            lines = []
            if snapshot_line:
                lines.append(snapshot_line)
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

        listeners = self._listening_sockets()
        failed_logins = self._failed_logins()
        sudo_usage = self._sudo_usage()

        lines = ["Listening sockets:"]
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

    def _path_size(self, path: Path, timeout: float = 6.0) -> int | None:
        if not path.exists():
            return None
        result = run_command(["du", "-sx", "-B1", str(path)], timeout=timeout)
        if not result.stdout:
            return None
        return parse_int(result.stdout.split()[0], default=-1)

    def _journal_disk_usage(self) -> str:
        result = run_command(["journalctl", "--disk-usage"], timeout=3.0)
        if result.stdout:
            return result.stdout.replace("Archived and active journals take up ", "").strip(".")
        if result.missing:
            return "journalctl not found"
        if result.stderr:
            return shorten(single_line(result.stderr), 120)
        return "unavailable"

    def collect_hygiene(self) -> list[str]:
        orphaned, orphan_error = self.cached("orphans_hygiene", 900.0, self._orphan_packages)
        pacman_cache = self.cached("pacman_cache_size", 300.0, lambda: self._path_size(Path("/var/cache/pacman/pkg")))
        log_dir = self.cached("log_dir_size", 300.0, lambda: self._path_size(Path("/var/log")))
        tmp_dir = self.cached("tmp_dir_size", 300.0, lambda: self._path_size(Path("/tmp")))
        var_tmp_dir = self.cached("var_tmp_dir_size", 300.0, lambda: self._path_size(Path("/var/tmp")))
        journal_usage = self.cached("journal_disk_usage", 300.0, self._journal_disk_usage)

        lines = [
            f"Orphans: {len(orphaned)}" + (f" ({orphan_error})" if orphan_error else ""),
        ]
        if orphaned:
            lines.append(f"  {', '.join(orphaned[:10])}")
        lines.append(
            "Pacman cache: " + (format_bytes(pacman_cache) if isinstance(pacman_cache, int) and pacman_cache >= 0 else "unavailable")
        )
        lines.append(
            "Log directory: " + (format_bytes(log_dir) if isinstance(log_dir, int) and log_dir >= 0 else "unavailable")
        )
        lines.append("Journal storage: " + str(journal_usage))
        lines.append(
            "Temp usage: "
            + ", ".join(
                filter(
                    None,
                    [
                        f"/tmp {format_bytes(tmp_dir)}" if isinstance(tmp_dir, int) and tmp_dir >= 0 else "",
                        f"/var/tmp {format_bytes(var_tmp_dir)}"
                        if isinstance(var_tmp_dir, int) and var_tmp_dir >= 0
                        else "",
                    ],
                )
            )
        )
        if lines[-1] == "Temp usage: ":
            lines[-1] = "Temp usage: unavailable"
        return lines

    def _boot_time(self) -> str:
        result = run_command(["systemd-analyze"], timeout=4.0)
        if result.stdout:
            return result.stdout.splitlines()[0]
        if result.missing:
            return "systemd-analyze not found"
        if result.stderr:
            return shorten(result.stderr, 140)
        return "unavailable"

    def _boot_blame(self) -> list[str]:
        result = run_command(["systemd-analyze", "blame", "--no-pager"], timeout=5.0)
        return line_list(result.stdout, limit=8)

    def _uptime_summary(self) -> str:
        raw = read_text(Path("/proc/uptime")).strip().split()
        if not raw:
            return "Uptime: unavailable"
        try:
            uptime_seconds = float(raw[0])
        except ValueError:
            return "Uptime: unavailable"
        booted_at = datetime.fromtimestamp(time.time() - uptime_seconds).strftime("%Y-%m-%d %H:%M")
        return f"Uptime: {format_duration_compact(uptime_seconds)} | booted {booted_at}"

    def collect_boot(self) -> list[str]:
        lines = [
            self._uptime_summary(),
            f"Boot time: {self.cached('boot_time', 300.0, self._boot_time)}",
            "Slowest boot services:",
        ]
        blame = self.cached("boot_blame", 300.0, self._boot_blame)
        for item in blame[:6]:
            lines.append(f"  {item}")
        if not blame:
            lines.append("  unavailable")
        return lines


class DashboardModel:
    def __init__(self) -> None:
        self.backend = MonitorBackend()
        self.collectors = self._build_collectors()
        self.states = {
            collector.key: SectionState(title=collector.title) for collector in self.collectors
        }
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.force_refresh = threading.Event()

    def _build_collectors(self) -> list[Collector]:
        backend = self.backend
        return [
            Collector("top_problems", "tier1", "Top Problems", 15, backend.collect_top_problems),
            Collector("diff_snapshot", "tier1", "Diff Snapshot", 15, backend.collect_diff_snapshot),
            Collector("packages", "tier1", "Kernel / Firmware / NVIDIA", 5, backend.collect_packages),
            Collector("storage", "tier1", "Storage / Capacity", 20, backend.collect_storage),
            Collector("systemd", "tier1", "Systemd / Service Health", 20, backend.collect_systemd),
            Collector("logs", "tier1", "Logs / Errors", 20, backend.collect_logs),
            Collector("memory", "tier2", "Memory / Pressure", 5, backend.collect_memory),
            Collector("cpu", "tier2", "CPU / System Load", 4, backend.collect_cpu),
            Collector("thermal", "tier2", "Thermal / Power", 6, backend.collect_thermal),
            Collector("hardware", "tier2", "Hardware Health", 30, backend.collect_hardware),
            Collector("fs_integrity", "tier2", "Filesystem Integrity", 30, backend.collect_fs_integrity),
            Collector("device_specific", "tier2", "Device-Specific Signals", 20, backend.collect_device_specific),
            Collector("network", "tier3", "Network State", 15, backend.collect_network),
            Collector("security", "tier3", "Security / Exposure Surface", 30, backend.collect_security),
            Collector("hygiene", "tier3", "System Hygiene", 300, backend.collect_hygiene),
            Collector("boot", "tier3", "Boot / Regression Signals", 300, backend.collect_boot),
        ]

    def start_background_tasks(self) -> None:
        self.backend.start_package_worker()

    def refresh_sync(self, tab: str | None = None) -> None:
        for collector in self.collectors:
            if tab is not None and tab != "all" and collector.tab != tab:
                continue
            self._refresh_collector(collector)

    def _refresh_collector(self, collector: Collector) -> None:
        started = time.time()
        with self.lock:
            state = self.states[collector.key]
            state.loading = True
        error = None
        try:
            lines = collector.func()
            if not lines:
                lines = ["No data returned."]
        except Exception as exc:  # pragma: no cover - defensive path
            error = str(exc)
            lines = [f"Collector failed: {exc}"]
        finished = time.time()
        with self.lock:
            state = self.states[collector.key]
            state.lines = lines
            state.loading = False
            state.last_updated = finished
            state.duration = finished - started
            state.last_error = error

    def refresh_loop(self) -> None:
        while not self.stop_event.is_set():
            now = time.time()
            force = self.force_refresh.is_set()
            if force:
                self.force_refresh.clear()
            due: list[Collector] = []
            with self.lock:
                for collector in self.collectors:
                    state = self.states[collector.key]
                    if force or state.last_updated == 0.0 or now - state.last_updated >= collector.interval:
                        due.append(collector)
            if not due:
                self.stop_event.wait(0.25)
                continue
            for collector in due:
                if self.stop_event.is_set():
                    break
                self._refresh_collector(collector)

    def request_refresh(self) -> None:
        self.backend.request_package_refresh()
        self.force_refresh.set()

    def snapshot(self, tab: str) -> list[tuple[Collector, SectionState]]:
        with self.lock:
            selected = [
                (collector, self.states[collector.key])
                for collector in self.collectors
                if collector.tab == tab
            ]
            return [
                (
                    collector,
                    SectionState(
                        title=state.title,
                        lines=list(state.lines),
                        loading=state.loading,
                        last_updated=state.last_updated,
                        duration=state.duration,
                        last_error=state.last_error,
                    ),
                )
                for collector, state in selected
            ]

    def overall_status(self) -> str:
        with self.lock:
            loading = sum(1 for state in self.states.values() if state.loading)
            updated = [state.last_updated for state in self.states.values() if state.last_updated]
        last = datetime.fromtimestamp(max(updated)).strftime("%H:%M:%S") if updated else "never"
        return f"loading {loading} | last update {last}"

    def stop(self) -> None:
        self.stop_event.set()
        self.backend.stop_background_tasks()


class DashboardUI:
    def __init__(self, model: DashboardModel, initial_tab: str = "tier1") -> None:
        self.model = model
        self.active_tab_index = max(TAB_ORDER.index(initial_tab), 0)
        self.scroll_offsets = {tab: 0 for tab in TAB_ORDER}

    @property
    def active_tab(self) -> str:
        return TAB_ORDER[self.active_tab_index]

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
                self.active_tab_index = (self.active_tab_index + 1) % len(TAB_ORDER)
            elif key in (curses.KEY_LEFT, ord("h")):
                self.active_tab_index = (self.active_tab_index - 1) % len(TAB_ORDER)
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
            f"{self.model.overall_status()} | {TAB_TITLES[self.active_tab]} "
            f"| scroll {offset}/{max_offset}"
        )
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))
        stdscr.refresh()

    def _draw_tabs(self, stdscr: curses.window, width: int) -> None:
        col = 0
        for index, tab in enumerate(TAB_ORDER):
            label = f" {TAB_TITLES[tab]} "
            attr = self._tab_attr(tab, index == self.active_tab_index)
            self._safe_addstr(stdscr, 0, col, label[: max(width - col, 0)], attr)
            col += len(label) + 1

    def _draw_help(self, stdscr: curses.window, width: int) -> None:
        help_text = "Left/Right switch tabs | Up/Down scroll | r refresh | q quit | green ok | yellow watch | red problem"
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
        }
        return palette.get(tab, curses.color_pair(1)) | curses.A_BOLD

    def _line_attr(self, line: str, section: str) -> int:
        stripped = line.strip()
        lowered = stripped.lower()
        if line.startswith("[") and "]" in line:
            return curses.color_pair(2) | curses.A_BOLD
        if not stripped:
            return curses.A_NORMAL
        if stripped.startswith("Privileged snapshot:"):
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
        if stripped.startswith("Uptime:"):
            return True
        if lowered.endswith(" current"):
            return True
        if "none configured" in lowered:
            return True
        if stripped == "No sudo entries in current boot journal.":
            return True
        if stripped.startswith("System state:") and "running" in lowered:
            return True
        if stripped.startswith("Official repo updates:") and "0 pending" in lowered:
            return True
        if stripped.startswith("AUR updates:") and "0 pending" in lowered:
            return True
        if stripped.startswith("Pending updates:") and parse_int(stripped) == 0:
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
    tabs = TAB_ORDER if tab == "all" else (tab,)
    for name in tabs:
        print(f"=== {TAB_TITLES[name]} ===")
        for _collector, state in model.snapshot(name):
            print(f"[{state.title}]")
            for line in state.lines:
                print(f"  {line}")
            print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Arch/Linux monitoring TUI with tiered tabs for system drift, health, and regressions."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Collect and print a one-shot snapshot instead of launching the TUI.",
    )
    parser.add_argument(
        "--tab",
        choices=[*TAB_ORDER, "all"],
        default="tier1",
        help="Initial tab for the TUI or the tab to print in --once mode.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    model = DashboardModel()
    if args.once:
        model.refresh_sync(tab=args.tab)
        print_once(model, args.tab)
        return 0

    model.start_background_tasks()
    worker = threading.Thread(target=model.refresh_loop, daemon=True)
    worker.start()
    try:
        DashboardUI(model, initial_tab=args.tab if args.tab in TAB_ORDER else "tier1").run()
    finally:
        model.stop()
        worker.join(timeout=1.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
