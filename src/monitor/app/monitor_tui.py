#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Sequence

from monitor.shared.command import CommandResult, run_command
from monitor.shared.constants import (
    DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE,
    DEFAULT_PRIVILEGED_SNAPSHOT_PATH,
    FS_LOG_PATTERN,
    HARDWARE_LOG_PATTERN,
    PRIVILEGED_SNAPSHOT_VERSION,
    PSEUDO_FILESYSTEMS,
    WIFI_LOG_PATTERN,
)
from monitor.shared.formatting import (
    first_nonempty_line,
    format_bytes,
    format_duration_compact,
    format_eta,
    format_percent,
    is_loopback_endpoint,
    parse_size_bytes,
    single_line,
    summarize_list,
)
from monitor.shared.parsing_bluetooth import (
    parse_bluetoothctl_devices,
    parse_bluetoothctl_info,
    parse_bluetoothctl_show,
)
from monitor.shared.parsing_journal import detect_ro_mounts, journal_line_list, parse_journal_lines
from monitor.shared.parsing_network import (
    parse_iw_channel_details,
    parse_iw_link_output,
    parse_iw_station_dump,
    parse_proc_net_wireless_text,
    parse_rfkill_output,
)
from monitor.shared.paths import diff_snapshot_state_path, legacy_repo_diff_snapshot_path
from monitor.shared.text import line_list, parse_float, parse_int, read_lines, read_text, shorten
from monitor.collectors.package_monitor import PackageMonitor, PackageRefreshState, PackageUpdateRow
from monitor.collectors.resources import (
    CpuCollector,
    FilesystemIntegrityCollector,
    HardwareCollector,
    MemoryCollector,
    ThermalCollector,
)
from monitor.collectors.storage import StorageCollector
from monitor.collectors.logs import LogsCollector
from monitor.collectors.systemd_health import SystemdHealthCollector
from monitor.snapshot.diff_snapshot import DiffSnapshotService
from monitor.snapshot.privileged import PrivilegedSnapshotService


BASE_TAB_ORDER = ("tier1", "tier2", "tier3", "packages", "aur")
BASE_TAB_TITLES = {
    "tier1": "Tier 1",
    "tier2": "Tier 2",
    "tier3": "Tier 3",
    "packages": "Packages",
    "aur": "AUR",
}
DIFF_SNAPSHOT_INTERVAL = 120
DEFAULT_PRIVILEGED_SNAPSHOT = str(DEFAULT_PRIVILEGED_SNAPSHOT_PATH)
PRIVILEGED_REFRESH_SCRIPT = "./refresh_monitor_privileged.sh"
WATCHED_DIRS = (
    Path("/var/log"),
    Path("/var/cache"),
    Path("/var/tmp"),
    Path("/tmp"),
    Path("/var/lib/docker"),
    Path("/var/lib/systemd/coredump"),
    Path.home() / ".cache",
)
CONFIG_DRIFT_SUFFIXES = (
    ".pacnew",
    ".pacsave",
    ".pacorig",
    ".dpkg-dist",
    ".dpkg-old",
    ".ucf-dist",
    ".ucf-old",
)
CRON_FILES = (
    Path("/etc/crontab"),
    Path("/etc/anacrontab"),
)
CRON_DIRS = (
    Path("/etc/cron.d"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
)
CRON_SPOOL_DIRS = (
    Path("/var/spool/cron"),
    Path("/var/spool/cron/crontabs"),
)
CONTAINER_DATA_DIRS = (
    Path("/var/lib/docker"),
    Path("/var/lib/containers/storage"),
    Path.home() / ".local/share/containers/storage",
)
VM_IMAGE_DIRS = (
    Path("/var/lib/libvirt/images"),
    Path.home() / ".local/share/libvirt/images",
    Path.home() / "VirtualBox VMs",
)
VM_IMAGE_SUFFIXES = (".qcow2", ".img", ".vdi", ".vmdk", ".vhd", ".vhdx")
ENCODER_KEYWORDS = ("nvenc", "vaapi", "v4l2m2m", "qsv", "amf", "rkmpp")
DEVICE_LOG_PATTERN = r"HDMI|EDID|drm|v4l2|CSI|camera|encoder|nvenc|mpp|video"
CAPTURE_LOG_PATTERN = r"AVMatrix|HwsCapture|uvcvideo|videodev|v4l2|capture"
THROTTLE_LOG_PATTERN = r"throttl|thermal"
BLUETOOTH_LOG_PATTERN = r"bluetooth|BlueZ|btusb|btintel|btmtk|hci\d+"
CAPTURE_STACK_MODULES = (
    "HwsCapture",
    "uvcvideo",
    "videodev",
    "videobuf2_v4l2",
    "videobuf2_common",
    "videobuf2_dma_contig",
)


def read_os_release() -> dict[str, str]:
    info: dict[str, str] = {}
    for raw in read_lines(Path("/etc/os-release")):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        info[key] = value
    return info

class MonitorBackend:
    def __init__(self) -> None:
        self.cache: dict[str, tuple[float, object]] = {}
        self.cpu_prev: tuple[float, dict[str, int]] | None = None
        self.disk_prev: tuple[float, dict[str, tuple[int, int]]] | None = None
        self.os_release = read_os_release()
        self.distro_id = self.os_release.get("ID", "").strip().lower()
        self.distro_like = {
            item.strip().lower()
            for item in self.os_release.get("ID_LIKE", "").split()
            if item.strip()
        }
        self.package_backend = self._detect_package_backend()
        self.supports_aur = self.package_backend == "pacman" and shutil.which("yay") is not None
        self.dns_probe_host = self._dns_probe_target()
        self.package_cache_label, self.package_cache_path = self._package_cache_config()
        self.package_state = PackageRefreshState()
        self.package_lock = threading.Lock()
        self.package_force_event = threading.Event()
        self.package_stop_event = threading.Event()
        self.package_worker: threading.Thread | None = None
        self.package_worker_started = False
        sort_mode = os.environ.get("MONITOR_PACKAGE_SORT", "size").strip().lower()
        self.package_sort_mode = sort_mode if sort_mode in {"size", "name"} else "size"
        self.logs = LogsCollector(self)
        self.package_monitor = PackageMonitor(self)
        self.memory = MemoryCollector(self)
        self.cpu = CpuCollector(self)
        self.storage = StorageCollector(self)
        self.systemd_health = SystemdHealthCollector(self)
        self.thermal = ThermalCollector(self)
        self.hardware = HardwareCollector(self)
        self.fs_integrity = FilesystemIntegrityCollector(self)
        self.privileged_snapshots = PrivilegedSnapshotService(self)
        self.diff_snapshots = DiffSnapshotService(self, self.privileged_snapshots)

    def _detect_package_backend(self) -> str:
        if shutil.which("pacman") is not None:
            return "pacman"
        if shutil.which("apt-get") is not None and shutil.which("dpkg-query") is not None:
            return "apt"
        return "none"

    def _dns_probe_target(self) -> str:
        if self.distro_id == "debian" or "debian" in self.distro_like:
            return "deb.debian.org"
        if self.distro_id in {"ubuntu", "linuxmint", "pop"} or {"ubuntu"} & self.distro_like:
            return "archive.ubuntu.com"
        return "archlinux.org"

    def _package_cache_config(self) -> tuple[str, Path | None]:
        if self.package_backend == "pacman":
            return "Pacman cache", Path("/var/cache/pacman/pkg")
        if self.package_backend == "apt":
            return "APT cache", Path("/var/cache/apt/archives")
        return "Package cache", None

    def package_monitoring_enabled(self) -> bool:
        return self.package_backend in {"pacman", "apt"}

    def nvidia_monitoring_enabled(self) -> bool:
        return bool(self.cached("nvidia_monitoring_enabled", 60.0, self._detect_nvidia_monitoring))

    def _detect_nvidia_monitoring(self) -> bool:
        if Path("/proc/driver/nvidia/version").exists():
            return True
        if shutil.which("nvidia-smi") is not None:
            return True
        return False

    def capture_monitoring_enabled(self) -> bool:
        return bool(self.cached("capture_monitoring_enabled", 60.0, self._detect_capture_monitoring))

    def _detect_capture_monitoring(self) -> bool:
        cards = self.cached("capture_cards", 30.0, self._capture_cards)
        return any("avmatrix" in card.lower() for card in cards)

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
        return PrivilegedSnapshotService.snapshot_path()

    def _load_privileged_snapshot(self) -> dict[str, object]:
        return self.privileged_snapshots.load_snapshot()

    def _privileged_snapshot(self) -> dict[str, object]:
        return self.privileged_snapshots.snapshot()

    @staticmethod
    def _privileged_snapshot_max_age() -> int:
        return PrivilegedSnapshotService.snapshot_max_age()

    def _compute_privileged_snapshot_health(self) -> dict[str, object]:
        return self.privileged_snapshots.compute_health()

    def _privileged_snapshot_health(self) -> dict[str, object]:
        return self.privileged_snapshots.health()

    def _privileged_section(self, name: str) -> dict[str, object] | None:
        return self.privileged_snapshots.section(name)

    def _privileged_snapshot_line(self) -> str | None:
        return self.privileged_snapshots.snapshot_line()

    def collect_snapshot_health(self) -> list[str]:
        return self.privileged_snapshots.collect_health()

    @staticmethod
    def _diff_snapshot_path() -> Path:
        return DiffSnapshotService.snapshot_path()

    @staticmethod
    def _migrate_legacy_diff_snapshot(target: Path) -> None:
        DiffSnapshotService.migrate_legacy_snapshot(target)

    def _load_diff_snapshot(self) -> dict[str, object] | None:
        return self.diff_snapshots.load_snapshot()

    def _write_diff_snapshot(self, payload: dict[str, object]) -> None:
        self.diff_snapshots.write_snapshot(payload)

    @staticmethod
    def _age_label(seconds: int) -> str:
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m"
        return f"{seconds // 3600}h"

    def _current_state_digest(self) -> dict[str, object]:
        return self.diff_snapshots.current_state_digest()

    def _build_state_digest(self) -> dict[str, object]:
        return self.diff_snapshots.build_state_digest()

    def collect_diff_snapshot(self) -> list[str]:
        return self.diff_snapshots.collect_snapshot(DIFF_SNAPSHOT_INTERVAL)

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

        snapshot = current.get("privileged_snapshot", {})
        if isinstance(snapshot, dict):
            status = str(snapshot.get("status", "missing"))
            version = snapshot.get("version")
            expected = int(snapshot.get("expected_version", PRIVILEGED_SNAPSHOT_VERSION))
            age = snapshot.get("age")
            if status == "version_drift":
                version_label = f"v{version}" if isinstance(version, int) else "missing"
                problems.append((95, f"! Privileged snapshot schema drift ({version_label}, need v{expected})"))
            elif status == "invalid":
                problems.append((90, "! Privileged snapshot is unreadable"))
            elif status == "stale" and isinstance(age, int):
                problems.append((65, f"? Privileged snapshot is stale ({self._age_label(age)} old)"))

        wifi = current.get("wifi", {})
        if isinstance(wifi, dict):
            blocked = bool(wifi.get("blocked"))
            connected = bool(wifi.get("connected"))
            signal = wifi.get("signal_dbm")
            ssid = str(wifi.get("ssid", "")).strip()
            beacon_loss = wifi.get("beacon_loss")
            if blocked:
                problems.append((85, "! Wi-Fi radio is rfkill-blocked"))
            elif connected and isinstance(signal, (int, float)):
                if signal <= -78:
                    problems.append((80, f"! Wi-Fi signal is very weak ({signal:.0f} dBm on {ssid or 'current network'})"))
                elif signal <= -70:
                    problems.append((55, f"? Wi-Fi signal is marginal ({signal:.0f} dBm on {ssid or 'current network'})"))
            if connected and isinstance(beacon_loss, int) and beacon_loss > 0:
                problems.append((70, f"? Wi-Fi reports beacon loss ({beacon_loss})"))

        bluetooth = current.get("bluetooth", {})
        if isinstance(bluetooth, dict):
            adapter_count = bluetooth.get("adapter_count")
            blocked = bool(bluetooth.get("blocked"))
            powered = bluetooth.get("powered")
            service_active = str(bluetooth.get("service_active", "unknown"))
            connected_count = bluetooth.get("connected_count")
            issue_count = bluetooth.get("issue_count")
            if isinstance(adapter_count, int) and adapter_count > 0:
                if blocked:
                    problems.append((70, "? Bluetooth radio is rfkill-blocked"))
                elif service_active == "active" and powered is False:
                    problems.append((50, "? Bluetooth controller is present but powered off"))
                if (
                    isinstance(issue_count, int)
                    and issue_count > 0
                    and isinstance(connected_count, int)
                    and connected_count > 0
                ):
                    problems.append((45, f"? Bluetooth journal shows {issue_count} recent issue hints"))

        capture = current.get("capture", {})
        if isinstance(capture, dict):
            avmatrix_cards = capture.get("avmatrix_cards")
            kernel_channels = capture.get("kernel_channels")
            video_nodes = capture.get("video_nodes")
            if isinstance(avmatrix_cards, int) and avmatrix_cards > 0:
                if isinstance(kernel_channels, int) and kernel_channels == 0:
                    problems.append((95, "! AVMatrix card is present but kernel video channels are missing"))
                elif isinstance(kernel_channels, int) and isinstance(video_nodes, int):
                    if kernel_channels > 0 and video_nodes == 0:
                        problems.append((100, f"! AVMatrix has {kernel_channels} kernel channel(s) but no /dev/video nodes"))
                    elif 0 < video_nodes < kernel_channels:
                        problems.append((80, f"? AVMatrix exposes only {video_nodes}/{kernel_channels} /dev/video nodes"))

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
        self.package_monitor.start_worker()

    def stop_background_tasks(self) -> None:
        self.package_monitor.stop_worker()

    def request_package_refresh(self) -> None:
        self.package_monitor.request_refresh()

    def cycle_package_sort_mode(self) -> str:
        return self.package_monitor.cycle_sort_mode()

    def _package_refresh_loop(self) -> None:
        self.package_monitor.package_refresh_loop()

    @staticmethod
    def _parse_update_map(lines: Sequence[str]) -> dict[str, tuple[str, str]]:
        return PackageMonitor.parse_update_map(lines)

    @staticmethod
    def _filter_installed_updates(
        updates: dict[str, tuple[str, str]],
        installed: Sequence[str],
    ) -> dict[str, tuple[str, str]]:
        return PackageMonitor.filter_installed_updates(updates, installed)

    def refresh_package_state_sync(self) -> None:
        self.package_monitor.refresh_state_sync()

    def _package_state_snapshot(self) -> PackageRefreshState:
        return self.package_monitor.package_state_snapshot()

    def _package_refresh_lines(self, state: PackageRefreshState) -> list[str]:
        return self.package_monitor.package_refresh_lines(state)

    @staticmethod
    def _package_meta_cache_key(prefix: str, updates: dict[str, tuple[str, str]]) -> str:
        return PackageMonitor.package_meta_cache_key(prefix, updates)

    @staticmethod
    def _parse_info_blocks(text: str) -> list[dict[str, str]]:
        return PackageMonitor.parse_info_blocks(text)

    def _repo_update_metadata(self, updates: dict[str, tuple[str, str]]) -> tuple[dict[str, dict[str, int | str | None]], str | None]:
        return self.package_monitor.repo_update_metadata(updates)

    def _aur_update_metadata(self, updates: dict[str, tuple[str, str]]) -> tuple[dict[str, dict[str, int | str | None]], str | None]:
        return self.package_monitor.aur_update_metadata(updates)

    def _pending_update_rows(self, state: PackageRefreshState) -> tuple[list[PackageUpdateRow], list[str]]:
        return self.package_monitor.pending_update_rows(state)

    def _sorted_pending_rows(self, rows: Sequence[PackageUpdateRow]) -> list[PackageUpdateRow]:
        return self.package_monitor.sorted_pending_rows(rows)

    def _installed_packages(self) -> dict[str, str]:
        return self.package_monitor.installed_packages()

    def _running_kernel_version(self) -> str:
        return self.package_monitor.running_kernel_version()

    def _nvidia_module_version(self) -> str:
        return self.package_monitor.nvidia_module_version()

    def _tracked_kernel_packages(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        return self.package_monitor.tracked_kernel_packages(installed)

    def _tracked_firmware_versions(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        return self.package_monitor.tracked_firmware_versions(installed)

    def _tracked_nvidia_packages(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        return self.package_monitor.tracked_nvidia_packages(installed)

    @staticmethod
    def _package_line(name: str, installed_version: str, latest_version: str | None) -> str:
        return PackageMonitor.package_line(name, installed_version, latest_version)

    @staticmethod
    def _latest_version_for(name: str, updates: dict[str, tuple[str, str]]) -> str | None:
        return PackageMonitor.latest_version_for(name, updates)

    def command_lines(
        self,
        primary: Sequence[str],
        fallback: Sequence[str] | None = None,
        timeout: float = 6.0,
    ) -> tuple[list[str], str | None]:
        return self.package_monitor.command_lines(primary, fallback=fallback, timeout=timeout)

    def count_command_lines(self, args: Sequence[str], timeout: float = 5.0) -> tuple[int | None, str | None]:
        return self.package_monitor.count_command_lines(args, timeout=timeout)

    def _official_updates(self) -> tuple[list[str], str | None]:
        return self.package_monitor.official_updates()

    def _aur_updates(self) -> tuple[list[str], str | None]:
        return self.package_monitor.aur_updates()

    def _count_explicit(self) -> tuple[int | None, str | None]:
        return self.package_monitor.count_explicit()

    def _count_dependencies(self) -> tuple[int | None, str | None]:
        return self.package_monitor.count_dependencies()

    def _orphan_packages(self) -> tuple[list[str], str | None]:
        return self.package_monitor.orphan_packages()

    def _foreign_packages(self) -> tuple[list[str], str | None]:
        return self.package_monitor.foreign_packages()

    def _ignored_packages(self) -> list[str]:
        return self.package_monitor.ignored_packages()

    def _recent_upgrades(self) -> list[str]:
        return self.package_monitor.recent_upgrades()

    def collect_packages(self) -> list[str]:
        return self.package_monitor.collect_packages()

    def _collect_update_backlog(self, source: str) -> list[str]:
        return self.package_monitor.collect_update_backlog(source)

    def collect_pending_updates(self) -> list[str]:
        return self.package_monitor.collect_update_backlog("repo")

    def collect_aur_updates(self) -> list[str]:
        return self.package_monitor.collect_update_backlog("aur")

    def _filesystem_usage(self) -> list[dict[str, str | int]]:
        return self.storage.filesystem_usage()

    def _inode_usage(self) -> dict[str, int]:
        return self.storage.inode_usage()

    def _mount_summary(self) -> list[str]:
        return self.storage.mount_summary()

    @staticmethod
    def _mount_sort_key(item: str) -> tuple[int, str]:
        return StorageCollector.mount_sort_key(item)

    @staticmethod
    def _filesystem_sort_key(entry: dict[str, str | int]) -> tuple[int, str]:
        return StorageCollector.filesystem_sort_key(entry)

    @staticmethod
    def _storage_severity(pct: int, inode_pct: int | None) -> str:
        return StorageCollector.storage_severity(pct, inode_pct)

    @staticmethod
    def _abbreviate_path(path: str) -> str:
        return StorageCollector.abbreviate_path(path)

    def _directory_sizes(self) -> list[tuple[str, int]]:
        return self.storage.directory_sizes()

    def _read_diskstats(self) -> dict[str, tuple[int, int]]:
        return self.storage.read_diskstats()

    def _disk_rates(self) -> tuple[float, float, list[tuple[str, float]]]:
        return self.storage.disk_rates()

    def collect_storage(self) -> list[str]:
        return self.storage.collect()

    def _systemd_state(self) -> str:
        return self.systemd_health.systemd_state()

    def _failed_services(self) -> list[str]:
        return self.systemd_health.failed_services()

    def _restart_hints(self) -> list[str]:
        return self.systemd_health.restart_hints()

    def _service_count(self, state: str) -> tuple[int | None, str | None]:
        return self.systemd_health.service_count(state)

    def collect_systemd(self) -> list[str]:
        return self.systemd_health.collect()

    def collect_logs(self) -> list[str]:
        return self.logs.collect()

    def _meminfo(self) -> dict[str, int]:
        return self.memory.meminfo()

    def _psi(self, path: Path) -> dict[str, dict[str, float]]:
        return self.memory.psi(path)

    def collect_memory(self) -> list[str]:
        return self.memory.collect()

    def _read_cpu_stat(self) -> dict[str, int]:
        return self.cpu.read_cpu_stat()

    def _cpu_percentages(self) -> tuple[float, float, float]:
        return self.cpu.cpu_percentages()

    def _cpu_frequency(self) -> str:
        return self.cpu.cpu_frequency()

    def _top_processes(self) -> list[str]:
        return self.cpu.top_processes()

    def collect_cpu(self) -> list[str]:
        return self.cpu.collect()

    def _thermal_zones(self) -> list[str]:
        return self.thermal.thermal_zones()

    def _fans(self) -> list[str]:
        return self.thermal.fans()

    def _power_state(self) -> list[str]:
        return self.thermal.power_state()

    def _gpu_telemetry(self) -> list[str]:
        return self.thermal.gpu_telemetry()

    def collect_thermal(self) -> list[str]:
        return self.thermal.collect()

    def _smart_devices(self) -> list[str]:
        return self.hardware.smart_devices()

    def _smart_summary(self) -> list[str]:
        return self.hardware.smart_summary()

    def _gpu_processes(self) -> list[str]:
        return self.hardware.gpu_processes()

    def _device_counts(self) -> list[str]:
        return self.hardware.device_counts()

    def collect_hardware(self) -> list[str]:
        return self.hardware.collect()

    def collect_fs_integrity(self) -> list[str]:
        return self.fs_integrity.collect()

    def _drm_connectors(self) -> list[str]:
        connectors = []
        for status_path in sorted(Path("/sys/class/drm").glob("card*-*/status")):
            connector = status_path.parent.name
            status = read_text(status_path).strip() or "unknown"
            connectors.append(f"{connector} {status}")
        return connectors

    @staticmethod
    def _capture_slots(cards: Sequence[str]) -> set[str]:
        slots: set[str] = set()
        for raw in cards:
            match = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\b", raw, re.IGNORECASE)
            if match:
                slots.add(match.group(1))
        return slots

    def _capture_cards(self) -> list[str]:
        result = run_command(["lspci", "-D", "-nn", "-k"], timeout=4.0)
        if not result.stdout:
            return []
        cards = []
        blocks = re.split(r"\n(?=[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\s)", result.stdout, flags=re.IGNORECASE)
        for block in blocks:
            lines = [line.rstrip() for line in block.splitlines() if line.strip()]
            if not lines:
                continue
            header = lines[0].strip()
            lowered = header.lower()
            if "avmatrix" not in lowered and "multimedia video controller" not in lowered and "capture" not in lowered:
                continue
            driver = ""
            modules = ""
            for raw in lines[1:]:
                stripped = raw.strip()
                lowered_detail = stripped.lower()
                if lowered_detail.startswith("kernel driver in use:"):
                    driver = stripped.split(":", 1)[1].strip()
                elif lowered_detail.startswith("kernel modules:"):
                    modules = stripped.split(":", 1)[1].strip()
            summary = header
            if driver:
                summary += f" | driver {driver}"
            elif modules:
                summary += f" | modules {modules}"
            cards.append(summary)
        return cards[:6]

    def _capture_modules(self) -> list[str]:
        result = run_command(["lsmod"], timeout=3.0)
        if not result.stdout:
            return []
        modules = []
        for raw in line_list(result.stdout):
            name = raw.split()[0]
            if name in CAPTURE_STACK_MODULES:
                modules.append(name)
        return modules

    def _capture_driver_params(self) -> list[str]:
        params_dir = Path("/sys/module/HwsCapture/parameters")
        if not params_dir.exists():
            return []
        params = []
        for path in sorted(params_dir.iterdir()):
            if path.is_file():
                params.append(f"{path.name}={read_text(path).strip()}")
        return params

    @staticmethod
    def _capture_driver_overrides(params: Sequence[str]) -> list[str]:
        overrides = []
        for item in params:
            lowered = item.lower()
            if lowered.endswith("=n") or lowered.endswith("=0") or lowered.endswith("=false"):
                continue
            overrides.append(item)
        return overrides

    @staticmethod
    def _capture_card_brief(card: str) -> str:
        slot_match = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+", card, re.IGNORECASE)
        slot = slot_match.group(1) if slot_match else "unknown"
        description = card
        if ": " in description:
            description = description.split(": ", 1)[1]
        if " | " in description:
            description = description.split(" | ", 1)[0]
        description = description.replace("Silicon Magic ", "")
        driver_match = re.search(r"\|\s*driver\s+(.+)$", card)
        driver = driver_match.group(1).strip() if driver_match else "unknown"
        return shorten(f"{slot} | {description} | {driver}", 120)

    @staticmethod
    def _probe_v4l2_node(node: str) -> dict[str, str]:
        info: dict[str, str] = {}
        result = run_command(["v4l2-ctl", "-D", "-d", node], timeout=3.0)
        if result.stdout:
            for raw in result.stdout.splitlines():
                if ":" not in raw:
                    continue
                key, value = [part.strip() for part in raw.split(":", 1)]
                if key in {"Driver name", "Card type", "Bus info"}:
                    info[key] = value
        fmt_result = run_command(["v4l2-ctl", "--get-fmt-video", "-d", node], timeout=3.0)
        if fmt_result.stdout:
            width = None
            height = None
            pixfmt = None
            for raw in fmt_result.stdout.splitlines():
                raw = raw.strip()
                if raw.startswith("Width/Height"):
                    match = re.search(r"(\d+)\s*/\s*(\d+)", raw)
                    if match:
                        width, height = match.groups()
                elif raw.startswith("Pixel Format"):
                    match = re.search(r"'([^']+)'", raw)
                    if match:
                        pixfmt = match.group(1)
            if width and height:
                info["Format"] = f"{width}x{height}" + (f" {pixfmt}" if pixfmt else "")
        return info

    def _sysfs_v4l2_nodes(self) -> list[dict[str, object]]:
        root = Path("/sys/class/video4linux")
        if not root.exists():
            return []
        nodes: list[dict[str, object]] = []
        for path in sorted(root.glob("video*")):
            devname = f"/dev/{path.name}"
            resolved = str(path.resolve())
            slots = re.findall(r"(0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])", resolved, re.IGNORECASE)
            nodes.append(
                {
                    "sysfs_name": path.name,
                    "label": read_text(path / "name").strip() or path.name,
                    "devname": devname,
                    "present": Path(devname).exists(),
                    "major_minor": read_text(path / "dev").strip() or "unknown",
                    "index": read_text(path / "index").strip() or "",
                    "slot": slots[-1] if slots else "unknown",
                    "detail": self._probe_v4l2_node(devname) if Path(devname).exists() else {},
                }
            )
        return nodes

    @staticmethod
    def _format_sysfs_v4l2_node(entry: dict[str, object]) -> str:
        label = str(entry.get("label") or entry.get("sysfs_name") or "video")
        devname = str(entry.get("devname") or entry.get("sysfs_name") or "unknown")
        state = "present" if entry.get("present") else "missing"
        parts = [f"{devname} {state}"]
        major_minor = str(entry.get("major_minor") or "")
        if major_minor and major_minor != "unknown":
            parts.append(major_minor)
        slot = str(entry.get("slot") or "")
        if slot and slot != "unknown":
            parts.append(f"pci {slot}")
        detail = entry.get("detail")
        if isinstance(detail, dict):
            for key in ("Driver name", "Card type", "Format"):
                value = detail.get(key)
                if value:
                    parts.append(str(value))
        return f"{label}: {' | '.join(parts)}"

    def _v4l2_inventory(self) -> dict[str, object]:
        sysfs_nodes = self._sysfs_v4l2_nodes()
        video_nodes = sorted(str(path) for path in Path("/dev").glob("video*"))
        media_nodes = sorted(str(path) for path in Path("/dev").glob("media*"))
        result = run_command(["v4l2-ctl", "--list-devices"], timeout=4.0)
        if result.missing:
            return {
                "video_nodes": video_nodes,
                "media_nodes": media_nodes,
                "sysfs_nodes": sysfs_nodes,
                "userspace_lines": ["v4l2-ctl not found."],
            }
        if result.stderr:
            return {
                "video_nodes": video_nodes,
                "media_nodes": media_nodes,
                "sysfs_nodes": sysfs_nodes,
                "userspace_lines": [shorten(single_line(result.stderr), 140)],
            }
        if not result.stdout:
            if sysfs_nodes:
                userspace_lines = [f"No V4L2 devices listed despite {len(sysfs_nodes)} kernel video4linux channel(s)."]
            else:
                userspace_lines = ["No V4L2 devices listed."]
            return {
                "video_nodes": video_nodes,
                "media_nodes": media_nodes,
                "sysfs_nodes": sysfs_nodes,
                "userspace_lines": userspace_lines,
            }

        devices: list[dict[str, object]] = []
        current: dict[str, object] | None = None
        for raw in result.stdout.splitlines():
            if raw and not raw.startswith("\t"):
                current = {"name": raw.strip().rstrip(":"), "nodes": []}
                devices.append(current)
            elif current is not None and raw.strip():
                current["nodes"].append(raw.strip())

        lines = []
        for device in devices[:6]:
            nodes = [node for node in device.get("nodes", []) if node.startswith("/dev/video")]
            media = [node for node in device.get("nodes", []) if node.startswith("/dev/media")]
            primary = nodes[0] if nodes else (media[0] if media else None)
            detail = self._probe_v4l2_node(primary) if primary and Path(primary).exists() else {}
            detail_parts = []
            if detail.get("Driver name"):
                detail_parts.append(detail["Driver name"])
            if detail.get("Card type"):
                detail_parts.append(detail["Card type"])
            if detail.get("Bus info"):
                detail_parts.append(detail["Bus info"])
            if detail.get("Format"):
                detail_parts.append(detail["Format"])
            node_summary = ", ".join(nodes[:4] + media[:2]) if nodes or media else "no nodes"
            suffix = f" | {' | '.join(detail_parts)}" if detail_parts else ""
            lines.append(f"{device['name']}: {node_summary}{suffix}")
        if not lines:
            lines.append("No V4L2 devices listed.")
        return {
            "video_nodes": video_nodes,
            "media_nodes": media_nodes,
            "sysfs_nodes": sysfs_nodes,
            "userspace_lines": lines,
        }

    def _capture_log_hints(self) -> list[str]:
        result = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={CAPTURE_LOG_PATTERN}",
                "-n",
                "10",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        return parse_journal_lines(result, limit=6)

    @staticmethod
    def _capture_log_issues(entries: Sequence[str]) -> list[str]:
        issue_keywords = (
            "error",
            "fail",
            "failed",
            "warn",
            "timeout",
            "reset",
            "disconnect",
            "missing",
            "invalid",
            "no signal",
        )
        issues = [entry for entry in entries if any(token in entry.lower() for token in issue_keywords)]
        return issues[:3]

    @staticmethod
    def _connected_drm_connectors(connectors: Sequence[str]) -> list[str]:
        connected = []
        for item in connectors:
            lowered = item.lower()
            if "connected" in lowered and "disconnected" not in lowered:
                connected.append(item.split()[0])
        return connected

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

    @staticmethod
    def _encoder_summary(encoders: Sequence[str]) -> str:
        if not encoders:
            return "none detected"
        if len(encoders) == 1 and (
            encoders[0].endswith("not found.") or encoders[0].startswith("No known hardware encoders")
        ):
            return encoders[0]
        families = []
        for needle, label in (
            ("nvenc", "NVENC"),
            ("qsv", "QSV"),
            ("amf", "AMF"),
            ("vaapi", "VAAPI"),
            ("v4l2m2m", "V4L2-M2M"),
            ("rkmpp", "RKMPP"),
        ):
            if any(needle in item.lower() for item in encoders):
                families.append(label)
        if families:
            return ", ".join(families)
        return shorten(", ".join(encoders[:3]), 120)

    @staticmethod
    def _capture_clients(nodes: Sequence[str]) -> dict[str, list[str]]:
        active_nodes = [node for node in nodes if Path(node).exists()]
        if not active_nodes:
            return {}
        owners: dict[str, set[str]] = {node: set() for node in active_nodes}
        target_nodes = set(active_nodes)
        proc_root = Path("/proc")
        for pid_dir in proc_root.iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            if not fd_dir.is_dir():
                continue
            comm = read_text(pid_dir / "comm").strip() or pid_dir.name
            matched: set[str] = set()
            try:
                for fd_path in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd_path)
                    except OSError:
                        continue
                    if target in target_nodes:
                        matched.add(target)
            except OSError:
                continue
            for node in matched:
                owners[node].add(f"{pid_dir.name} {comm}")
        return {
            node: sorted(values)
            for node, values in owners.items()
            if values
        }

    def collect_device_specific(self) -> list[str]:
        lines = ["Capture pipeline:"]
        cards = self.cached("capture_cards", 30.0, self._capture_cards)
        modules = self.cached("capture_modules", 10.0, self._capture_modules)
        driver_params = self.cached("capture_driver_params", 30.0, self._capture_driver_params)
        v4l2_inventory = self.cached("v4l2_inventory", 20.0, self._v4l2_inventory)
        encoders = self.cached("encoder_availability", 600.0, self._encoder_availability)
        connectors = self._drm_connectors()
        log_hints = self._capture_log_hints()
        avmatrix_cards = [card for card in cards if "avmatrix" in card.lower()]
        capture_slots = self._capture_slots(avmatrix_cards)
        sysfs_nodes = v4l2_inventory.get("sysfs_nodes", []) if isinstance(v4l2_inventory, dict) else []
        capture_sysfs_nodes = [
            entry
            for entry in sysfs_nodes
            if isinstance(entry, dict) and str(entry.get("slot", "")) in capture_slots
        ]
        capture_video_nodes = [
            str(entry.get("devname"))
            for entry in capture_sysfs_nodes
            if entry.get("present") and entry.get("devname")
        ]
        media_nodes = v4l2_inventory.get("media_nodes", []) if isinstance(v4l2_inventory, dict) else []
        userspace_lines = v4l2_inventory.get("userspace_lines", []) if isinstance(v4l2_inventory, dict) else []
        capture_clients = (
            self.cached(
                "capture_clients:" + ",".join(capture_video_nodes),
                10.0,
                lambda: self._capture_clients(capture_video_nodes),
            )
            if capture_video_nodes
            else {}
        )
        driver_overrides = self._capture_driver_overrides(driver_params)
        connected_links = self._connected_drm_connectors(connectors)
        capture_log_issues = self._capture_log_issues(log_hints)

        health = "not detected"
        if avmatrix_cards:
            if not capture_sysfs_nodes:
                health = "broken"
            elif not capture_video_nodes:
                health = "degraded"
            elif len(capture_video_nodes) < len(capture_sysfs_nodes):
                health = "degraded"
            else:
                health = "ready"

        if health == "broken":
            lines.append("! AVMatrix readiness: broken")
        elif health == "degraded":
            lines.append("! AVMatrix readiness: degraded")
        elif health == "ready":
            lines.append("AVMatrix readiness: ready")
        else:
            lines.append("AVMatrix readiness: not detected")

        if avmatrix_cards:
            lines.append(f"  Card: {self._capture_card_brief(avmatrix_cards[0])}")
        lines.append(
            "  Stages: "
            + f"card {len(avmatrix_cards)} | kernel {len(capture_sysfs_nodes)}"
            + f" | /dev/video {len(capture_video_nodes)} | /dev/media {len(media_nodes)}"
        )
        lines.append("  Modules: " + (", ".join(modules[:6]) if modules else "none loaded"))

        if avmatrix_cards and not capture_sysfs_nodes:
            lines.append("! Breakpoint: AVMatrix is on PCI, but no kernel video channels were registered")
        elif avmatrix_cards and capture_sysfs_nodes and not capture_video_nodes:
            lines.append("! Breakpoint: kernel channels exist, but /dev/video nodes were not created")
            lines.append("? Likely udev/device-node issue; userspace cannot open the capture card")
        elif avmatrix_cards and len(capture_video_nodes) < len(capture_sysfs_nodes):
            lines.append(f"? Breakpoint: only {len(capture_video_nodes)}/{len(capture_sysfs_nodes)} capture nodes reached userspace")
        elif modules and not capture_sysfs_nodes:
            lines.append("? Breakpoint: capture modules are loaded, but the card is not exposing video channels")

        if driver_overrides:
            lines.append("  Driver overrides: " + ", ".join(driver_overrides[:4]))

        if capture_sysfs_nodes and health != "ready":
            lines.append("  Channels:")
            for entry in capture_sysfs_nodes[:8]:
                lines.append(f"    {self._format_sysfs_v4l2_node(entry)}")
        elif capture_sysfs_nodes:
            channel_names = [str(entry.get("label", entry.get("sysfs_name", "video"))) for entry in capture_sysfs_nodes]
            lines.append("  Channels: " + ", ".join(channel_names[:6]))

        if capture_video_nodes:
            rw_access = sum(1 for node in capture_video_nodes if os.access(node, os.R_OK | os.W_OK))
            lines.append(f"  Node access: {rw_access}/{len(capture_video_nodes)} read-write")
            if isinstance(capture_clients, dict) and capture_clients:
                client_parts = []
                for node, owners in list(capture_clients.items())[:4]:
                    client_parts.append(f"{Path(node).name} -> {', '.join(owners[:2])}")
                lines.append("  Capture clients: " + "; ".join(client_parts))
            else:
                lines.append("  Capture clients: none")
        elif userspace_lines and health == "not detected":
            lines.append("  V4L2 view: " + shorten(userspace_lines[0], 140))

        lines.append("Display / encode:")
        if connected_links:
            lines.append(f"  Connected links: {', '.join(connected_links[:4])}")
        else:
            lines.append("  Connected links: none")
        lines.append("  Encoders: " + self._encoder_summary(encoders))

        lines.append("Capture log issues:")
        if capture_log_issues:
            for item in capture_log_issues[:3]:
                lines.append(f"  {item}")
        elif log_hints:
            lines.append("  No AVMatrix warnings in current boot journal.")
        else:
            lines.append("  No AVMatrix journal entries found this boot.")
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
        result = run_command(["getent", "ahosts", self.dns_probe_host], timeout=3.0)
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

    def _wireless_interfaces(self) -> list[str]:
        root = Path("/sys/class/net")
        if not root.exists():
            return []
        names = []
        for path in sorted(root.iterdir()):
            if (path / "wireless").exists() or (path / "phy80211").exists():
                names.append(path.name)
        return names

    def _proc_net_wireless(self) -> dict[str, dict[str, object]]:
        return parse_proc_net_wireless_text(read_text(Path("/proc/net/wireless")))

    def _wireless_logs(self) -> list[str]:
        result = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={WIFI_LOG_PATTERN}",
                "-n",
                "10",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        return parse_journal_lines(result, limit=6)

    def _unit_status(self, action: str, unit: str) -> str:
        result = run_command(["systemctl", action, unit], timeout=3.0)
        if result.stdout:
            return first_nonempty_line(result.stdout)
        if result.missing:
            return "systemctl not found"
        if result.timed_out:
            return "systemctl timed out"
        if result.stderr:
            lowered = result.stderr.lower()
            if "failed to connect to system scope bus" in lowered or "operation not permitted" in lowered:
                return "system bus unavailable"
            return shorten(single_line(first_nonempty_line(result.stderr)), 120)
        return "unknown"

    def _rfkill_radios_from_sysfs(self, allowed_types: Sequence[str]) -> list[dict[str, object]]:
        type_filters = {entry.strip().lower() for entry in allowed_types}
        root = Path("/sys/class/rfkill")
        if not root.exists():
            return []
        radios: list[dict[str, object]] = []
        for path in sorted(root.iterdir()):
            radio_type = read_text(path / "type").strip().lower()
            if radio_type not in type_filters:
                continue
            radios.append(
                {
                    "name": read_text(path / "name").strip() or path.name,
                    "type": radio_type,
                    "soft_blocked": read_text(path / "soft").strip() == "1",
                    "hard_blocked": read_text(path / "hard").strip() == "1",
                }
            )
        return radios

    def _bluetooth_adapters(self) -> list[str]:
        root = Path("/sys/class/bluetooth")
        if not root.exists():
            return []
        return sorted(path.name for path in root.iterdir())

    def _bluetooth_logs(self) -> list[str]:
        result = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={BLUETOOTH_LOG_PATTERN}",
                "-n",
                "12",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        return parse_journal_lines(result, limit=8)

    def _bluetoothctl_text(self, args: Sequence[str], timeout: float = 4.0) -> tuple[str, str | None]:
        result = run_command(["bluetoothctl", *args], timeout=timeout)
        if result.stdout:
            return result.stdout, None
        if result.missing:
            return "", "bluetoothctl not found"
        if result.timed_out:
            return "", "bluetoothctl timed out"
        if result.stderr:
            lowered = result.stderr.lower()
            if "dbus_connection_get_object_path_data" in lowered or "connection != null" in lowered:
                return "", "bluetoothctl failed to connect to D-Bus"
            return "", shorten(single_line(first_nonempty_line(result.stderr)), 120)
        return "", f"bluetoothctl exited {result.returncode}"

    @staticmethod
    def _bluetooth_device_sort_key(entry: dict[str, object]) -> tuple[int, int, int, str]:
        connected = 0 if entry.get("connected") else 1
        trusted = 0 if entry.get("trusted") else 1
        paired = 0 if entry.get("paired") else 1
        name = str(entry.get("alias") or entry.get("name") or entry.get("address") or "")
        return (connected, trusted, paired, name.lower())

    @staticmethod
    def _bluetooth_issue_logs(entries: Sequence[str]) -> list[str]:
        issue_keywords = (
            "error",
            "fail",
            "failed",
            "timeout",
            "disconnect",
            "denied",
            "blocked",
            "abort",
            "missing",
        )
        return [entry for entry in entries if any(token in entry.lower() for token in issue_keywords)][:4]

    def _live_bluetooth_state(self) -> dict[str, object]:
        service_active = self._unit_status("is-active", "bluetooth.service")
        service_enabled = self._unit_status("is-enabled", "bluetooth.service")
        adapters = self._bluetooth_adapters()
        rfkill = self._rfkill_radios_from_sysfs(("bluetooth",))
        if not rfkill:
            rfkill_result = run_command(["rfkill", "list"], timeout=3.0)
            rfkill = parse_rfkill_output(rfkill_result.stdout, allowed_types=("bluetooth",)) if rfkill_result.stdout else []

        controller: dict[str, object] = {}
        devices: list[dict[str, object]] = []
        notes: list[str] = []
        should_query_bluetoothctl = bool(adapters) or service_active in {"active", "activating"}
        if should_query_bluetoothctl:
            show_text, show_error = self._bluetoothctl_text(["show"], timeout=4.0)
            if show_text and "No default controller available" not in show_text:
                controller = parse_bluetoothctl_show(show_text)
            elif show_error:
                notes.append(show_error)

            paired_text, paired_error = self._bluetoothctl_text(["paired-devices"], timeout=4.0)
            connected_text, connected_error = self._bluetoothctl_text(["devices", "Connected"], timeout=4.0)

            known_devices: dict[str, dict[str, object]] = {}
            if paired_text:
                for entry in parse_bluetoothctl_devices(paired_text):
                    address = str(entry.get("address", "")).upper()
                    if not address:
                        continue
                    known_devices[address] = {**entry, "paired": True}
            if connected_text:
                for entry in parse_bluetoothctl_devices(connected_text):
                    address = str(entry.get("address", "")).upper()
                    if not address:
                        continue
                    known = known_devices.setdefault(address, dict(entry))
                    known.update(entry)
                    known["connected"] = True
            for error in (paired_error, connected_error):
                if error and error not in notes:
                    notes.append(error)

            for address in list(known_devices)[:10]:
                info_text, info_error = self._bluetoothctl_text(["info", address], timeout=4.0)
                if info_text:
                    known_devices[address].update(parse_bluetoothctl_info(info_text))
                elif info_error and info_error not in notes:
                    notes.append(info_error)
            devices = sorted(known_devices.values(), key=self._bluetooth_device_sort_key)

        logs = self.cached("bluetooth_logs", 60.0, self._bluetooth_logs)
        return {
            "service_active": service_active,
            "service_enabled": service_enabled,
            "adapters": adapters,
            "rfkill": rfkill,
            "controller": controller,
            "devices": devices,
            "logs": logs,
            "notes": notes,
        }

    def _bluetooth_state(self) -> dict[str, object]:
        live = self.cached("bluetooth_live_state", 15.0, self._live_bluetooth_state)
        if isinstance(live, dict):
            return live
        return {}

    def _live_wifi_state(self) -> dict[str, object]:
        quality = self.cached("proc_net_wireless", 5.0, self._proc_net_wireless)
        interfaces: list[dict[str, object]] = []
        for name in self._wireless_interfaces():
            sysfs = Path("/sys/class/net") / name
            entry: dict[str, object] = {
                "interface": name,
                "operstate": read_text(sysfs / "operstate").strip() or "unknown",
                "mac": read_text(sysfs / "address").strip() or "",
                "carrier": read_text(sysfs / "carrier").strip() == "1",
                "mtu": parse_int(read_text(sysfs / "mtu"), default=0),
            }
            try:
                entry["driver"] = (sysfs / "device" / "driver").resolve().name
            except OSError:
                pass

            info_result = run_command(["iw", "dev", name, "info"], timeout=3.0)
            if info_result.stdout:
                for raw in info_result.stdout.splitlines():
                    line = raw.strip()
                    if line.startswith("type "):
                        entry["type"] = line.split(None, 1)[1].strip()
                    elif line.startswith("channel "):
                        entry.update(parse_iw_channel_details(line))
                    elif line.startswith("txpower "):
                        number = parse_float(line)
                        if number is not None:
                            entry["tx_power_dbm"] = number

            link_result = run_command(["iw", "dev", name, "link"], timeout=3.0)
            if link_result.stdout:
                entry.update(parse_iw_link_output(link_result.stdout))

            station_result = run_command(["iw", "dev", name, "station", "dump"], timeout=4.0)
            if station_result.stdout:
                entry.update(parse_iw_station_dump(station_result.stdout))

            power_save_result = run_command(["iw", "dev", name, "get", "power_save"], timeout=3.0)
            if power_save_result.stdout:
                for raw in power_save_result.stdout.splitlines():
                    line = raw.strip()
                    if line.lower().startswith("power save:"):
                        entry["power_save"] = line.split(":", 1)[1].strip().lower()
                        break

            if isinstance(quality, dict) and name in quality:
                entry.update(quality[name])
            interfaces.append(entry)

        rfkill_result = run_command(["rfkill", "list"], timeout=3.0)
        radios = parse_rfkill_output(rfkill_result.stdout) if rfkill_result.stdout else []
        logs = self.cached("wifi_logs", 60.0, self._wireless_logs)
        return {
            "interfaces": interfaces,
            "rfkill": radios,
            "logs": logs,
        }

    def _wifi_state(self) -> dict[str, object]:
        privileged = self._privileged_section("wifi")
        if privileged:
            return privileged
        live = self.cached("wifi_live_state", 10.0, self._live_wifi_state)
        if isinstance(live, dict):
            return live
        return {}

    @staticmethod
    def _wifi_interface_sort_key(entry: dict[str, object]) -> tuple[int, int, str]:
        connected = 0 if entry.get("connected") else 1
        carrier = 0 if entry.get("carrier") else 1
        return (connected, carrier, str(entry.get("interface", "")))

    @staticmethod
    def _wifi_signal_label(signal_dbm: float | int | None) -> str:
        if not isinstance(signal_dbm, (int, float)):
            return "unknown signal"
        if signal_dbm >= -60:
            return "excellent signal"
        if signal_dbm >= -67:
            return "good signal"
        if signal_dbm >= -75:
            return "fair signal"
        return "weak signal"

    @staticmethod
    def _wifi_issue_logs(entries: Sequence[str]) -> list[str]:
        issue_keywords = (
            "error",
            "fail",
            "failed",
            "warn",
            "timeout",
            "disconnect",
            "roam",
            "deauth",
            "auth",
            "blocked",
        )
        issues = [entry for entry in entries if any(token in entry.lower() for token in issue_keywords)]
        return issues[:3]

    def _wifi_summary_line(self, entry: dict[str, object]) -> str:
        iface = str(entry.get("interface", "wifi"))
        driver = str(entry.get("driver", "")).strip()
        operstate = str(entry.get("operstate", "unknown"))
        carrier = "carrier" if entry.get("carrier") else "no-carrier"
        mode = str(entry.get("type", "")).strip()
        parts = [f"{iface} {operstate}", carrier]
        if driver:
            parts.append(driver)
        if mode:
            parts.append(mode)
        return " | ".join(parts)

    def _wifi_link_line(self, entry: dict[str, object]) -> str:
        if not entry.get("connected"):
            return "Link: not associated"
        ssid = str(entry.get("ssid", "")).strip() or "hidden SSID"
        bssid = str(entry.get("bssid", "")).strip()
        band = str(entry.get("band", "")).strip()
        channel = entry.get("channel")
        frequency = entry.get("frequency_mhz")
        width = entry.get("width_mhz")
        parts = [ssid]
        if bssid:
            parts.append(bssid)
        if band:
            parts.append(band)
        if isinstance(channel, int) and channel > 0:
            parts.append(f"ch {channel}")
        if isinstance(width, int) and width > 0:
            parts.append(f"{width} MHz")
        elif isinstance(frequency, int) and frequency > 0:
            parts.append(f"{frequency} MHz")
        return "Link: " + " | ".join(parts)

    def _wifi_signal_line(self, entry: dict[str, object]) -> str:
        signal = entry.get("signal_dbm")
        noise = entry.get("noise_dbm")
        quality = entry.get("quality_pct")
        tx_power = entry.get("tx_power_dbm")
        parts = []
        if isinstance(signal, (int, float)):
            parts.append(f"{signal:.0f} dBm")
            parts.append(self._wifi_signal_label(signal))
        if isinstance(quality, (int, float)):
            parts.append(f"{quality:.0f}% quality")
        if isinstance(noise, (int, float)):
            parts.append(f"noise {noise:.0f} dBm")
        if isinstance(tx_power, (int, float)):
            parts.append(f"txpower {tx_power:.1f} dBm")
        return "Signal: " + (" | ".join(parts) if parts else "unavailable")

    @staticmethod
    def _wifi_phy_line(entry: dict[str, object]) -> str:
        rx = entry.get("rx_bitrate_mbps")
        tx = entry.get("tx_bitrate_mbps")
        expected = entry.get("expected_throughput_mbps")
        power_save = str(entry.get("power_save", "")).strip()
        parts = []
        if isinstance(rx, (int, float)):
            parts.append(f"rx {rx:.1f} Mb/s")
        if isinstance(tx, (int, float)):
            parts.append(f"tx {tx:.1f} Mb/s")
        if isinstance(expected, (int, float)):
            parts.append(f"expected {expected:.1f} Mb/s")
        if power_save:
            parts.append(f"power save {power_save}")
        return "PHY: " + (" | ".join(parts) if parts else "unavailable")

    @staticmethod
    def _wifi_traffic_line(entry: dict[str, object]) -> str:
        rx_bytes = entry.get("rx_bytes")
        tx_bytes = entry.get("tx_bytes")
        rx_packets = entry.get("rx_packets")
        tx_packets = entry.get("tx_packets")
        connected_seconds = entry.get("connected_seconds")
        parts = []
        if isinstance(rx_bytes, int) and rx_bytes >= 0:
            rx_label = format_bytes(rx_bytes)
            if isinstance(rx_packets, int):
                rx_label += f" / {rx_packets} pkts"
            parts.append(f"rx {rx_label}")
        if isinstance(tx_bytes, int) and tx_bytes >= 0:
            tx_label = format_bytes(tx_bytes)
            if isinstance(tx_packets, int):
                tx_label += f" / {tx_packets} pkts"
            parts.append(f"tx {tx_label}")
        if isinstance(connected_seconds, int) and connected_seconds >= 0:
            parts.append(f"connected {format_duration_compact(connected_seconds)}")
        return "Traffic: " + (" | ".join(parts) if parts else "unavailable")

    @staticmethod
    def _wifi_reliability_line(entry: dict[str, object]) -> str:
        inactive_ms = entry.get("inactive_ms")
        retries = entry.get("tx_retries")
        failed = entry.get("tx_failed")
        beacon_loss = entry.get("beacon_loss")
        discard_retry = entry.get("discard_retry")
        missed_beacon = entry.get("missed_beacon")
        authorized = entry.get("authorized")
        authenticated = entry.get("authenticated")
        associated = entry.get("associated")
        parts = []
        if isinstance(inactive_ms, int):
            parts.append(f"idle {inactive_ms} ms")
        if isinstance(retries, int):
            parts.append(f"retries {retries}")
        if isinstance(failed, int):
            parts.append(f"failed {failed}")
        if isinstance(beacon_loss, int):
            parts.append(f"beacon loss {beacon_loss}")
        if isinstance(discard_retry, int) and discard_retry > 0:
            parts.append(f"driver retry discards {discard_retry}")
        if isinstance(missed_beacon, int) and missed_beacon > 0:
            parts.append(f"missed beacon {missed_beacon}")
        auth_states = []
        if isinstance(authorized, bool):
            auth_states.append("authorized" if authorized else "not authorized")
        if isinstance(authenticated, bool):
            auth_states.append("authenticated" if authenticated else "not authenticated")
        if isinstance(associated, bool):
            auth_states.append("associated" if associated else "not associated")
        if auth_states:
            parts.append(", ".join(auth_states))
        return "Reliability: " + (" | ".join(parts) if parts else "no station metrics")

    def _wifi_assessment_line(self, entry: dict[str, object]) -> str:
        if not entry.get("connected"):
            operstate = str(entry.get("operstate", "unknown"))
            return f"Assessment: disconnected | operstate {operstate}"
        signal = entry.get("signal_dbm")
        band = str(entry.get("band", "")).strip()
        expected = entry.get("expected_throughput_mbps")
        power_save = str(entry.get("power_save", "")).strip()
        retries = entry.get("tx_retries")
        failed = entry.get("tx_failed")
        beacon_loss = entry.get("beacon_loss")
        parts = []
        parts.append(self._wifi_signal_label(signal if isinstance(signal, (int, float)) else None))
        if band:
            parts.append(f"{band} link")
        if isinstance(expected, (int, float)):
            if expected >= 400:
                parts.append("high expected throughput")
            elif expected >= 100:
                parts.append("moderate expected throughput")
            else:
                parts.append("low expected throughput")
        if isinstance(beacon_loss, int) and beacon_loss > 0:
            parts.append("beacon loss observed")
        elif isinstance(failed, int) and failed > 0:
            parts.append("tx failures observed")
        elif isinstance(retries, int) and retries > 200:
            parts.append("retry-heavy link")
        else:
            parts.append("no obvious retry pressure")
        if power_save == "on":
            parts.append("power save enabled")
        return "Assessment: " + " | ".join(parts)

    def _wifi_digest(self) -> dict[str, object]:
        state = self._wifi_state()
        interfaces = state.get("interfaces", [])
        radios = state.get("rfkill", [])
        digest: dict[str, object] = {
            "present": False,
            "blocked": False,
            "connected": False,
        }
        if isinstance(radios, list):
            for radio in radios:
                if not isinstance(radio, dict):
                    continue
                if radio.get("soft_blocked") or radio.get("hard_blocked"):
                    digest["blocked"] = True
                    break
        if not isinstance(interfaces, list) or not interfaces:
            return digest
        parsed_interfaces = [entry for entry in interfaces if isinstance(entry, dict)]
        if not parsed_interfaces:
            return digest
        parsed_interfaces.sort(key=self._wifi_interface_sort_key)
        active = parsed_interfaces[0]
        digest["present"] = True
        digest["interface"] = str(active.get("interface", ""))
        digest["connected"] = bool(active.get("connected"))
        if active.get("connected"):
            digest["ssid"] = str(active.get("ssid", ""))
        signal = active.get("signal_dbm")
        if isinstance(signal, (int, float)):
            digest["signal_dbm"] = float(signal)
        retries = active.get("tx_retries")
        failed = active.get("tx_failed")
        beacon_loss = active.get("beacon_loss")
        if isinstance(retries, int):
            digest["tx_retries"] = retries
        if isinstance(failed, int):
            digest["tx_failed"] = failed
        if isinstance(beacon_loss, int):
            digest["beacon_loss"] = beacon_loss
        return digest

    @staticmethod
    def _bluetooth_device_line(entry: dict[str, object]) -> str:
        name = str(entry.get("alias") or entry.get("name") or entry.get("address") or "device").strip()
        address = str(entry.get("address", "")).strip()
        icon = str(entry.get("icon", "")).strip()
        parts = [name]
        if address and address != name:
            parts.append(address)
        if icon:
            parts.append(icon)
        flags = []
        if entry.get("connected"):
            flags.append("connected")
        if entry.get("trusted"):
            flags.append("trusted")
        if entry.get("paired"):
            flags.append("paired")
        if entry.get("blocked"):
            flags.append("blocked")
        battery = entry.get("battery_pct")
        rssi = entry.get("rssi_dbm")
        tx_power = entry.get("tx_power_dbm")
        if isinstance(battery, int) and battery >= 0:
            parts.append(f"battery {battery}%")
        if isinstance(rssi, (int, float)):
            parts.append(f"RSSI {rssi:.0f} dBm")
        if isinstance(tx_power, (int, float)):
            parts.append(f"tx {tx_power:.0f} dBm")
        if flags:
            parts.append("/".join(flags))
        return " | ".join(parts)

    def _bluetooth_digest(self) -> dict[str, object]:
        state = self._bluetooth_state()
        adapters = state.get("adapters", [])
        rfkill = state.get("rfkill", [])
        controller = state.get("controller", {})
        devices = state.get("devices", [])
        logs = state.get("logs", [])
        digest: dict[str, object] = {
            "adapter_count": len(adapters) if isinstance(adapters, list) else 0,
            "blocked": False,
            "connected_count": 0,
            "paired_count": 0,
            "trusted_count": 0,
            "service_active": str(state.get("service_active", "unknown")),
        }
        if isinstance(rfkill, list):
            for radio in rfkill:
                if not isinstance(radio, dict):
                    continue
                if radio.get("soft_blocked") or radio.get("hard_blocked"):
                    digest["blocked"] = True
                    break
        if isinstance(controller, dict) and controller:
            powered = controller.get("powered")
            if isinstance(powered, bool):
                digest["powered"] = powered
            discovering = controller.get("discovering")
            if isinstance(discovering, bool):
                digest["discovering"] = discovering
        if isinstance(devices, list):
            parsed_devices = [entry for entry in devices if isinstance(entry, dict)]
            digest["connected_count"] = sum(1 for entry in parsed_devices if entry.get("connected"))
            digest["paired_count"] = sum(1 for entry in parsed_devices if entry.get("paired"))
            digest["trusted_count"] = sum(1 for entry in parsed_devices if entry.get("trusted"))
        if isinstance(logs, list):
            digest["issue_count"] = len(self._bluetooth_issue_logs(logs))
        return digest

    def collect_bluetooth(self) -> list[str]:
        state = self._bluetooth_state()
        adapters = state.get("adapters", [])
        rfkill = state.get("rfkill", [])
        controller = state.get("controller", {})
        devices = state.get("devices", [])
        logs = state.get("logs", [])
        notes = state.get("notes", [])
        service_active = str(state.get("service_active", "unknown"))
        service_enabled = str(state.get("service_enabled", "unknown"))

        lines: list[str] = [f"Service: {service_active} | {service_enabled}"]

        if isinstance(adapters, list) and adapters:
            lines.append(f"Adapters: {len(adapters)} detected ({', '.join(adapters[:4])})")
        else:
            lines.append("Adapters: none detected")

        if isinstance(rfkill, list) and rfkill:
            radio_parts = []
            for radio in rfkill[:4]:
                if not isinstance(radio, dict):
                    continue
                name = str(radio.get("name", "bluetooth"))
                status = "hard-blocked" if radio.get("hard_blocked") else "soft-blocked" if radio.get("soft_blocked") else "unblocked"
                radio_parts.append(f"{name} {status}")
            if radio_parts:
                lines.append("RFKill: " + " | ".join(radio_parts))

        if isinstance(controller, dict) and controller:
            parts = []
            name = str(controller.get("alias") or controller.get("name") or controller.get("address") or "controller").strip()
            address = str(controller.get("address", "")).strip()
            parts.append(name)
            if address and address != name:
                parts.append(address)
            powered = controller.get("powered")
            discoverable = controller.get("discoverable")
            pairable = controller.get("pairable")
            discovering = controller.get("discovering")
            if isinstance(powered, bool):
                parts.append("powered" if powered else "powered off")
            if isinstance(discoverable, bool):
                parts.append("discoverable" if discoverable else "non-discoverable")
            if isinstance(pairable, bool):
                parts.append("pairable" if pairable else "non-pairable")
            if isinstance(discovering, bool):
                parts.append("scanning" if discovering else "idle")
            lines.append("Controller: " + " | ".join(parts))

        parsed_devices = [entry for entry in devices if isinstance(entry, dict)] if isinstance(devices, list) else []
        connected_devices = [entry for entry in parsed_devices if entry.get("connected")]
        trusted_count = sum(1 for entry in parsed_devices if entry.get("trusted"))
        paired_count = sum(1 for entry in parsed_devices if entry.get("paired"))
        lines.append(
            "Devices: "
            + f"{paired_count} paired | {trusted_count} trusted | {len(connected_devices)} connected"
        )

        if connected_devices:
            lines.append("Connected devices:")
            for entry in connected_devices[:4]:
                lines.append(f"  {self._bluetooth_device_line(entry)}")
        elif parsed_devices:
            lines.append("Known devices:")
            for entry in parsed_devices[:4]:
                lines.append(f"  {self._bluetooth_device_line(entry)}")
        else:
            lines.append("Devices: no paired or connected devices reported.")

        if isinstance(notes, list) and notes:
            lines.append("Collector notes:")
            for note in notes[:3]:
                lines.append(f"  {note}")

        lines.append("Recent Bluetooth logs:")
        issues = self._bluetooth_issue_logs(logs) if isinstance(logs, list) else []
        if issues:
            for item in issues[:4]:
                lines.append(f"  {item}")
        elif isinstance(logs, list) and logs:
            lines.append("  No obvious Bluetooth warnings in current boot journal.")
        else:
            lines.append("  No Bluetooth journal entries found this boot.")
        return lines

    def collect_wifi(self) -> list[str]:
        state = self._wifi_state()
        snapshot_line = self._privileged_snapshot_line() if self._privileged_section("wifi") else None
        interfaces = state.get("interfaces", [])
        radios = state.get("rfkill", [])
        logs = state.get("logs", [])

        lines: list[str] = []
        if snapshot_line:
            lines.append(snapshot_line)

        if isinstance(radios, list) and radios:
            radio_parts = []
            for radio in radios[:4]:
                if not isinstance(radio, dict):
                    continue
                name = str(radio.get("name", "wifi"))
                status = "hard-blocked" if radio.get("hard_blocked") else "soft-blocked" if radio.get("soft_blocked") else "unblocked"
                radio_parts.append(f"{name} {status}")
            if radio_parts:
                lines.append("RFKill: " + " | ".join(radio_parts))

        parsed_interfaces = [entry for entry in interfaces if isinstance(entry, dict)] if isinstance(interfaces, list) else []
        if not parsed_interfaces:
            lines.append("No wireless interfaces detected.")
            return lines

        parsed_interfaces.sort(key=self._wifi_interface_sort_key)
        for entry in parsed_interfaces[:2]:
            lines.append(self._wifi_summary_line(entry))
            lines.append("  " + self._wifi_link_line(entry))
            lines.append("  " + self._wifi_signal_line(entry))
            lines.append("  " + self._wifi_phy_line(entry))
            lines.append("  " + self._wifi_traffic_line(entry))
            lines.append("  " + self._wifi_reliability_line(entry))
            lines.append("  " + self._wifi_assessment_line(entry))

        lines.append("Recent Wi-Fi logs:")
        issues = self._wifi_issue_logs(logs) if isinstance(logs, list) else []
        if issues:
            for item in issues[:3]:
                lines.append(f"  {item}")
        elif isinstance(logs, list) and logs:
            lines.append("  No obvious Wi-Fi warnings in current boot journal.")
        else:
            lines.append("  No Wi-Fi journal entries found this boot.")
        return lines

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
            lines.append(f"DNS lookup: {self.dns_probe_host} -> {dns_check}")
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
        lines.append(f"DNS lookup: {self.dns_probe_host} -> {dns_check}")
        if established is None or listening is None:
            lines.append("Connections: unavailable (socket inspection failed)")
        else:
            lines.append(f"Connections: {established} established | {listening} listening sockets")
        return lines

    def _listening_sockets(self) -> list[str]:
        rows, error = self._listener_rows()
        sockets = [f"{local} {process}".strip() for _proto, local, process in rows]
        if sockets:
            return sockets[:8]
        if error:
            return [error]
        return ["No listening sockets."]

    def _listener_rows(self) -> tuple[list[tuple[str, str, str]], str | None]:
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

    def _non_loopback_listeners(self) -> tuple[list[str], str | None]:
        rows, error = self._listener_rows()
        exposed = [
            f"{proto} {local} {process}".strip()
            for proto, local, process in rows
            if not is_loopback_endpoint(local)
        ]
        return exposed[:8], error

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
        exposed, exposed_error = self.cached("non_loopback_listeners", 30.0, self._non_loopback_listeners)
        privileged = self._privileged_section("security")
        if privileged:
            snapshot_line = self._privileged_snapshot_line()
            listeners = privileged.get("listeners", [])
            failed_logins = privileged.get("failed_logins", [])
            sudo_usage = privileged.get("sudo_usage", [])
            lines = []
            if snapshot_line:
                lines.append(snapshot_line)
            lines.append(
                f"Non-loopback listeners: {len(exposed)}"
                + (f" ({exposed_error})" if exposed_error else "")
            )
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

        listeners = self._listening_sockets()
        failed_logins = self._failed_logins()
        sudo_usage = self._sudo_usage()

        lines = [
            f"Non-loopback listeners: {len(exposed)}" + (f" ({exposed_error})" if exposed_error else "")
        ]
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

    def _path_size(self, path: Path, timeout: float = 6.0) -> int | None:
        if not path.exists():
            return None
        result = run_command(["du", "-sx", "-B1", str(path)], timeout=timeout)
        if not result.stdout:
            return None
        return parse_int(result.stdout.split()[0], default=-1)

    def _package_cache_stats(self) -> dict[str, object]:
        path = self.package_cache_path
        stats: dict[str, object] = {
            "label": self.package_cache_label,
            "path": str(path) if path is not None else "",
            "size": None,
            "files": 0,
            "oldest_age": None,
        }
        if path is None or not path.exists():
            return stats
        stats["size"] = self._path_size(path, timeout=8.0)
        oldest_age: int | None = None
        file_count = 0
        now = time.time()
        try:
            for entry in path.iterdir():
                try:
                    if not entry.is_file():
                        continue
                except OSError:
                    continue
                if self.package_backend == "pacman" and ".pkg.tar" not in entry.name:
                    continue
                if self.package_backend == "apt" and not entry.name.endswith(".deb"):
                    continue
                file_count += 1
                try:
                    age = max(int(now - entry.stat().st_mtime), 0)
                except OSError:
                    continue
                oldest_age = age if oldest_age is None else max(oldest_age, age)
        except OSError:
            return stats
        stats["files"] = file_count
        stats["oldest_age"] = oldest_age
        return stats

    def _config_drift_files(self) -> tuple[list[str], str | None]:
        root = Path("/etc")
        if not root.exists():
            return [], "/etc not found"
        matches: list[str] = []
        try:
            for current_root, _dirs, files in os.walk(root, followlinks=False):
                for name in files:
                    lowered = name.lower()
                    if not lowered.endswith(CONFIG_DRIFT_SUFFIXES):
                        continue
                    full_path = Path(current_root) / name
                    matches.append(str(full_path.relative_to(root)))
        except OSError as exc:
            return [], shorten(str(exc), 120)
        matches.sort()
        return matches, None

    def _count_crontab_lines(self, path: Path) -> int:
        count = 0
        for raw in read_lines(path):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and not re.match(r"^(@|\d|\*)", line):
                continue
            count += 1
        return count

    def _cron_entry_count(self) -> int:
        count = 0
        for path in CRON_FILES:
            if path.exists():
                count += self._count_crontab_lines(path)
        for directory in (*CRON_DIRS, *CRON_SPOOL_DIRS):
            if not directory.exists():
                continue
            try:
                count += sum(1 for entry in directory.iterdir() if entry.is_file() and not entry.name.startswith("."))
            except OSError:
                continue
        return count

    def _timer_hygiene(self) -> dict[str, object]:
        enabled_count, enabled_error = self.count_command_lines(
            ["systemctl", "list-unit-files", "--type=timer", "--state=enabled", "--no-legend", "--no-pager"],
            timeout=5.0,
        )
        failed_lines, failed_error = self.command_lines(
            ["systemctl", "--failed", "--type=timer", "--no-legend", "--no-pager"],
            timeout=5.0,
        )
        failed_timers = [line.split()[0] for line in failed_lines if line.split()]
        no_next_run: list[str] = []
        timers_error: str | None = None
        result = run_command(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"], timeout=6.0)
        if result.stdout or result.ok:
            for raw in line_list(result.stdout):
                parts = raw.rsplit(None, 2)
                if len(parts) < 3:
                    continue
                prefix, unit, _activates = parts
                if prefix.startswith("n/a"):
                    no_next_run.append(unit)
        elif result.missing:
            timers_error = "systemctl not found"
        elif result.timed_out:
            timers_error = "systemctl timed out"
        elif result.stderr:
            timers_error = shorten(single_line(result.stderr), 120)
        return {
            "enabled_count": enabled_count,
            "enabled_error": enabled_error,
            "failed_timers": failed_timers,
            "failed_error": failed_error,
            "no_next_run": no_next_run,
            "timers_error": timers_error,
            "cron_count": self._cron_entry_count(),
        }

    def _vm_image_inventory(self) -> list[tuple[str, int]]:
        images: list[tuple[str, int]] = []
        for base in VM_IMAGE_DIRS:
            if not base.exists():
                continue
            for current_root, _dirs, files in os.walk(base, followlinks=False):
                for name in files:
                    if not name.lower().endswith(VM_IMAGE_SUFFIXES):
                        continue
                    path = Path(current_root) / name
                    try:
                        size = path.stat().st_size
                    except OSError:
                        continue
                    images.append((str(path), size))
        images.sort(key=lambda item: item[1], reverse=True)
        return images

    def _container_vm_hygiene(self) -> dict[str, object]:
        docker_data = self._path_size(Path("/var/lib/docker"), timeout=8.0)
        podman_root = self._path_size(Path("/var/lib/containers/storage"), timeout=8.0)
        podman_user = self._path_size(Path.home() / ".local/share/containers/storage", timeout=8.0)

        docker_exited: int | None = None
        docker_dangling_images: int | None = None
        docker_dangling_volumes: int | None = None
        if shutil.which("docker") is not None:
            docker_exited, _ = self.count_command_lines(
                ["docker", "ps", "-aq", "--filter", "status=exited"],
                timeout=5.0,
            )
            docker_dangling_images, _ = self.count_command_lines(
                ["docker", "images", "-q", "--filter", "dangling=true"],
                timeout=5.0,
            )
            docker_dangling_volumes, _ = self.count_command_lines(
                ["docker", "volume", "ls", "-q", "--filter", "dangling=true"],
                timeout=5.0,
            )

        podman_exited: int | None = None
        podman_dangling_images: int | None = None
        if shutil.which("podman") is not None:
            podman_exited, _ = self.count_command_lines(
                ["podman", "ps", "-aq", "--filter", "status=exited"],
                timeout=5.0,
            )
            podman_dangling_images, _ = self.count_command_lines(
                ["podman", "images", "-q", "--filter", "dangling=true"],
                timeout=5.0,
            )

        vm_images = self._vm_image_inventory()
        summary_parts: list[str] = []
        if isinstance(docker_data, int) and docker_data > 0:
            summary_parts.append(f"docker data {format_bytes(docker_data)}")
        if isinstance(docker_exited, int) and docker_exited > 0:
            summary_parts.append(f"{docker_exited} exited docker ctrs")
        if isinstance(docker_dangling_images, int) and docker_dangling_images > 0:
            summary_parts.append(f"{docker_dangling_images} dangling docker images")
        if isinstance(docker_dangling_volumes, int) and docker_dangling_volumes > 0:
            summary_parts.append(f"{docker_dangling_volumes} dangling docker volumes")
        if isinstance(podman_root, int) and podman_root > 0:
            summary_parts.append(f"podman root {format_bytes(podman_root)}")
        if isinstance(podman_user, int) and podman_user > 0:
            summary_parts.append(f"podman user {format_bytes(podman_user)}")
        if isinstance(podman_exited, int) and podman_exited > 0:
            summary_parts.append(f"{podman_exited} exited podman ctrs")
        if isinstance(podman_dangling_images, int) and podman_dangling_images > 0:
            summary_parts.append(f"{podman_dangling_images} dangling podman images")
        if vm_images:
            total_vm_size = sum(size for _path, size in vm_images)
            summary_parts.append(f"{len(vm_images)} VM image(s) {format_bytes(total_vm_size)}")

        details = [
            f"{self._abbreviate_path(path)} {format_bytes(size)}"
            for path, size in vm_images[:3]
        ]
        return {
            "summary": "Container / VM leftovers: " + (" | ".join(summary_parts) if summary_parts else "none obvious"),
            "details": details,
        }

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
        package_cache = self.cached("package_cache_stats", 300.0, self._package_cache_stats)
        dir_sizes = self.cached("dir_sizes", 300.0, self._directory_sizes)
        config_drift, config_error = self.cached("config_drift_files", 600.0, self._config_drift_files)
        timer_hygiene = self.cached("timer_hygiene", 300.0, self._timer_hygiene)
        container_vm = self.cached("container_vm_hygiene", 600.0, self._container_vm_hygiene)
        log_dir = self.cached("log_dir_size", 300.0, lambda: self._path_size(Path("/var/log")))
        tmp_dir = self.cached("tmp_dir_size", 300.0, lambda: self._path_size(Path("/tmp")))
        var_tmp_dir = self.cached("var_tmp_dir_size", 300.0, lambda: self._path_size(Path("/var/tmp")))
        journal_usage = self.cached("journal_disk_usage", 300.0, self._journal_disk_usage)

        lines = [
            f"Orphans: {len(orphaned)}" + (f" ({orphan_error})" if orphan_error else ""),
        ]
        if orphaned:
            lines.append(f"  {', '.join(orphaned[:10])}")
        if isinstance(package_cache, dict):
            cache_size = package_cache.get("size")
            cache_files = int(package_cache.get("files", 0))
            oldest_age = package_cache.get("oldest_age")
            cache_line = (
                str(package_cache.get("label", self.package_cache_label))
                + ": "
                + (
                    format_bytes(cache_size)
                    if isinstance(cache_size, int) and cache_size >= 0
                    else "unavailable"
                )
            )
            if cache_files > 0:
                cache_line += f" across {cache_files} file(s)"
            if isinstance(oldest_age, int) and oldest_age > 0:
                cache_line += f" | oldest {self._age_label(oldest_age)}"
            lines.append(cache_line)
        else:
            lines.append(self.package_cache_label + ": unavailable")
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
        noisy_dirs = [(path, size) for path, size in dir_sizes if size >= 512 * 1024**2]
        if noisy_dirs:
            lines.append(
                "Large directories: "
                + ", ".join(
                    f"{self._abbreviate_path(path)} {format_bytes(size)}"
                    for path, size in noisy_dirs[:4]
                )
            )
        else:
            lines.append("Large directories: none above 512 MiB in watched paths.")

        if config_error:
            lines.append(f"Config drift: unavailable ({config_error})")
        else:
            lines.append(f"Config drift: {len(config_drift)} tracked leftover file(s) under /etc")
            for item in config_drift[:4]:
                lines.append(f"  {item}")

        if isinstance(timer_hygiene, dict):
            enabled_count = timer_hygiene.get("enabled_count")
            enabled_display = str(enabled_count) if isinstance(enabled_count, int) else "n/a"
            failed_timers = timer_hygiene.get("failed_timers", [])
            no_next_run = timer_hygiene.get("no_next_run", [])
            cron_count = int(timer_hygiene.get("cron_count", 0))
            timer_notes = ", ".join(
                note
                for note in (
                    timer_hygiene.get("enabled_error"),
                    timer_hygiene.get("failed_error"),
                    timer_hygiene.get("timers_error"),
                )
                if isinstance(note, str) and note
            )
            lines.append(
                f"Scheduled tasks: {enabled_display} enabled timer(s) | "
                f"{len(failed_timers) if isinstance(failed_timers, list) else 0} failed | "
                f"{cron_count} cron entry/file(s)"
                + (f" ({timer_notes})" if timer_notes else "")
            )
            if isinstance(failed_timers, list) and failed_timers:
                lines.append(f"  Failed timers: {summarize_list(failed_timers, limit=3)}")
            if isinstance(no_next_run, list) and no_next_run:
                lines.append(f"  No next run: {summarize_list(no_next_run, limit=3)}")

        if isinstance(container_vm, dict):
            summary = str(container_vm.get("summary", "Container / VM leftovers: none obvious"))
            lines.append(summary)
            details = container_vm.get("details", [])
            if isinstance(details, list):
                for item in details[:2]:
                    lines.append(f"  {shorten(str(item), 140)}")
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

    def collect_uptime(self) -> list[str]:
        return [self._uptime_summary()]

    def collect_boot(self) -> list[str]:
        lines = [
            f"Boot time: {self.cached('boot_time', 300.0, self._boot_time)}",
            "Slowest boot services:",
        ]
        blame = self.cached("boot_blame", 300.0, self._boot_blame)
        for item in blame[:6]:
            lines.append(f"  {item}")
        if not blame:
            lines.append("  unavailable")
        return lines


from monitor.model.dashboard import DashboardModel
from monitor.tui.dashboard import DashboardUI, print_once


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
        choices=[*BASE_TAB_ORDER, "all"],
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
        DashboardUI(model, initial_tab=args.tab if args.tab in model.tab_order else model.tab_order[0]).run()
    finally:
        model.stop()
        worker.join(timeout=1.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
