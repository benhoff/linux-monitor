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
from monitor.collectors.boot import BootCollector
from monitor.collectors.capture import CaptureCollector
from monitor.collectors.containers import ContainersCollector
from monitor.collectors.hygiene import HygieneCollector
from monitor.collectors.networking import BluetoothCollector, EthernetCollector, NetworkCollector, WifiCollector
from monitor.collectors.package_monitor import PackageMonitor, PackageRefreshState, PackageUpdateRow
from monitor.collectors.resources import (
    CpuCollector,
    FilesystemIntegrityCollector,
    HardwareCollector,
    MemoryCollector,
    ThermalCollector,
)
from monitor.collectors.security import SecurityCollector
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
        self.capture = CaptureCollector(self)
        self.containers = ContainersCollector(self)
        self.memory = MemoryCollector(self)
        self.network = NetworkCollector(self)
        self.ethernet = EthernetCollector(self)
        self.wifi = WifiCollector(self)
        self.bluetooth = BluetoothCollector(self)
        self.cpu = CpuCollector(self)
        self.storage = StorageCollector(self)
        self.systemd_health = SystemdHealthCollector(self)
        self.security = SecurityCollector(self)
        self.hygiene = HygieneCollector(self)
        self.boot = BootCollector(self)
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

    def container_monitoring_enabled(self) -> bool:
        return bool(self.cached("container_monitoring_enabled", 60.0, self._detect_container_monitoring))

    def _detect_container_monitoring(self) -> bool:
        return self.containers.detect_enabled()

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
                problems.append((severity, f"? {tracked_outdated} tracked priority packages are outdated"))

        storage = current.get("storage", {})
        root_pct = storage.get("root_pct") if isinstance(storage, dict) else None
        if isinstance(storage, dict):
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

        containers = current.get("containers", {})
        if isinstance(containers, dict) and containers.get("detected"):
            unhealthy = containers.get("unhealthy")
            restarting = containers.get("restarting")
            dead = containers.get("dead")
            docker_data_bytes = containers.get("docker_data_bytes")
            reclaimable_bytes = containers.get("reclaimable_bytes")
            stale_images_90d = containers.get("stale_images_90d")
            top_cpu_name = str(containers.get("top_cpu_name", "")).strip()
            top_cpu_pct = containers.get("top_cpu_pct")
            top_memory_name = str(containers.get("top_memory_name", "")).strip()
            top_memory_bytes = containers.get("top_memory_bytes")
            top_writable_name = str(containers.get("top_writable_name", "")).strip()
            top_writable_bytes = containers.get("top_writable_bytes")

            if isinstance(unhealthy, int) and unhealthy > 0:
                severity = 100 if unhealthy >= 3 else 90
                problems.append((severity, f"! Docker reports {unhealthy} unhealthy container(s)"))
            if (
                isinstance(restarting, int)
                and restarting > 0
                or isinstance(dead, int)
                and dead > 0
            ):
                restarting_count = restarting if isinstance(restarting, int) else 0
                dead_count = dead if isinstance(dead, int) else 0
                problems.append((88, f"! Docker has {restarting_count} restarting and {dead_count} dead container(s)"))
            if isinstance(top_cpu_pct, (int, float)) and float(top_cpu_pct) >= 80.0 and top_cpu_name:
                problems.append((70, f"? Docker CPU hotspot: {top_cpu_name} at {float(top_cpu_pct):.0f}%"))
            if isinstance(top_memory_bytes, int) and top_memory_bytes >= 2 * 1024**3 and top_memory_name:
                problems.append((65, f"? Docker memory hotspot: {top_memory_name} using {format_bytes(top_memory_bytes)}"))
            if isinstance(top_writable_bytes, int) and top_writable_bytes >= 2 * 1024**3 and top_writable_name:
                problems.append((60, f"? Docker writable layer hotspot: {top_writable_name} at {format_bytes(top_writable_bytes)}"))
            if isinstance(root_pct, int) and root_pct >= 75:
                if isinstance(docker_data_bytes, int) and docker_data_bytes >= 50 * 1024**3:
                    problems.append((85, f"! Docker data uses {format_bytes(docker_data_bytes)}"))
                elif isinstance(docker_data_bytes, int) and docker_data_bytes >= 25 * 1024**3:
                    problems.append((60, f"? Docker data uses {format_bytes(docker_data_bytes)}"))
                if isinstance(reclaimable_bytes, int) and reclaimable_bytes >= 15 * 1024**3:
                    problems.append((70, f"? Docker has {format_bytes(reclaimable_bytes)} reclaimable space"))
                elif isinstance(reclaimable_bytes, int) and reclaimable_bytes >= 5 * 1024**3:
                    problems.append((55, f"? Docker has {format_bytes(reclaimable_bytes)} reclaimable space"))
            if isinstance(stale_images_90d, int) and stale_images_90d > 0:
                severity = 65 if stale_images_90d >= 5 else 50
                problems.append((severity, f"? Docker image freshness: {stale_images_90d} image(s) older than 90d"))

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
            if isinstance(journal_errors, int) and journal_errors >= 3:
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
            elif status == "unreadable":
                problems.append((90, "! Privileged snapshot is not readable by the current user"))
            elif status == "invalid":
                problems.append((90, "! Privileged snapshot contents are invalid"))
            elif status == "stale" and isinstance(age, int):
                problems.append((65, f"? Privileged snapshot is stale ({self._age_label(age)} old)"))

        ethernet = current.get("ethernet", {})
        ethernet_default_route_up = False
        if isinstance(ethernet, dict) and ethernet.get("present"):
            interface = str(ethernet.get("interface", "ethernet")).strip() or "ethernet"
            connected = bool(ethernet.get("connected"))
            default_route = bool(ethernet.get("default_route"))
            ethernet_default_route_up = connected and default_route
            error_count = ethernet.get("error_count")
            drop_count = ethernet.get("drop_count")
            link_down_count = ethernet.get("link_down_count")
            issue_count = ethernet.get("issue_count")
            if default_route and not connected:
                problems.append((85, f"! Default-route Ethernet link is down on {interface}"))
            if connected and isinstance(error_count, int) and error_count > 0:
                severity = 85 if default_route else 70
                problems.append((severity, f"! Ethernet on {interface} reports {error_count} error counter(s)"))
            if connected and isinstance(drop_count, int) and drop_count >= 25:
                severity = 70 if default_route else 55
                problems.append((severity, f"? Ethernet on {interface} has {drop_count} dropped packets"))
            if isinstance(link_down_count, int) and link_down_count >= 5 and isinstance(issue_count, int) and issue_count > 0:
                severity = 70 if default_route else 55
                problems.append((severity, f"? Ethernet on {interface} has dropped link {link_down_count} time(s)"))
            if isinstance(issue_count, int) and issue_count >= 3 and not connected:
                problems.append((45, f"? Ethernet journal shows {issue_count} recent issue hints for {interface}"))

        wifi = current.get("wifi", {})
        if isinstance(wifi, dict):
            blocked = bool(wifi.get("blocked"))
            connected = bool(wifi.get("connected"))
            signal = wifi.get("signal_dbm")
            ssid = str(wifi.get("ssid", "")).strip()
            beacon_loss = wifi.get("beacon_loss")
            if blocked and not ethernet_default_route_up:
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

    def _tracked_priority_packages(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        return self.package_monitor.tracked_priority_rows(installed)

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
        return self.capture.drm_connectors()

    @staticmethod
    def _capture_slots(cards: Sequence[str]) -> set[str]:
        return CaptureCollector.capture_slots(cards)

    def _capture_cards(self) -> list[str]:
        return self.capture.capture_cards()

    def _capture_modules(self) -> list[str]:
        return self.capture.capture_modules()

    def _capture_driver_params(self) -> list[str]:
        return self.capture.capture_driver_params()

    @staticmethod
    def _capture_driver_overrides(params: Sequence[str]) -> list[str]:
        return CaptureCollector.capture_driver_overrides(params)

    @staticmethod
    def _capture_card_brief(card: str) -> str:
        return CaptureCollector.capture_card_brief(card)

    @staticmethod
    def _probe_v4l2_node(node: str) -> dict[str, str]:
        return CaptureCollector.probe_v4l2_node(node)

    def _sysfs_v4l2_nodes(self) -> list[dict[str, object]]:
        return self.capture.sysfs_v4l2_nodes()

    @staticmethod
    def _format_sysfs_v4l2_node(entry: dict[str, object]) -> str:
        return CaptureCollector.format_sysfs_v4l2_node(entry)

    def _v4l2_inventory(self) -> dict[str, object]:
        return self.capture.v4l2_inventory()

    def _capture_log_hints(self) -> list[str]:
        return self.capture.capture_log_hints()

    @staticmethod
    def _capture_log_issues(entries: Sequence[str]) -> list[str]:
        return CaptureCollector.capture_log_issues(entries)

    @staticmethod
    def _connected_drm_connectors(connectors: Sequence[str]) -> list[str]:
        return CaptureCollector.connected_drm_connectors(connectors)

    def _encoder_availability(self) -> list[str]:
        return self.capture.encoder_availability()

    @staticmethod
    def _encoder_summary(encoders: Sequence[str]) -> str:
        return CaptureCollector.encoder_summary(encoders)

    @staticmethod
    def _capture_clients(nodes: Sequence[str]) -> dict[str, list[str]]:
        return CaptureCollector.capture_clients(nodes)

    def collect_device_specific(self) -> list[str]:
        return self.capture.collect()

    def _interface_summary(self) -> list[str]:
        return self.network.interface_summary()

    def _default_route(self) -> str:
        return self.network.default_route()

    def _dns_servers(self) -> str:
        return self.network.dns_servers()

    def _dns_check(self) -> str:
        return self.network.dns_check()

    def _socket_counts(self) -> tuple[int | None, int | None]:
        return self.network.socket_counts()

    def _wireless_interfaces(self) -> list[str]:
        return self.wifi.wireless_interfaces()

    def _proc_net_wireless(self) -> dict[str, dict[str, object]]:
        return self.wifi.proc_net_wireless()

    def _wireless_logs(self) -> list[str]:
        return self.wifi.wireless_logs()

    def _unit_status(self, action: str, unit: str) -> str:
        return self.bluetooth.unit_status(action, unit)

    def _rfkill_radios_from_sysfs(self, allowed_types: Sequence[str]) -> list[dict[str, object]]:
        return self.bluetooth.rfkill_radios_from_sysfs(allowed_types)

    def _bluetooth_adapters(self) -> list[str]:
        return self.bluetooth.bluetooth_adapters()

    def _bluetooth_logs(self) -> list[str]:
        return self.bluetooth.bluetooth_logs()

    def _bluetoothctl_text(self, args: Sequence[str], timeout: float = 4.0) -> tuple[str, str | None]:
        return self.bluetooth.bluetoothctl_text(args, timeout=timeout)

    @staticmethod
    def _bluetooth_device_sort_key(entry: dict[str, object]) -> tuple[int, int, int, str]:
        return BluetoothCollector.bluetooth_device_sort_key(entry)

    @staticmethod
    def _bluetooth_issue_logs(entries: Sequence[str]) -> list[str]:
        return BluetoothCollector.bluetooth_issue_logs(entries)

    def _live_bluetooth_state(self) -> dict[str, object]:
        return self.bluetooth.live_state()

    def _bluetooth_state(self) -> dict[str, object]:
        return self.bluetooth.state()

    def _live_wifi_state(self) -> dict[str, object]:
        return self.wifi.live_state()

    def _wifi_state(self) -> dict[str, object]:
        return self.wifi.state()

    @staticmethod
    def _wifi_interface_sort_key(entry: dict[str, object]) -> tuple[int, int, str]:
        return WifiCollector.interface_sort_key(entry)

    @staticmethod
    def _wifi_signal_label(signal_dbm: float | int | None) -> str:
        return WifiCollector.signal_label(signal_dbm)

    @staticmethod
    def _wifi_issue_logs(entries: Sequence[str]) -> list[str]:
        return WifiCollector.issue_logs(entries)

    def _wifi_summary_line(self, entry: dict[str, object]) -> str:
        return self.wifi.summary_line(entry)

    def _wifi_link_line(self, entry: dict[str, object]) -> str:
        return self.wifi.link_line(entry)

    def _wifi_signal_line(self, entry: dict[str, object]) -> str:
        return self.wifi.signal_line(entry)

    @staticmethod
    def _wifi_phy_line(entry: dict[str, object]) -> str:
        return WifiCollector.phy_line(entry)

    @staticmethod
    def _wifi_traffic_line(entry: dict[str, object]) -> str:
        return WifiCollector.traffic_line(entry)

    @staticmethod
    def _wifi_reliability_line(entry: dict[str, object]) -> str:
        return WifiCollector.reliability_line(entry)

    def _wifi_assessment_line(self, entry: dict[str, object]) -> str:
        return self.wifi.assessment_line(entry)

    def _wifi_digest(self) -> dict[str, object]:
        return self.wifi.digest()

    @staticmethod
    def _bluetooth_device_line(entry: dict[str, object]) -> str:
        return BluetoothCollector.bluetooth_device_line(entry)

    def _bluetooth_digest(self) -> dict[str, object]:
        return self.bluetooth.digest()

    def collect_bluetooth(self) -> list[str]:
        return self.bluetooth.collect()

    def _live_ethernet_state(self) -> dict[str, object]:
        return self.ethernet.live_state()

    def _ethernet_state(self) -> dict[str, object]:
        return self.ethernet.state()

    def _ethernet_digest(self) -> dict[str, object]:
        return self.ethernet.digest()

    def collect_ethernet(self) -> list[str]:
        return self.ethernet.collect()

    def collect_wifi(self) -> list[str]:
        return self.wifi.collect()

    def collect_network(self) -> list[str]:
        return self.network.collect()

    def _listening_sockets(self) -> list[str]:
        return self.security.listening_sockets()

    def _listener_rows(self) -> tuple[list[tuple[str, str, str]], str | None]:
        return self.security.listener_rows()

    def _non_loopback_listeners(self) -> tuple[list[str], str | None]:
        return self.security.non_loopback_listeners()

    def _failed_logins(self) -> list[str]:
        return self.security.failed_logins()

    def _sudo_usage(self) -> list[str]:
        return self.security.sudo_usage()

    def collect_security(self) -> list[str]:
        return self.security.collect()

    def _path_size(self, path: Path, timeout: float = 6.0) -> int | None:
        return self.hygiene.path_size(path, timeout=timeout)

    def _package_cache_stats(self) -> dict[str, object]:
        return self.hygiene.package_cache_stats()

    def _config_drift_files(self) -> tuple[list[str], str | None]:
        return self.hygiene.config_drift_files()

    def _count_crontab_lines(self, path: Path) -> int:
        return self.hygiene.count_crontab_lines(path)

    def _cron_entry_count(self) -> int:
        return self.hygiene.cron_entry_count()

    def _timer_hygiene(self) -> dict[str, object]:
        return self.hygiene.timer_hygiene()

    def _vm_image_inventory(self) -> list[tuple[str, int]]:
        return self.hygiene.vm_image_inventory()

    def _container_vm_hygiene(self) -> dict[str, object]:
        return self.hygiene.container_vm_hygiene()

    def _journal_disk_usage(self) -> str:
        return self.hygiene.journal_disk_usage()

    def collect_hygiene(self) -> list[str]:
        return self.hygiene.collect()

    def _docker_digest(self) -> dict[str, object]:
        return self.containers.digest()

    def collect_containers(self) -> list[str]:
        return self.containers.collect()

    def _boot_time(self) -> str:
        return self.boot.boot_time()

    def _boot_blame(self) -> list[str]:
        return self.boot.boot_blame()

    def _uptime_summary(self) -> str:
        return self.boot.uptime_summary()

    def collect_uptime(self) -> list[str]:
        return self.boot.collect_uptime()

    def collect_boot(self) -> list[str]:
        return self.boot.collect()

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
    from monitor.model.dashboard import DashboardModel
    from monitor.tui.dashboard import DashboardUI, print_once

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
