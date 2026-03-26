#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Sequence

from monitor.shared.constants import (
    DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE,
    DEFAULT_PRIVILEGED_SNAPSHOT_PATH,
    FS_LOG_PATTERN,
    HARDWARE_LOG_PATTERN,
    PRIVILEGED_SNAPSHOT_VERSION,
    PSEUDO_FILESYSTEMS,
    WIFI_LOG_PATTERN,
)
from monitor.shared.paths import diff_snapshot_state_path, legacy_repo_diff_snapshot_path
from monitor.shared.text import line_list, parse_float, parse_int, read_lines, read_text


BASE_TAB_ORDER = ("tier1", "tier2", "tier3", "packages", "aur")
BASE_TAB_TITLES = {
    "tier1": "Tier 1",
    "tier2": "Tier 2",
    "tier3": "Tier 3",
    "packages": "Packages",
    "aur": "AUR",
}
PACKAGE_REFRESH_INTERVAL = 900
PACKAGE_METADATA_INTERVAL = 600
DIFF_SNAPSHOT_INTERVAL = 120
DEFAULT_PRIVILEGED_SNAPSHOT = str(DEFAULT_PRIVILEGED_SNAPSHOT_PATH)
PRIVILEGED_REFRESH_SCRIPT = "./refresh_monitor_privileged.sh"
PACKAGE_EST_DOWNLOAD_BYTES_PER_SEC = 10 * 1024 * 1024
PACKAGE_EST_AUR_SECONDS = 45
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
class PackageRefreshState:
    loading: bool = False
    last_updated: float = 0.0
    official_updates: dict[str, tuple[str, str]] = field(default_factory=dict)
    aur_updates: dict[str, tuple[str, str]] = field(default_factory=dict)
    official_error: str | None = None
    aur_error: str | None = None


@dataclass(frozen=True)
class PackageUpdateRow:
    source: str
    name: str
    current: str
    latest: str
    download_size: int | None = None
    installed_size: int | None = None


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


def parse_size_bytes(value: str) -> int | None:
    text = value.strip()
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?i?B)\b", text, re.IGNORECASE)
    if not match:
        return None
    amount = float(match.group(1))
    unit = match.group(2).upper()
    factors = {
        "B": 1,
        "KIB": 1024,
        "MIB": 1024**2,
        "GIB": 1024**3,
        "TIB": 1024**4,
        "PIB": 1024**5,
        "EIB": 1024**6,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
        "PB": 1000**5,
        "EB": 1000**6,
    }
    factor = factors.get(unit)
    if factor is None:
        return None
    return int(amount * factor)


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


def format_eta(seconds: int | float) -> str:
    total = max(int(seconds), 0)
    if total < 60:
        return f"{total}s"
    if total < 3600:
        minutes, secs = divmod(total, 60)
        if secs >= 30:
            minutes += 1
        return f"{minutes}m"
    return format_duration_compact(total)


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


def summarize_list(items: Sequence[str], limit: int = 3) -> str:
    values = [item for item in items if item]
    if not values:
        return "none"
    if len(values) <= limit:
        return ", ".join(values)
    return ", ".join(values[:limit]) + f", +{len(values) - limit} more"


def split_socket_endpoint(endpoint: str) -> tuple[str, str]:
    value = endpoint.strip()
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            host = value[1:end]
            remainder = value[end + 1 :]
            if remainder.startswith(":"):
                return host, remainder[1:]
            return host, ""
    host, sep, port = value.rpartition(":")
    if sep:
        return host, port
    return value, ""


def is_loopback_endpoint(endpoint: str) -> bool:
    host, _port = split_socket_endpoint(endpoint)
    host = host.strip().strip("[]")
    if not host:
        return False
    lowered = host.lower()
    if lowered in {"localhost", "ip6-localhost"}:
        return True
    if lowered == "*":
        return False
    host = host.split("%", 1)[0]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def journal_line_list(text: str, limit: int | None = None) -> list[str]:
    lines = [line for line in line_list(text) if line != "-- No entries --"]
    if limit is not None:
        return lines[:limit]
    return lines


def wireless_band_label(frequency_mhz: int | None) -> str | None:
    if frequency_mhz is None:
        return None
    if frequency_mhz >= 5925:
        return "6 GHz"
    if frequency_mhz >= 4900:
        return "5 GHz"
    if frequency_mhz >= 2400:
        return "2.4 GHz"
    return f"{frequency_mhz} MHz"


def parse_iw_channel_details(raw: str) -> dict[str, object]:
    details: dict[str, object] = {}
    channel_match = re.search(r"\bchannel\s+(\d+)\b", raw)
    freq_match = re.search(r"\((\d+)\s*MHz\)", raw)
    width_match = re.search(r"width:\s*([0-9]+)\s*MHz", raw)
    center1_match = re.search(r"center1:\s*(\d+)", raw)
    if channel_match:
        details["channel"] = int(channel_match.group(1))
    if freq_match:
        frequency = int(freq_match.group(1))
        details["frequency_mhz"] = frequency
        details["band"] = wireless_band_label(frequency)
    if width_match:
        details["width_mhz"] = int(width_match.group(1))
    if center1_match:
        details["center1_mhz"] = int(center1_match.group(1))
    return details


def parse_iw_rate_mbps(raw: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.\d+)?)\s*MBit/s", raw)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def parse_proc_net_wireless_text(text: str) -> dict[str, dict[str, object]]:
    stats: dict[str, dict[str, object]] = {}
    for raw in text.splitlines()[2:]:
        if ":" not in raw:
            continue
        iface, rest = raw.split(":", 1)
        fields = rest.split()
        if len(fields) < 10:
            continue
        link = parse_float(fields[1])
        level = parse_float(fields[2])
        noise = parse_float(fields[3])
        if link is None or level is None or noise is None:
            continue
        quality_pct = max(0.0, min(link / 70.0 * 100.0, 100.0))
        stats[iface.strip()] = {
            "link_quality": round(link, 1),
            "quality_pct": round(quality_pct, 1),
            "signal_dbm": round(level, 1),
            "noise_dbm": round(noise, 1),
            "discard_nwid": parse_int(fields[4]),
            "discard_crypt": parse_int(fields[5]),
            "discard_frag": parse_int(fields[6]),
            "discard_retry": parse_int(fields[7]),
            "discard_misc": parse_int(fields[8]),
            "missed_beacon": parse_int(fields[9]),
        }
    return stats


def parse_iw_link_output(text: str) -> dict[str, object]:
    state: dict[str, object] = {"connected": False}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Connected to "):
            state["connected"] = True
            match = re.match(r"Connected to ([0-9a-f:]{17})", line, re.IGNORECASE)
            if match:
                state["bssid"] = match.group(1).lower()
        elif line == "Not connected.":
            state["connected"] = False
        elif line.startswith("SSID:"):
            state["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("freq:"):
            frequency = parse_int(line)
            if frequency > 0:
                state["frequency_mhz"] = frequency
                state["band"] = wireless_band_label(frequency)
        elif line.startswith("signal:"):
            value = parse_float(line)
            if value is not None:
                state["signal_dbm"] = value
        elif line.startswith("rx bitrate:"):
            bitrate = parse_iw_rate_mbps(line)
            if bitrate is not None:
                state["rx_bitrate_mbps"] = bitrate
        elif line.startswith("tx bitrate:"):
            bitrate = parse_iw_rate_mbps(line)
            if bitrate is not None:
                state["tx_bitrate_mbps"] = bitrate
        elif line.startswith("RX:"):
            match = re.search(r"RX:\s*(\d+)\s+bytes\s+\((\d+)\s+packets\)", line)
            if match:
                state["rx_bytes"] = int(match.group(1))
                state["rx_packets"] = int(match.group(2))
        elif line.startswith("TX:"):
            match = re.search(r"TX:\s*(\d+)\s+bytes\s+\((\d+)\s+packets\)", line)
            if match:
                state["tx_bytes"] = int(match.group(1))
                state["tx_packets"] = int(match.group(2))
    return state


def parse_iw_station_dump(text: str) -> dict[str, object]:
    state: dict[str, object] = {}
    in_station = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Station "):
            if in_station:
                break
            in_station = True
            continue
        if not in_station or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        lower = key.lower()
        if lower == "inactive time":
            number = parse_float(value)
            if number is not None:
                state["inactive_ms"] = int(number)
        elif lower == "connected time":
            number = parse_float(value)
            if number is not None:
                state["connected_seconds"] = int(number)
        elif lower == "signal avg":
            number = parse_float(value)
            if number is not None:
                state["signal_avg_dbm"] = number
        elif lower == "tx retries":
            number = parse_float(value)
            if number is not None:
                state["tx_retries"] = int(number)
        elif lower == "tx failed":
            number = parse_float(value)
            if number is not None:
                state["tx_failed"] = int(number)
        elif lower == "beacon loss":
            number = parse_float(value)
            if number is not None:
                state["beacon_loss"] = int(number)
        elif lower == "expected throughput":
            bitrate = parse_iw_rate_mbps(value)
            if bitrate is not None:
                state["expected_throughput_mbps"] = bitrate
        elif lower == "authorized":
            state["authorized"] = value.lower() == "yes"
        elif lower == "authenticated":
            state["authenticated"] = value.lower() == "yes"
        elif lower == "associated":
            state["associated"] = value.lower() == "yes"
        elif lower == "wmm/wme":
            state["wmm"] = value.lower() == "yes"
        elif lower == "mfp":
            state["mfp"] = value.lower() == "yes"
    return state


def parse_rfkill_output(text: str, allowed_types: Sequence[str] | None = None) -> list[dict[str, object]]:
    type_filters = {
        entry.strip().lower()
        for entry in (allowed_types or ("wireless lan", "wlan", "wifi"))
    }
    radios: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        header = re.match(r"^\d+:\s+([^:]+):\s+(.+)$", line.strip())
        if header:
            if current and str(current.get("type", "")).lower() in type_filters:
                radios.append(current)
            current = {
                "name": header.group(1).strip(),
                "type": header.group(2).strip(),
            }
            continue
        if current is None or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        lower = key.lower()
        if lower == "soft blocked":
            current["soft_blocked"] = value.lower() == "yes"
        elif lower == "hard blocked":
            current["hard_blocked"] = value.lower() == "yes"
    if current and str(current.get("type", "")).lower() in type_filters:
        radios.append(current)
    return radios


def parse_bluetoothctl_devices(text: str) -> list[dict[str, object]]:
    devices: list[dict[str, object]] = []
    for raw in text.splitlines():
        match = re.match(r"^Device\s+([0-9A-F:]{17})\s+(.+)$", raw.strip(), re.IGNORECASE)
        if not match:
            continue
        devices.append(
            {
                "address": match.group(1).upper(),
                "name": match.group(2).strip(),
            }
        )
    return devices


def parse_bluetoothctl_show(text: str) -> dict[str, object]:
    state: dict[str, object] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        header = re.match(r"^Controller\s+([0-9A-F:]{17})\s+(.+?)(?:\s+\[default\])?$", line, re.IGNORECASE)
        if header:
            state["address"] = header.group(1).upper()
            state["name"] = header.group(2).strip()
            continue
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        lower = key.lower()
        if lower in {"powered", "discoverable", "discovering", "pairable"}:
            state[lower] = value.lower() == "yes"
        elif lower in {"name", "alias", "class", "modalias"}:
            state[lower] = value
    return state


def parse_bluetoothctl_info(text: str) -> dict[str, object]:
    state: dict[str, object] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        header = re.match(r"^Device\s+([0-9A-F:]{17})\s+(.+)$", line, re.IGNORECASE)
        if header:
            state["address"] = header.group(1).upper()
            state["name"] = header.group(2).strip()
            continue
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        lower = key.lower()
        if lower in {"name", "alias", "icon"}:
            state[lower] = value
        elif lower in {"paired", "trusted", "blocked", "connected", "legacypairing", "wakeallowed"}:
            state[lower] = value.lower() == "yes"
        elif lower == "battery percentage":
            match = re.search(r"\((\d+)\)", value)
            state["battery_pct"] = int(match.group(1)) if match else parse_int(value, default=-1)
        elif lower == "rssi":
            number = parse_float(value)
            if number is not None:
                state["rssi_dbm"] = number
        elif lower == "txpower":
            number = parse_float(value)
            if number is not None:
                state["tx_power_dbm"] = number
    return state


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
        return Path(os.environ.get("MONITOR_PRIVILEGED_SNAPSHOT", DEFAULT_PRIVILEGED_SNAPSHOT))

    def _load_privileged_snapshot(self) -> dict[str, object]:
        path = self._privileged_snapshot_path()
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _privileged_snapshot(self) -> dict[str, object]:
        return self.cached("privileged_snapshot", 2.0, self._load_privileged_snapshot)

    @staticmethod
    def _privileged_snapshot_max_age() -> int:
        raw = os.environ.get("MONITOR_PRIVILEGED_SNAPSHOT_MAX_AGE")
        if raw is None:
            return DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE
        try:
            value = int(raw)
        except ValueError:
            return DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE
        return value if value > 0 else DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE

    def _compute_privileged_snapshot_health(self) -> dict[str, object]:
        path = self._privileged_snapshot_path()
        max_age = self._privileged_snapshot_max_age()
        health: dict[str, object] = {
            "path": str(path),
            "expected_version": PRIVILEGED_SNAPSHOT_VERSION,
            "max_age": max_age,
            "status": "missing",
            "usable": False,
            "snapshot": {},
        }
        if not path.exists():
            health["reason"] = "snapshot file does not exist"
            return health
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            health["status"] = "invalid"
            health["reason"] = str(exc)
            return health
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            health["status"] = "invalid"
            health["reason"] = f"invalid JSON: {exc.msg}"
            return health
        if not isinstance(data, dict):
            health["status"] = "invalid"
            health["reason"] = "snapshot root is not a JSON object"
            return health

        health["snapshot"] = data
        version = data.get("snapshot_version")
        writer = data.get("snapshot_writer")
        generated = data.get("generated_at")
        health["version"] = version if isinstance(version, int) else None
        if isinstance(writer, str) and writer:
            health["writer"] = writer
        if isinstance(generated, (int, float)):
            health["generated_at"] = float(generated)
            health["age"] = max(int(time.time() - float(generated)), 0)
        else:
            health["generated_at"] = None
            health["age"] = None

        if not isinstance(version, int) or version != PRIVILEGED_SNAPSHOT_VERSION:
            health["status"] = "version_drift"
            if isinstance(version, int):
                health["reason"] = f"snapshot schema v{version}, expected v{PRIVILEGED_SNAPSHOT_VERSION}"
            else:
                health["reason"] = f"snapshot schema missing, expected v{PRIVILEGED_SNAPSHOT_VERSION}"
            return health

        if not isinstance(generated, (int, float)):
            health["status"] = "invalid"
            health["reason"] = "generated_at missing from snapshot"
            return health

        health["usable"] = True
        if int(health["age"]) > max_age:
            health["status"] = "stale"
            health["reason"] = f"snapshot older than {self._age_label(max_age)}"
        else:
            health["status"] = "healthy"
        return health

    def _privileged_snapshot_health(self) -> dict[str, object]:
        return self.cached("privileged_snapshot_health", 2.0, self._compute_privileged_snapshot_health)

    def _privileged_section(self, name: str) -> dict[str, object] | None:
        health = self._privileged_snapshot_health()
        if not health.get("usable"):
            return None
        snapshot = health.get("snapshot", {})
        if not isinstance(snapshot, dict):
            return None
        section = snapshot.get(name)
        if isinstance(section, dict):
            return section
        return None

    def _privileged_snapshot_line(self) -> str | None:
        health = self._privileged_snapshot_health()
        status = str(health.get("status", "missing"))
        generated = health.get("generated_at")
        if not isinstance(generated, (int, float)):
            return None
        age = max(int(health.get("age", max(int(time.time() - generated), 0))), 0)
        version = health.get("version")
        if status == "healthy":
            return None
        version_label = f"v{version}" if isinstance(version, int) else "schema?"
        if status == "stale":
            return f"? Snapshot: {version_label} | {self._age_label(age)} old | stale"
        return None

    def collect_snapshot_health(self) -> list[str]:
        health = self._privileged_snapshot_health()
        status = str(health.get("status", "missing"))
        version = health.get("version")
        expected = int(health.get("expected_version", PRIVILEGED_SNAPSHOT_VERSION))
        path = str(health.get("path", self._privileged_snapshot_path()))
        writer = health.get("writer")
        generated = health.get("generated_at")
        age = health.get("age")
        max_age = int(health.get("max_age", DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE))
        reason = str(health.get("reason", "")).strip()
        age_label = self._age_label(age) if isinstance(age, int) else "unknown age"
        version_label = f"v{version}" if isinstance(version, int) else "schema?"

        lines: list[str] = []
        if status == "healthy":
            lines.append(f"Status: healthy | {version_label} | {age_label} old")
            lines.append("Mode: privileged sections are using the snapshot")
            return lines

        if status == "stale":
            lines.append(f"? Status: stale | {version_label} | {age_label} old")
            lines.append(f"? Older than {self._age_label(max_age)}; privileged sections may lag reality")
            lines.append("Refresh: monitor-privileged-refresh")
            return lines

        if status == "version_drift":
            found = f"v{version}" if isinstance(version, int) else "missing schema"
            lines.append(f"! Status: version drift | found {found} | need v{expected}")
            lines.append("! Privileged sections fell back to unprivileged probes")
            lines.append(f"Path: {path}")
            lines.append("Refresh: monitor-privileged-refresh")
            return lines

        if status == "invalid":
            lines.append("! Status: invalid")
            lines.append(f"! {reason or 'Snapshot is unreadable'}")
            lines.append(f"Path: {path}")
            lines.append("Refresh: monitor-privileged-refresh")
            return lines

        lines.append("? Status: missing")
        lines.append("? Privileged sections fell back to unprivileged probes")
        lines.append(f"Path: {path}")
        if isinstance(generated, (int, float)):
            timestamp = datetime.fromtimestamp(generated).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"Last refresh: {timestamp} ({age_label} ago)")
        if isinstance(writer, str) and writer:
            lines.append(f"Writer: {writer}")
        lines.append("Refresh: monitor-privileged-refresh")
        return lines

    @staticmethod
    def _diff_snapshot_path() -> Path:
        return diff_snapshot_state_path()

    @staticmethod
    def _migrate_legacy_diff_snapshot(target: Path) -> None:
        if os.environ.get("MONITOR_DIFF_SNAPSHOT"):
            return
        legacy = legacy_repo_diff_snapshot_path()
        if legacy == target or target.exists() or not legacy.exists():
            return
        try:
            payload = legacy.read_text(encoding="utf-8")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(payload, encoding="utf-8")
        except OSError:
            return

    def _load_diff_snapshot(self) -> dict[str, object] | None:
        path = self._diff_snapshot_path()
        self._migrate_legacy_diff_snapshot(path)
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

        snapshot_health = self._privileged_snapshot_health()
        wifi_digest = self._wifi_digest()
        bluetooth_digest = self._bluetooth_digest()

        capture_cards = self.cached("capture_cards", 30.0, self._capture_cards)
        avmatrix_cards = [card for card in capture_cards if "avmatrix" in card.lower()]
        capture_slots = self._capture_slots(avmatrix_cards)
        v4l2_inventory = self.cached("v4l2_inventory", 20.0, self._v4l2_inventory)
        sysfs_nodes = v4l2_inventory.get("sysfs_nodes", []) if isinstance(v4l2_inventory, dict) else []
        avmatrix_sysfs_nodes = [
            entry
            for entry in sysfs_nodes
            if isinstance(entry, dict) and str(entry.get("slot", "")) in capture_slots
        ]
        avmatrix_video_nodes = [
            entry
            for entry in avmatrix_sysfs_nodes
            if isinstance(entry, dict) and entry.get("present")
        ]

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
            "privileged_snapshot": {
                "status": str(snapshot_health.get("status", "missing")),
                "version": snapshot_health.get("version"),
                "expected_version": int(snapshot_health.get("expected_version", PRIVILEGED_SNAPSHOT_VERSION)),
                "age": snapshot_health.get("age"),
            },
            "wifi": wifi_digest,
            "bluetooth": bluetooth_digest,
            "capture": {
                "avmatrix_cards": len(avmatrix_cards),
                "kernel_channels": len(avmatrix_sysfs_nodes),
                "video_nodes": len(avmatrix_video_nodes),
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

        current_snapshot = current.get("privileged_snapshot", {})
        previous_snapshot = previous.get("privileged_snapshot", {})
        if isinstance(current_snapshot, dict) and isinstance(previous_snapshot, dict):
            current_status = str(current_snapshot.get("status", "missing"))
            previous_status = str(previous_snapshot.get("status", "missing"))
            if current_status != previous_status:
                changes.append(f"Privileged snapshot: {previous_status} -> {current_status}")
            current_version = current_snapshot.get("version")
            previous_version = previous_snapshot.get("version")
            if (
                isinstance(current_version, int)
                and isinstance(previous_version, int)
                and current_version != previous_version
            ):
                changes.append(f"Privileged snapshot schema: v{previous_version} -> v{current_version}")

        current_wifi = current.get("wifi", {})
        previous_wifi = previous.get("wifi", {})
        if isinstance(current_wifi, dict) and isinstance(previous_wifi, dict):
            current_connected = bool(current_wifi.get("connected"))
            previous_connected = bool(previous_wifi.get("connected"))
            if current_connected != previous_connected:
                if current_connected:
                    ssid = str(current_wifi.get("ssid", "")).strip()
                    changes.append(f"Wi-Fi: connected to {ssid or 'network'}")
                else:
                    changes.append("Wi-Fi: link dropped")
            current_ssid = str(current_wifi.get("ssid", "")).strip()
            previous_ssid = str(previous_wifi.get("ssid", "")).strip()
            if current_connected and previous_connected and current_ssid and previous_ssid and current_ssid != previous_ssid:
                changes.append(f"Wi-Fi SSID: {previous_ssid} -> {current_ssid}")
            current_signal = current_wifi.get("signal_dbm")
            previous_signal = previous_wifi.get("signal_dbm")
            if (
                isinstance(current_signal, (int, float))
                and isinstance(previous_signal, (int, float))
                and abs(float(current_signal) - float(previous_signal)) >= 10.0
            ):
                changes.append(f"Wi-Fi signal: {previous_signal:.0f} -> {current_signal:.0f} dBm")
            current_blocked = bool(current_wifi.get("blocked"))
            previous_blocked = bool(previous_wifi.get("blocked"))
            if current_blocked != previous_blocked:
                changes.append("Wi-Fi radio: blocked" if current_blocked else "Wi-Fi radio: unblocked")

        current_bluetooth = current.get("bluetooth", {})
        previous_bluetooth = previous.get("bluetooth", {})
        if isinstance(current_bluetooth, dict) and isinstance(previous_bluetooth, dict):
            current_connected = current_bluetooth.get("connected_count")
            previous_connected = previous_bluetooth.get("connected_count")
            if isinstance(current_connected, int) and isinstance(previous_connected, int) and current_connected != previous_connected:
                changes.append(f"Bluetooth: {current_connected - previous_connected:+d} connected devices ({current_connected} now)")
            current_blocked = bool(current_bluetooth.get("blocked"))
            previous_blocked = bool(previous_bluetooth.get("blocked"))
            if current_blocked != previous_blocked:
                changes.append("Bluetooth radio: blocked" if current_blocked else "Bluetooth radio: unblocked")
            current_powered = current_bluetooth.get("powered")
            previous_powered = previous_bluetooth.get("powered")
            if isinstance(current_powered, bool) and isinstance(previous_powered, bool) and current_powered != previous_powered:
                changes.append("Bluetooth controller: powered on" if current_powered else "Bluetooth controller: powered off")

        current_capture = current.get("capture", {})
        previous_capture = previous.get("capture", {})
        if isinstance(current_capture, dict) and isinstance(previous_capture, dict):
            current_cards = current_capture.get("avmatrix_cards")
            previous_cards = previous_capture.get("avmatrix_cards")
            current_kernel = current_capture.get("kernel_channels")
            previous_kernel = previous_capture.get("kernel_channels")
            current_nodes = current_capture.get("video_nodes")
            previous_nodes = previous_capture.get("video_nodes")
            if (
                isinstance(current_cards, int)
                and isinstance(previous_cards, int)
                and current_cards != previous_cards
            ):
                changes.append(f"AVMatrix cards: {current_cards - previous_cards:+d} detected ({current_cards} now)")
            if (
                isinstance(current_kernel, int)
                and isinstance(previous_kernel, int)
                and isinstance(current_nodes, int)
                and isinstance(previous_nodes, int)
                and (current_kernel != previous_kernel or current_nodes != previous_nodes)
            ):
                changes.append(
                    "AVMatrix nodes: "
                    + f"{current_nodes}/{current_kernel} /dev-to-kernel channels "
                    + f"(was {previous_nodes}/{previous_kernel})"
                )

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
        if not self.package_monitoring_enabled():
            return
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

    def cycle_package_sort_mode(self) -> str:
        self.package_sort_mode = "name" if self.package_sort_mode == "size" else "size"
        return self.package_sort_mode

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

    @staticmethod
    def _filter_installed_updates(
        updates: dict[str, tuple[str, str]],
        installed: Sequence[str],
    ) -> dict[str, tuple[str, str]]:
        installed_names = set(installed)
        return {
            name: versions
            for name, versions in updates.items()
            if name in installed_names
        }

    def refresh_package_state_sync(self) -> None:
        if not self.package_monitoring_enabled():
            with self.package_lock:
                self.package_state = PackageRefreshState(
                    loading=False,
                    last_updated=time.time(),
                    official_updates={},
                    aur_updates={},
                    official_error="package monitoring is only implemented for pacman systems",
                    aur_error=None,
                )
            return
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
        aur_lines: list[str] = []
        aur_error: str | None = None
        if self.supports_aur:
            aur_lines, aur_error = self._aur_updates()
        installed_packages = self._installed_packages()
        official_updates = self._filter_installed_updates(
            self._parse_update_map(official_lines),
            installed_packages,
        )
        aur_updates = self._filter_installed_updates(
            self._parse_update_map(aur_lines),
            installed_packages,
        )
        with self.package_lock:
            self.package_state = PackageRefreshState(
                loading=False,
                last_updated=time.time(),
                official_updates=official_updates,
                aur_updates=aur_updates,
                official_error=official_error,
                aur_error=aur_error,
            )

    def _package_state_snapshot(self) -> PackageRefreshState:
        if not self.package_monitoring_enabled():
            return PackageRefreshState(
                loading=False,
                last_updated=time.time(),
                official_updates={},
                aur_updates={},
                official_error="package monitoring is only implemented for pacman systems",
                aur_error=None,
            )
        if not self.package_worker_started and self.package_state.last_updated == 0.0:
            self.refresh_package_state_sync()
        with self.package_lock:
            return PackageRefreshState(
                loading=self.package_state.loading,
                last_updated=self.package_state.last_updated,
                official_updates=dict(self.package_state.official_updates),
                aur_updates=dict(self.package_state.aur_updates),
                official_error=self.package_state.official_error,
                aur_error=self.package_state.aur_error,
            )

    def _package_refresh_lines(self, state: PackageRefreshState) -> list[str]:
        lines: list[str] = []
        source_label = {
            "pacman": "pacman/checkupdates",
            "apt": "apt package metadata",
        }.get(self.package_backend, "package metadata")
        lines.append(f"Package source: {source_label} | privileged snapshot not required")
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
        return lines

    @staticmethod
    def _package_meta_cache_key(prefix: str, updates: dict[str, tuple[str, str]]) -> str:
        digest = hashlib.sha1(
            "\n".join(
                f"{name}\t{current}\t{latest}"
                for name, (current, latest) in sorted(updates.items())
            ).encode("utf-8")
        ).hexdigest()
        return f"{prefix}:{digest}"

    @staticmethod
    def _parse_info_blocks(text: str) -> list[dict[str, str]]:
        blocks: list[dict[str, str]] = []
        current: dict[str, str] = {}
        last_key: str | None = None
        for raw in text.splitlines():
            if not raw.strip():
                if current:
                    blocks.append(current)
                    current = {}
                    last_key = None
                continue
            if ":" in raw:
                key, value = raw.split(":", 1)
                key = key.strip()
                if key:
                    current[key] = value.strip()
                    last_key = key
                    continue
            if last_key is not None:
                current[last_key] = (current[last_key] + " " + raw.strip()).strip()
        if current:
            blocks.append(current)
        return blocks

    def _repo_update_metadata(self, updates: dict[str, tuple[str, str]]) -> tuple[dict[str, dict[str, int | str | None]], str | None]:
        if not updates:
            return {}, None
        names = sorted(updates)
        timeout = min(max(8.0, len(names) * 0.4), 30.0)
        if self.package_backend == "pacman":
            result = run_command(["pacman", "-Si", *names], timeout=timeout)
            if not result.stdout:
                if result.missing:
                    return {}, "pacman not found"
                if result.timed_out:
                    return {}, "pacman -Si timed out"
                if result.stderr:
                    return {}, shorten(single_line(result.stderr), 120)
                return {}, "pacman -Si returned no data"
        elif self.package_backend == "apt":
            result = run_command(["apt-cache", "show", *names], timeout=timeout)
            if not result.stdout:
                if result.missing:
                    return {}, "apt-cache not found"
                if result.timed_out:
                    return {}, "apt-cache show timed out"
                if result.stderr:
                    return {}, shorten(single_line(result.stderr), 120)
                return {}, "apt-cache show returned no data"
        else:
            return {}, "repo metadata is unavailable for this package backend"
        metadata: dict[str, dict[str, int | str | None]] = {}
        for block in self._parse_info_blocks(result.stdout):
            name = block.get("Name")
            if not name:
                continue
            if self.package_backend == "pacman":
                metadata[name] = {
                    "version": block.get("Version"),
                    "download_size": parse_size_bytes(block.get("Download Size", "")),
                    "installed_size": parse_size_bytes(block.get("Installed Size", "")),
                }
                continue

            version = block.get("Version")
            latest = updates.get(name, ("", ""))[1]
            if latest and version and version != latest and name in metadata:
                continue
            download_size = parse_int(block.get("Size", ""), default=-1)
            installed_size = parse_int(block.get("Installed-Size", ""), default=-1)
            metadata[name] = {
                "version": version,
                "download_size": download_size if download_size >= 0 else None,
                "installed_size": installed_size * 1024 if installed_size >= 0 else None,
            }
        return metadata, None

    def _aur_update_metadata(self, updates: dict[str, tuple[str, str]]) -> tuple[dict[str, dict[str, int | str | None]], str | None]:
        if not updates:
            return {}, None
        names = sorted(updates)
        timeout = min(max(10.0, len(names) * 0.5), 40.0)
        result = run_command(["yay", "-Si", "--aur", *names], timeout=timeout)
        if not result.stdout:
            if result.missing:
                return {}, "yay not found"
            if result.timed_out:
                return {}, "yay -Si timed out"
            if result.stderr:
                return {}, shorten(single_line(result.stderr), 120)
            return {}, "yay -Si returned no data"
        metadata: dict[str, dict[str, int | str | None]] = {}
        for block in self._parse_info_blocks(result.stdout):
            name = block.get("Name")
            if not name:
                continue
            metadata[name] = {
                "version": block.get("Version"),
                "download_size": (
                    parse_size_bytes(block.get("Download Size", ""))
                    or parse_size_bytes(block.get("Package Size", ""))
                ),
                "installed_size": (
                    parse_size_bytes(block.get("Installed Size", ""))
                    or parse_size_bytes(block.get("Package Size", ""))
                ),
            }
        return metadata, None

    def _pending_update_rows(self, state: PackageRefreshState) -> tuple[list[PackageUpdateRow], list[str]]:
        notes: list[str] = []
        repo_meta: dict[str, dict[str, int | str | None]] = {}
        aur_meta: dict[str, dict[str, int | str | None]] = {}

        if state.official_updates and not state.official_error:
            repo_meta, repo_error = self.cached(
                self._package_meta_cache_key("repo_meta", state.official_updates),
                PACKAGE_METADATA_INTERVAL,
                lambda: self._repo_update_metadata(state.official_updates),
            )
            if repo_error:
                notes.append(f"repo size metadata unavailable ({repo_error})")

        if state.aur_updates and not state.aur_error:
            aur_meta, aur_error = self.cached(
                self._package_meta_cache_key("aur_meta", state.aur_updates),
                PACKAGE_METADATA_INTERVAL,
                lambda: self._aur_update_metadata(state.aur_updates),
            )
            if aur_error:
                notes.append(f"AUR size metadata unavailable ({aur_error})")

        rows: list[PackageUpdateRow] = []
        for name, (current, latest) in state.official_updates.items():
            meta = repo_meta.get(name, {})
            rows.append(
                PackageUpdateRow(
                    source="repo",
                    name=name,
                    current=current,
                    latest=latest,
                    download_size=meta.get("download_size") if isinstance(meta, dict) else None,
                    installed_size=meta.get("installed_size") if isinstance(meta, dict) else None,
                )
            )
        for name, (current, latest) in state.aur_updates.items():
            meta = aur_meta.get(name, {})
            rows.append(
                PackageUpdateRow(
                    source="aur",
                    name=name,
                    current=current,
                    latest=latest,
                    download_size=meta.get("download_size") if isinstance(meta, dict) else None,
                    installed_size=meta.get("installed_size") if isinstance(meta, dict) else None,
                )
            )
        return rows, notes

    def _sorted_pending_rows(self, rows: Sequence[PackageUpdateRow]) -> list[PackageUpdateRow]:
        if self.package_sort_mode == "name":
            return sorted(rows, key=lambda row: (row.name.lower(), row.source))
        return sorted(
            rows,
            key=lambda row: (
                0 if row.download_size is not None else 1,
                -(row.download_size or 0),
                row.name.lower(),
                row.source,
            ),
        )

    def _installed_packages(self) -> dict[str, str]:
        packages: dict[str, str] = {}
        if self.package_backend == "pacman":
            result = run_command(["pacman", "-Q"], timeout=6.0)
            for raw in line_list(result.stdout):
                parts = raw.split(None, 1)
                if len(parts) != 2:
                    continue
                packages[parts[0]] = parts[1]
            return packages
        if self.package_backend == "apt":
            result = run_command(
                ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
                timeout=10.0,
            )
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

    def _tracked_kernel_packages(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        if self.package_backend == "pacman":
            return [(name, installed[name]) for name in KERNEL_PACKAGE_NAMES if name in installed]
        if self.package_backend == "apt":
            running_kernel_pkg = f"linux-image-{self._running_kernel_version()}"
            preferred: list[str] = []
            for name in installed:
                if name == running_kernel_pkg:
                    preferred.append(name)
                elif name.startswith(("linux-generic", "linux-image-generic", "linux-headers-generic")):
                    preferred.append(name)
                elif name.startswith("linux-image-") and name.endswith("-generic"):
                    preferred.append(name)
            unique = sorted(dict.fromkeys(preferred))
            return [(name, installed[name]) for name in unique[:6]]
        return []

    def _tracked_firmware_versions(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        if self.package_backend == "pacman":
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
        if self.package_backend == "apt":
            rows: list[tuple[str, str]] = []
            for name in ("linux-firmware", "intel-microcode", "amd64-microcode"):
                if name in installed:
                    rows.append((name, installed[name]))
            return rows
        return []

    def _tracked_nvidia_packages(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        if self.package_backend == "pacman":
            return [(name, installed[name]) for name in NVIDIA_PACKAGE_NAMES if name in installed]
        if self.package_backend == "apt":
            rows = [
                (name, version)
                for name, version in installed.items()
                if name.startswith(("nvidia-driver-", "nvidia-utils-", "linux-modules-nvidia-"))
            ]
            rows.sort(key=lambda item: item[0])
            return rows[:8]
        return []

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
        if self.package_backend == "apt":
            result = run_command(["apt", "list", "--upgradable"], timeout=12.0)
            if result.stdout:
                lines: list[str] = []
                for raw in result.stdout.splitlines():
                    line = raw.strip()
                    if not line or line.lower().startswith("listing"):
                        continue
                    match = re.match(
                        r"^([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: (\S+)\]$",
                        line,
                    )
                    if not match:
                        continue
                    name, latest, current = match.groups()
                    lines.append(f"{name} {current} -> {latest}")
                return lines, None
            if result.missing:
                return [], "apt not found"
            if result.timed_out:
                return [], "apt list timed out"
            if result.stderr:
                return [], shorten(single_line(result.stderr), 120)
            return [], None
        if self.package_backend != "pacman":
            return [], "repo update monitoring is unavailable for this package backend"
        return self.command_lines(
            ["checkupdates"],
            fallback=["pacman", "-Qu"],
            timeout=8.0,
        )

    def _aur_updates(self) -> tuple[list[str], str | None]:
        if not self.supports_aur:
            return [], None
        return self.command_lines(["yay", "-Qua"], timeout=12.0)

    def _count_explicit(self) -> tuple[int | None, str | None]:
        if self.package_backend == "apt":
            return self.count_command_lines(["apt-mark", "showmanual"], timeout=6.0)
        if self.package_backend != "pacman":
            return None, "explicit package count is only implemented for pacman systems"
        return self.count_command_lines(["pacman", "-Qe"])

    def _count_dependencies(self) -> tuple[int | None, str | None]:
        if self.package_backend == "apt":
            return self.count_command_lines(["apt-mark", "showauto"], timeout=6.0)
        if self.package_backend != "pacman":
            return None, "dependency package count is only implemented for pacman systems"
        return self.count_command_lines(["pacman", "-Qd"])

    def _orphan_packages(self) -> tuple[list[str], str | None]:
        if self.package_backend == "apt":
            result = run_command(["apt-get", "-s", "autoremove"], timeout=8.0)
            if result.stdout or result.ok:
                packages = []
                for raw in result.stdout.splitlines():
                    if not raw.startswith("Remv "):
                        continue
                    parts = raw.split()
                    if len(parts) >= 2:
                        packages.append(parts[1])
                return packages, None
            if result.missing:
                return [], "apt-get not found"
            if result.timed_out:
                return [], "apt-get timed out"
            if result.stderr:
                return [], shorten(single_line(result.stderr), 120)
            return [], None
        if self.package_backend != "pacman":
            return [], "orphan detection is unavailable for this package backend"
        return self.command_lines(["pacman", "-Qtdq"])

    def _foreign_packages(self) -> tuple[list[str], str | None]:
        if self.package_backend != "pacman":
            return [], "foreign package detection is only implemented for pacman systems"
        return self.command_lines(["pacman", "-Qm"])

    def _ignored_packages(self) -> list[str]:
        if self.package_backend == "apt":
            result = run_command(["apt-mark", "showhold"], timeout=4.0)
            return line_list(result.stdout)
        if self.package_backend != "pacman":
            return []
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
        if self.package_backend != "pacman":
            return []
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
        installed = self.cached("installed_packages", 30.0, self._installed_packages)
        foreign: list[str] = []
        foreign_error: str | None = None
        if self.package_backend == "pacman":
            foreign, foreign_error = self.cached("foreign", 900.0, self._foreign_packages)
        ignored = self.cached("ignored", 1800.0, self._ignored_packages)
        explicit_count, explicit_error = self.cached("count_explicit", 900.0, self._count_explicit)
        dependency_count, dependency_error = self.cached("count_dependencies", 900.0, self._count_dependencies)
        running_kernel = self._running_kernel_version()
        nvidia_module = self._nvidia_module_version()
        state = self._package_state_snapshot()

        lines: list[str] = []
        total_pending = len(state.official_updates) + len(state.aur_updates)
        lines.extend(self._package_refresh_lines(state))

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
        if self.supports_aur:
            aur_summary = "?" if state.aur_error else str(len(state.aur_updates))
            total_summary = (
                "unknown"
                if state.official_error or state.aur_error
                else str(total_pending)
            )
            lines.append(
                f"  Pending updates: {total_summary} total | {repo_summary} repo | {aur_summary} AUR"
            )
        else:
            total_summary = "unknown" if state.official_error else str(len(state.official_updates))
            lines.append(f"  Pending updates: {total_summary} repo")

        if self.package_backend == "pacman":
            lines.append(
                f"  Installed foreign packages: {len(foreign)}"
                + (f" ({foreign_error})" if foreign_error else "")
                + f" | ignored packages: {len(ignored)}"
            )
        else:
            manual_label = str(explicit_count) if explicit_count is not None else "?"
            auto_label = str(dependency_count) if dependency_count is not None else "?"
            note_parts = [f"manual {manual_label}", f"auto {auto_label}", f"held {len(ignored)}"]
            errors = [item for item in (explicit_error, dependency_error) if item]
            if errors:
                note_parts.append(" / ".join(errors))
            lines.append("  Package marks: " + " | ".join(note_parts))
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

        if self.nvidia_monitoring_enabled() or nvidia_packages:
            lines.append("NVIDIA:")
            lines.append(f"  loaded module: {nvidia_module}")
            if nvidia_packages:
                for name, version in nvidia_packages:
                    latest = self._latest_version_for(name, kernel_updates)
                    lines.append(f"  {self._package_line(name, version, latest)}")
            else:
                lines.append("  no tracked NVIDIA package installed")
        return lines

    def _collect_update_backlog(self, source: str) -> list[str]:
        state = self._package_state_snapshot()
        lines = self._package_refresh_lines(state)
        rows, meta_notes = self._pending_update_rows(state)
        filtered_rows = [row for row in rows if row.source == source]
        sorted_rows = self._sorted_pending_rows(filtered_rows)
        repo_count = len(state.official_updates) if not state.official_error else None
        aur_count = len(state.aur_updates) if not state.aur_error else None

        if self.supports_aur:
            if state.official_error or state.aur_error:
                total_summary = "unknown"
            else:
                total_summary = str(len(state.official_updates) + len(state.aur_updates))
        else:
            total_summary = "unknown" if state.official_error else str(len(state.official_updates))
        sort_label = "size desc" if self.package_sort_mode == "size" else "name asc"
        lines.append(f"Sort: {sort_label} | press s to toggle size/name")
        if self.supports_aur:
            lines.append(
                "Backlog: "
                + f"{total_summary} total | {repo_count if repo_count is not None else '?'} repo"
                + f" | {aur_count if aur_count is not None else '?'} AUR"
            )
        else:
            lines.append(
                "Backlog: "
                + f"{total_summary} total | {repo_count if repo_count is not None else '?'} repo"
            )

        if source == "repo":
            if state.official_error:
                lines.append(f"Repo backlog: unavailable ({state.official_error})")
            else:
                lines.append(f"Repo backlog: {len(state.official_updates)} packages")
        else:
            if state.aur_error:
                lines.append(f"AUR backlog: unavailable ({state.aur_error})")
            else:
                lines.append(f"AUR backlog: {len(state.aur_updates)} packages")

        known_download_total = sum(row.download_size or 0 for row in filtered_rows)
        known_installed_total = sum(row.installed_size or 0 for row in filtered_rows)
        known_download_count = sum(1 for row in filtered_rows if row.download_size is not None)
        known_installed_count = sum(1 for row in filtered_rows if row.installed_size is not None)
        if filtered_rows:
            lines.append(
                "Known download size: "
                + f"{format_bytes(known_download_total)} across {known_download_count}/{len(filtered_rows)} packages"
            )
            lines.append(
                "Known installed footprint: "
                + f"{format_bytes(known_installed_total)} across {known_installed_count}/{len(filtered_rows)} packages"
            )
            estimate_seconds = (
                known_download_total / PACKAGE_EST_DOWNLOAD_BYTES_PER_SEC
                + (len(filtered_rows) * (5 if source == "repo" else PACKAGE_EST_AUR_SECONDS))
            )
            per_pkg_label = "5s per repo package" if source == "repo" else f"{PACKAGE_EST_AUR_SECONDS}s per AUR package"
            estimate_line = f"Estimated update time: ~{format_eta(estimate_seconds)} (10 MiB/s + {per_pkg_label})"
            if known_download_count < len(filtered_rows):
                lines.append("? " + estimate_line + " with partial size data")
            else:
                lines.append(estimate_line)
        else:
            lines.append("Known download size: 0 B across 0/0 packages")
            lines.append("Known installed footprint: 0 B across 0/0 packages")
            lines.append("Estimated update time: 0s")

        if meta_notes and filtered_rows:
            lines.append("? Size metadata: " + " | ".join(meta_notes))

        if sorted_rows:
            lines.append("Updates:")
            for row in sorted_rows:
                source_label = "[repo]" if row.source == "repo" else "[AUR]"
                size_parts = []
                if row.download_size is not None:
                    size_parts.append(f"dl {format_bytes(row.download_size)}")
                if row.installed_size is not None:
                    size_parts.append(f"installed {format_bytes(row.installed_size)}")
                if not size_parts:
                    size_parts.append("size ?")
                lines.append(
                    "  "
                    + shorten(
                        f"{source_label} {row.name} {row.current} -> {row.latest} | " + " | ".join(size_parts),
                        160,
                    )
                )
        elif source == "repo" and not state.official_error:
            lines.append("Updates: none")
        elif source == "aur" and not state.aur_error:
            lines.append("Updates: none")
        return lines

    def collect_pending_updates(self) -> list[str]:
        return self._collect_update_backlog("repo")

    def collect_aur_updates(self) -> list[str]:
        return self._collect_update_backlog("aur")

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

        if self.nvidia_monitoring_enabled():
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
