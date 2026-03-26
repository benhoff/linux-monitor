#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

SRC_DIR = Path(__file__).resolve().parent / "src"
if SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from monitor.shared.constants import (
    DEFAULT_PRIVILEGED_SNAPSHOT_PATH,
    FS_LOG_PATTERN,
    HARDWARE_LOG_PATTERN,
    PRIVILEGED_SNAPSHOT_VERSION,
    PSEUDO_FILESYSTEMS,
    WIFI_LOG_PATTERN,
)
from monitor.shared.text import line_list as shared_line_list
from monitor.shared.text import parse_float, parse_int, read_text

DEFAULT_OUTPUT = DEFAULT_PRIVILEGED_SNAPSHOT_PATH
SNAPSHOT_VERSION = PRIVILEGED_SNAPSHOT_VERSION


def run_command(args: Sequence[str], timeout: float = 6.0) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def line_list(text: str, limit: int | None = None) -> list[str]:
    return shared_line_list(text, limit=limit, skip_no_entries=True)


def command_lines(args: Sequence[str], timeout: float = 6.0, limit: int | None = None) -> list[str]:
    result = run_command(args, timeout=timeout)
    if result is None:
        return []
    return line_list(result.stdout, limit=limit)


def detect_ro_mounts() -> list[str]:
    mounts = []
    result = run_command(["findmnt", "-rn", "-o", "TARGET,OPTIONS"], timeout=3.0)
    if result is None:
        return mounts
    for raw in result.stdout.splitlines():
        parts = raw.split(None, 1)
        if len(parts) != 2:
            continue
        target, options = parts
        if "ro" in options.split(","):
            mounts.append(target)
    return mounts


def dns_servers() -> str:
    resolvectl = run_command(["resolvectl", "dns"], timeout=3.0)
    if resolvectl is not None and resolvectl.stdout:
        servers = []
        for raw in resolvectl.stdout.splitlines():
            parts = raw.split(":", 1)
            if len(parts) == 2:
                servers.append(parts[1].strip())
        if servers:
            return " | ".join(servers[:4])
    nameservers = []
    for raw in read_text(Path("/etc/resolv.conf")).splitlines():
        if raw.startswith("nameserver "):
            nameservers.append(raw.split(None, 1)[1])
    return ", ".join(nameservers) if nameservers else "no nameservers found"


def smart_summary() -> list[str]:
    if shutil.which("smartctl") is None:
        return []
    devices = []
    scan = run_command(["smartctl", "--scan"], timeout=4.0)
    if scan is not None:
        for raw in line_list(scan.stdout):
            parts = raw.split()
            if parts:
                devices.append(parts[0])
    summaries = []
    for device in devices[:4]:
        result = run_command(["smartctl", "-H", "-A", device], timeout=8.0)
        if result is None:
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
    return summaries


def gpu_telemetry() -> list[str]:
    result = run_command(
        [
            "nvidia-smi",
            "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,pstate",
            "--format=csv,noheader,nounits",
        ],
        timeout=4.0,
    )
    if result is None:
        return []
    rows = []
    for raw in line_list(result.stdout):
        parts = [part.strip() for part in raw.split(",")]
        if len(parts) < 7:
            continue
        name, util, mem_used, mem_total, temp, power, pstate = parts[:7]
        rows.append(
            f"{name}: {util}% util | {mem_used}/{mem_total} MiB | {temp} C | {power} W | {pstate}"
        )
    return rows


def gpu_processes() -> list[str]:
    result = run_command(
        [
            "nvidia-smi",
            "--query-compute-apps=pid,process_name,used_memory",
            "--format=csv,noheader,nounits",
        ],
        timeout=4.0,
    )
    if result is None:
        return []
    rows = []
    for raw in line_list(result.stdout):
        parts = [part.strip() for part in raw.split(",")]
        if len(parts) >= 3:
            rows.append(f"pid {parts[0]} {parts[1]} {parts[2]} MiB")
    return rows


def device_counts() -> list[str]:
    rows = []
    lsusb = run_command(["lsusb"], timeout=3.0)
    if lsusb is not None and lsusb.stdout:
        rows.append(f"USB devices: {len(line_list(lsusb.stdout))}")
    lspci = run_command(["lspci"], timeout=3.0)
    if lspci is not None and lspci.stdout:
        rows.append(f"PCI devices: {len(line_list(lspci.stdout))}")
    return rows


def socket_counts() -> dict[str, int | None]:
    established = run_command(["ss", "-tun", "state", "established", "-H"], timeout=3.0)
    listening = run_command(["ss", "-ltnu", "-H"], timeout=3.0)
    return {
        "established": len(line_list(established.stdout)) if established is not None else None,
        "listening": len(line_list(listening.stdout)) if listening is not None else None,
    }


def listening_sockets() -> list[str]:
    result = run_command(["ss", "-ltnupH"], timeout=4.0)
    if result is None:
        return []
    rows = []
    for raw in line_list(result.stdout):
        parts = raw.split()
        if len(parts) < 5:
            continue
        rows.append(f"{parts[4]} {parts[-1]}")
    return rows[:8]


def visible_mounts() -> list[str]:
    result = run_command(["findmnt", "-rn", "-o", "TARGET,FSTYPE,OPTIONS"], timeout=3.0)
    if result is None:
        return []
    mounts = []
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
    return mounts


def wireless_interfaces() -> list[str]:
    root = Path("/sys/class/net")
    interfaces = []
    if not root.exists():
        return interfaces
    for path in sorted(root.iterdir()):
        if (path / "wireless").exists() or (path / "phy80211").exists():
            interfaces.append(path.name)
    return interfaces


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


def parse_proc_net_wireless() -> dict[str, dict[str, object]]:
    stats: dict[str, dict[str, object]] = {}
    lines = read_text(Path("/proc/net/wireless")).splitlines()
    for raw in lines[2:]:
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


def parse_rfkill_output(text: str) -> list[dict[str, object]]:
    radios: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        header = re.match(r"^\d+:\s+([^:]+):\s+(.+)$", line.strip())
        if header:
            if current and str(current.get("type", "")).lower() in {"wireless lan", "wlan", "wifi"}:
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
    if current and str(current.get("type", "")).lower() in {"wireless lan", "wlan", "wifi"}:
        radios.append(current)
    return radios


def wifi_logs() -> list[str]:
    return command_lines(
        ["journalctl", "-b", f"--grep={WIFI_LOG_PATTERN}", "-n", "10", "--no-pager", "-o", "short-iso"],
        timeout=5.0,
        limit=6,
    )


def wifi_snapshot() -> dict[str, object]:
    quality = parse_proc_net_wireless()
    interfaces: list[dict[str, object]] = []
    for name in wireless_interfaces():
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
        if info_result is not None and info_result.stdout:
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
        if link_result is not None and link_result.stdout:
            entry.update(parse_iw_link_output(link_result.stdout))

        station_result = run_command(["iw", "dev", name, "station", "dump"], timeout=4.0)
        if station_result is not None and station_result.stdout:
            entry.update(parse_iw_station_dump(station_result.stdout))

        power_save_result = run_command(["iw", "dev", name, "get", "power_save"], timeout=3.0)
        if power_save_result is not None and power_save_result.stdout:
            for raw in power_save_result.stdout.splitlines():
                line = raw.strip()
                if line.lower().startswith("power save:"):
                    entry["power_save"] = line.split(":", 1)[1].strip().lower()
                    break

        if name in quality:
            entry.update(quality[name])
        interfaces.append(entry)

    rfkill_result = run_command(["rfkill", "list"], timeout=3.0)
    radios = parse_rfkill_output(rfkill_result.stdout) if rfkill_result is not None and rfkill_result.stdout else []

    return {
        "interfaces": interfaces,
        "rfkill": radios,
        "logs": wifi_logs(),
    }


def collect_snapshot() -> dict[str, object]:
    system_state = run_command(["systemctl", "is-system-running"], timeout=3.0)
    enabled_units = command_lines(
        ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"],
        timeout=5.0,
    )
    disabled_units = command_lines(
        ["systemctl", "list-unit-files", "--type=service", "--state=disabled", "--no-legend", "--no-pager"],
        timeout=5.0,
    )
    route_result = run_command(["ip", "route", "show", "default"], timeout=3.0)
    dns_check_result = run_command(["getent", "ahosts", "archlinux.org"], timeout=3.0)
    default_route = route_result.stdout.splitlines()[0] if route_result and route_result.stdout else "no default route"
    dns_check = (
        dns_check_result.stdout.splitlines()[0].split()[0]
        if dns_check_result and dns_check_result.stdout
        else "resolution failed"
    )

    snapshot = {
        "snapshot_version": SNAPSHOT_VERSION,
        "snapshot_writer": os.path.abspath(__file__),
        "generated_at": time.time(),
        "systemd": {
            "state": line_list(system_state.stdout)[0] if system_state and system_state.stdout else "unknown",
            "failed_services": command_lines(
                ["systemctl", "--failed", "--type=service", "--no-legend", "--no-pager"],
                timeout=5.0,
                limit=8,
            ),
            "enabled_count": len(enabled_units),
            "disabled_count": len(disabled_units),
            "restart_hints": command_lines(
                [
                    "journalctl",
                    "-b",
                    "--grep=Scheduled restart job|Start request repeated too quickly",
                    "-n",
                    "8",
                    "--no-pager",
                ],
                timeout=5.0,
                limit=4,
            ),
        },
        "logs": {
            "journal_errors": command_lines(
                ["journalctl", "-b", "-p", "err", "-n", "10", "--no-pager", "-o", "short-iso"],
                timeout=5.0,
                limit=5,
            ),
            "kernel_warnings": command_lines(
                ["journalctl", "-k", "-b", "-p", "warning", "-n", "10", "--no-pager", "-o", "short-monotonic"],
                timeout=5.0,
                limit=5,
            ),
            "hardware_warnings": command_lines(
                ["journalctl", "-b", f"--grep={HARDWARE_LOG_PATTERN}", "-n", "10", "--no-pager", "-o", "short-iso"],
                timeout=5.0,
                limit=5,
            ),
        },
        "hardware": {
            "smart_summary": smart_summary(),
            "gpu_status": gpu_telemetry(),
            "gpu_processes": gpu_processes(),
            "device_counts": device_counts(),
        },
        "fs_integrity": {
            "ro_mounts": detect_ro_mounts(),
            "visible_mounts": visible_mounts(),
            "hints": command_lines(
                ["journalctl", "-b", f"--grep={FS_LOG_PATTERN}", "-n", "10", "--no-pager", "-o", "short-iso"],
                timeout=5.0,
                limit=6,
            ),
        },
        "network": {
            "interfaces": command_lines(["ip", "-brief", "address"], timeout=3.0, limit=8),
            "default_route": default_route,
            "dns_servers": dns_servers(),
            "dns_check": dns_check,
            "connections": socket_counts(),
        },
        "wifi": wifi_snapshot(),
        "security": {
            "listeners": listening_sockets(),
            "failed_logins": command_lines(
                ["journalctl", "-b", "--grep=Failed password|authentication failure|FAILED LOGIN", "-n", "8", "--no-pager", "-o", "short-iso"],
                timeout=5.0,
                limit=5,
            ),
            "sudo_usage": command_lines(
                ["journalctl", "-b", "SYSLOG_IDENTIFIER=sudo", "-n", "5", "--no-pager", "-o", "short-iso"],
                timeout=5.0,
                limit=5,
            ),
        },
    }
    return snapshot


def write_snapshot(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=path.parent, encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temp_path = Path(handle.name)
    os.chmod(temp_path, 0o644)
    os.replace(temp_path, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a privileged JSON snapshot for monitor_tui.py")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="JSON output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = collect_snapshot()
    write_snapshot(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
