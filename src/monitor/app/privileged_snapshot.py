#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Sequence

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
        rows.append(f"{name}: {util}% util | {mem_used}/{mem_total} MiB | {temp} C | {power} W | {pstate}")
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
        mounts.append(f"{target} ({fstype}) {'ro' if 'ro' in options.split(',') else 'rw'}")
    return mounts[:12]


def fs_errors() -> list[str]:
    return command_lines(
        ["journalctl", "-b", f"--grep={FS_LOG_PATTERN}", "-n", "10", "--no-pager", "-o", "short-iso"],
        timeout=4.0,
        limit=10,
    )


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
        stats[iface.strip()] = {
            "link_quality": round(link, 1),
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


def parse_iw_station_dump(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("tx bitrate:"):
            number = parse_float(line)
            if number is not None:
                result["tx_bitrate_mbps"] = number
        elif line.startswith("rx bitrate:"):
            number = parse_float(line)
            if number is not None:
                result["rx_bitrate_mbps"] = number
        elif line.startswith("signal avg:"):
            number = parse_float(line)
            if number is not None:
                result["signal_avg_dbm"] = number
        elif line.startswith("tx retries:"):
            number = parse_float(line)
            if number is not None:
                result["tx_retries"] = number
        elif line.startswith("tx failed:"):
            number = parse_float(line)
            if number is not None:
                result["tx_failed"] = number
        elif line.startswith("beacon loss:"):
            number = parse_float(line)
            if number is not None:
                result["beacon_loss"] = number
    return result


def wifi_snapshot() -> dict[str, object]:
    state: dict[str, object] = {
        "interfaces": [],
        "rfkill": [],
        "journal": command_lines(
            ["journalctl", "-b", f"--grep={WIFI_LOG_PATTERN}", "-n", "10", "--no-pager", "-o", "short-iso"],
            timeout=4.0,
            limit=10,
        ),
    }
    wireless = parse_proc_net_wireless()
    for path in Path("/sys/class/net").iterdir():
        if not (path / "wireless").exists():
            continue
        name = path.name
        sysfs = path
        entry: dict[str, object] = {
            "name": name,
            "operstate": read_text(sysfs / "operstate").strip() or "unknown",
            "mac": read_text(sysfs / "address").strip() or "",
            "carrier": read_text(sysfs / "carrier").strip() == "1",
            "mtu": parse_int(read_text(sysfs / "mtu"), default=0),
        }
        if name in wireless:
            entry.update(wireless[name])

        info_result = run_command(["iw", "dev", name, "info"], timeout=3.0)
        if info_result is not None:
            for raw in info_result.stdout.splitlines():
                line = raw.strip()
                if line.startswith("ssid "):
                    entry["ssid"] = line.split(None, 1)[1].strip()
                elif line.startswith("type "):
                    entry["type"] = line.split(None, 1)[1].strip()
                elif line.startswith("channel "):
                    number = parse_int(line)
                    if number:
                        entry["channel"] = number
                elif line.startswith("txpower "):
                    number = parse_float(line)
                    if number is not None:
                        entry["txpower_dbm"] = number

        link_result = run_command(["iw", "dev", name, "link"], timeout=3.0)
        if link_result is not None and "Connected to" in link_result.stdout:
            entry["link"] = line_list(link_result.stdout)

        station_result = run_command(["iw", "dev", name, "station", "dump"], timeout=4.0)
        if station_result is not None and station_result.stdout:
            entry.update(parse_iw_station_dump(station_result.stdout))

        power_save_result = run_command(["iw", "dev", name, "get", "power_save"], timeout=3.0)
        if power_save_result is not None:
            entry["power_save"] = line_list(power_save_result.stdout)

        state["interfaces"].append(entry)

    rfkill_result = run_command(["rfkill", "list"], timeout=3.0)
    if rfkill_result is not None:
        current: dict[str, object] | None = None
        for raw in rfkill_result.stdout.splitlines():
            if re.match(r"^\d+:", raw):
                if current:
                    state["rfkill"].append(current)
                current = {"name": raw.split(":", 1)[1].strip()}
            elif current is not None:
                line = raw.strip()
                if line.startswith("Soft blocked:"):
                    current["soft_blocked"] = line.endswith("yes")
                elif line.startswith("Hard blocked:"):
                    current["hard_blocked"] = line.endswith("yes")
                elif line.startswith("Type:"):
                    current["type"] = line.split(":", 1)[1].strip()
        if current:
            state["rfkill"].append(current)
    return state


def snapshot_payload() -> dict[str, object]:
    system_state = run_command(["systemctl", "is-system-running"], timeout=3.0)
    route_result = run_command(["ip", "route", "show", "default"], timeout=3.0)
    dns_check_result = run_command(["getent", "ahosts", "archlinux.org"], timeout=3.0)
    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "generated_at": time.time(),
        "hostname": os.uname().nodename,
        "systemd": {
            "state": line_list(system_state.stdout)[0] if system_state and system_state.stdout else "unknown",
            "failed_services": command_lines(
                ["systemctl", "--failed", "--type=service", "--no-legend", "--no-pager"],
                timeout=4.0,
                limit=12,
            ),
            "enabled_services": command_lines(
                ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"],
                timeout=4.0,
                limit=30,
            ),
            "disabled_services": command_lines(
                ["systemctl", "list-unit-files", "--type=service", "--state=disabled", "--no-legend", "--no-pager"],
                timeout=4.0,
                limit=30,
            ),
        },
        "logs": {
            "journal_errors": command_lines(
                ["journalctl", "-b", "-p", "err", "-n", "10", "--no-pager", "-o", "short-iso"],
                timeout=4.0,
                limit=10,
            ),
            "kernel_warnings": command_lines(
                ["journalctl", "-k", "-b", "-p", "warning", "-n", "10", "--no-pager", "-o", "short-monotonic"],
                timeout=4.0,
                limit=10,
            ),
            "hardware_hints": command_lines(
                ["journalctl", "-b", f"--grep={HARDWARE_LOG_PATTERN}", "-n", "10", "--no-pager", "-o", "short-iso"],
                timeout=4.0,
                limit=10,
            ),
        },
        "hardware": {
            "smart": smart_summary(),
            "gpu": gpu_telemetry(),
            "gpu_processes": gpu_processes(),
            "device_counts": device_counts(),
        },
        "network": {
            "default_route": line_list(route_result.stdout)[0] if route_result and route_result.stdout else "",
            "dns_servers": dns_servers(),
            "dns_check_ok": bool(dns_check_result and dns_check_result.stdout),
            "socket_counts": socket_counts(),
            "listening_sockets": listening_sockets(),
        },
        "filesystem": {
            "visible_mounts": visible_mounts(),
            "read_only_mounts": detect_ro_mounts(),
            "fs_errors": fs_errors(),
        },
        "wifi": wifi_snapshot(),
        "security": {
            "failed_logins": command_lines(
                ["journalctl", "-b", "--grep=Failed password|authentication failure|FAILED LOGIN", "-n", "8", "--no-pager", "-o", "short-iso"],
                timeout=4.0,
                limit=8,
            ),
            "sudo_usage": command_lines(
                ["journalctl", "-b", "SYSLOG_IDENTIFIER=sudo", "-n", "5", "--no-pager", "-o", "short-iso"],
                timeout=4.0,
                limit=5,
            ),
        },
    }


def atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temp_path = Path(handle.name)
    temp_path.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a privileged JSON snapshot for monitor")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="JSON output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    atomic_write_json(args.output, snapshot_payload())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
