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


DEFAULT_OUTPUT = Path("/run/monitor/privileged_snapshot.json")
SNAPSHOT_VERSION = 2
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
HARDWARE_LOG_PATTERN = r"gpu|drm|hdmi|edid|nvme|ata|usb|pci|v4l2|camera|csi"
FS_LOG_PATTERN = (
    r"EXT4-fs error|BTRFS|XFS|Buffer I/O error|I/O error|"
    r"read-only file system|Remounting filesystem read-only|mount failure|corrupt"
)


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
    lines = [line.strip() for line in text.splitlines() if line.strip() and line.strip() != "-- No entries --"]
    if limit is not None:
        return lines[:limit]
    return lines


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_int(value: str, default: int = 0) -> int:
    match = re.search(r"-?\d+", value)
    if not match:
        return default
    return int(match.group(0))


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
