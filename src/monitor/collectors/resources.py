from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

from monitor.shared.command import run_command
from monitor.shared.constants import FS_LOG_PATTERN
from monitor.shared.formatting import format_bytes, format_percent, single_line
from monitor.shared.parsing_journal import detect_ro_mounts, parse_journal_lines
from monitor.shared.text import line_list, parse_int, read_lines, read_text, shorten


THROTTLE_LOG_PATTERN = r"throttl|thermal"


class MemoryCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def meminfo(self) -> dict[str, int]:
        info: dict[str, int] = {}
        for raw in read_lines(Path("/proc/meminfo")):
            if ":" not in raw:
                continue
            key, rest = raw.split(":", 1)
            info[key] = parse_int(rest)
        return info

    def psi(self, path: Path) -> dict[str, dict[str, float]]:
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

    def collect(self) -> list[str]:
        info = self.meminfo()
        total = info.get("MemTotal", 0) * 1024
        available = info.get("MemAvailable", 0) * 1024
        free = info.get("MemFree", 0) * 1024
        buffers = info.get("Buffers", 0) * 1024
        cached = (info.get("Cached", 0) + info.get("SReclaimable", 0)) * 1024
        used = max(total - available, 0)
        swap_total = info.get("SwapTotal", 0) * 1024
        swap_free = info.get("SwapFree", 0) * 1024
        swap_used = max(swap_total - swap_free, 0)
        psi = self.psi(Path("/proc/pressure/memory"))
        oom_events = run_command(
            ["journalctl", "-b", "--grep=Out of memory|Killed process", "-n", "8", "--no-pager", "-o", "short-iso"],
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


class CpuCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def read_cpu_stat(self) -> dict[str, int]:
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

    def cpu_percentages(self) -> tuple[float, float, float]:
        now = time.time()
        current = self.read_cpu_stat()
        if not current:
            return 0.0, 0.0, 0.0
        if self.backend.cpu_prev is None:
            previous = current
            time.sleep(0.15)
            now = time.time()
            current = self.read_cpu_stat()
            previous_time = now - 0.15
        else:
            previous_time, previous = self.backend.cpu_prev
        self.backend.cpu_prev = (now, current)
        total_delta = max(current["total"] - previous.get("total", current["total"]), 1)
        user_pct = (current["user"] - previous.get("user", current["user"])) * 100.0 / total_delta
        system_pct = (current["system"] - previous.get("system", current["system"])) * 100.0 / total_delta
        iowait_pct = (current["iowait"] - previous.get("iowait", current["iowait"])) * 100.0 / total_delta
        return user_pct, system_pct, iowait_pct

    def cpu_frequency(self) -> str:
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

    def top_processes(self) -> list[str]:
        result = run_command(["ps", "-eo", "pid,comm,%cpu,%mem", "--sort=-%cpu", "--no-headers"], timeout=3.0)
        return line_list(result.stdout, limit=5)

    def collect(self) -> list[str]:
        loadavg = read_text(Path("/proc/loadavg")).split()
        user_pct, system_pct, iowait_pct = self.cpu_percentages()
        top_processes = self.top_processes()
        throttle_hints = run_command(
            ["journalctl", "-b", f"--grep={THROTTLE_LOG_PATTERN}", "-n", "6", "--no-pager", "-o", "short-monotonic"],
            timeout=4.0,
        )
        lines = [
            f"Load average: {' '.join(loadavg[:3]) if loadavg else 'unavailable'}",
            f"CPU usage: user {user_pct:.1f}% | system {system_pct:.1f}% | iowait {iowait_pct:.1f}%",
            f"CPU frequency: {self.cpu_frequency()}",
            "Top CPU processes:",
        ]
        for item in top_processes[:5]:
            lines.append(f"  {item}")
        lines.append("Throttle hints:")
        for item in parse_journal_lines(throttle_hints, limit=4):
            lines.append(f"  {item}")
        return lines


class ThermalCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def thermal_zones(self) -> list[str]:
        lines: list[str] = []
        for temp_path in sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp")):
            value = parse_int(read_text(temp_path))
            if value <= 0:
                continue
            type_path = temp_path.parent / "type"
            zone_type = read_text(type_path).strip() or temp_path.parent.name
            lines.append(f"{zone_type} {value / 1000:.1f} C")
        return lines

    def fans(self) -> list[str]:
        fans: list[str] = []
        for fan_path in sorted(Path("/sys/class/hwmon").glob("hwmon*/fan*_input")):
            rpm = parse_int(read_text(fan_path))
            if rpm <= 0:
                continue
            name_path = fan_path.parent / "name"
            hwmon_name = read_text(name_path).strip() or fan_path.parent.name
            fans.append(f"{hwmon_name}/{fan_path.stem} {rpm} RPM")
        return fans

    def power_state(self) -> list[str]:
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

    def gpu_telemetry(self) -> list[str]:
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
            telemetry.append(f"{name}: {util}% util | {mem_used}/{mem_total} MiB | {temp} C | {power} W | {pstate}")
        if telemetry:
            return telemetry
        if result.missing:
            return ["nvidia-smi not found."]
        if result.stderr:
            return [shorten(single_line(result.stderr), 140)]
        return ["No GPU telemetry available."]

    def collect(self) -> list[str]:
        lines = ["Thermal zones:"]
        zones = self.thermal_zones()
        if zones:
            for item in zones[:6]:
                lines.append(f"  {item}")
        else:
            lines.append("  No readable thermal zones.")
        fans = self.fans()
        lines.append("Fan speeds:")
        if fans:
            for item in fans[:6]:
                lines.append(f"  {item}")
        else:
            lines.append("  No readable fan sensors.")
        power_states = self.power_state()
        lines.append("Power supplies:")
        if power_states:
            for item in power_states[:4]:
                lines.append(f"  {item}")
        else:
            lines.append("  No battery or AC state exposed.")
        if self.backend.nvidia_monitoring_enabled():
            lines.append("GPU thermal / power:")
            for item in self.gpu_telemetry()[:4]:
                lines.append(f"  {item}")
        return lines


class HardwareCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def smart_devices(self) -> list[str]:
        result = run_command(["smartctl", "--scan"], timeout=4.0)
        devices = []
        for raw in line_list(result.stdout):
            parts = raw.split()
            if parts:
                devices.append(parts[0])
        return devices[:4]

    def smart_summary(self) -> list[str]:
        if shutil.which("smartctl") is None:
            return ["smartctl not found."]
        summaries: list[str] = []
        for device in self.backend.cached("smart_devices", 900.0, self.smart_devices):
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

    def gpu_processes(self) -> list[str]:
        result = run_command(
            ["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory", "--format=csv,noheader,nounits"],
            timeout=4.0,
        )
        rows = []
        for raw in line_list(result.stdout):
            parts = [part.strip() for part in raw.split(",")]
            if len(parts) >= 3:
                rows.append(f"pid {parts[0]} {parts[1]} {parts[2]} MiB")
        return rows

    def device_counts(self) -> list[str]:
        counts = []
        lsusb = run_command(["lsusb"], timeout=3.0)
        if lsusb.stdout:
            counts.append(f"USB devices: {len(line_list(lsusb.stdout))}")
        lspci = run_command(["lspci"], timeout=3.0)
        if lspci.stdout:
            counts.append(f"PCI devices: {len(line_list(lspci.stdout))}")
        return counts

    def collect(self) -> list[str]:
        privileged = self.backend._privileged_section("hardware")
        if privileged:
            lines = []
            snapshot_line = self.backend._privileged_snapshot_line()
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
        for item in self.backend.cached("smart_summary", 300.0, self.smart_summary)[:4]:
            lines.append(f"  {item}")
        lines.append("GPU status:")
        for item in self.backend.thermal.gpu_telemetry()[:3]:
            lines.append(f"  {item}")
        gpu_processes = self.gpu_processes()
        if gpu_processes:
            lines.append("GPU processes:")
            for item in gpu_processes[:4]:
                lines.append(f"  {item}")
        device_counts = self.backend.cached("device_counts", 120.0, self.device_counts)
        if device_counts:
            lines.append("Bus inventory:")
            for item in device_counts[:4]:
                lines.append(f"  {item}")
        return lines


class FilesystemIntegrityCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def collect(self) -> list[str]:
        privileged = self.backend._privileged_section("fs_integrity")
        if privileged:
            ro_mounts = privileged.get("ro_mounts", [])
            hints = privileged.get("hints", [])
            lines = []
            snapshot_line = self.backend._privileged_snapshot_line()
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
            ["journalctl", "-b", f"--grep={FS_LOG_PATTERN}", "-n", "10", "--no-pager", "-o", "short-iso"],
            timeout=5.0,
        )
        lines = [
            "Read-only mounts: " + (", ".join(ro_mounts) if ro_mounts else "none"),
            "Filesystem integrity hints:",
        ]
        for item in parse_journal_lines(journal_fs, limit=6):
            lines.append(f"  {item}")
        return lines
