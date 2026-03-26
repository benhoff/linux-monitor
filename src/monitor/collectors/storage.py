from __future__ import annotations

import time
from pathlib import Path

from monitor.shared.command import run_command
from monitor.shared.constants import PSEUDO_FILESYSTEMS
from monitor.shared.formatting import format_bytes
from monitor.shared.text import parse_int, read_lines


WATCHED_DIRS = (
    Path("/var/log"),
    Path("/var/cache"),
    Path("/var/tmp"),
    Path("/tmp"),
    Path("/var/lib/docker"),
    Path("/var/lib/systemd/coredump"),
    Path.home() / ".cache",
)


class StorageCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def filesystem_usage(self) -> list[dict[str, str | int]]:
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

    def inode_usage(self) -> dict[str, int]:
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

    def mount_summary(self) -> list[str]:
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
        mounts.sort(key=self.mount_sort_key)
        return mounts

    @staticmethod
    def mount_sort_key(item: str) -> tuple[int, str]:
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
    def filesystem_sort_key(entry: dict[str, str | int]) -> tuple[int, str]:
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
    def storage_severity(pct: int, inode_pct: int | None) -> str:
        inode_value = inode_pct if inode_pct is not None else 0
        highest = max(pct, inode_value)
        if highest >= 90:
            return "critical"
        if highest >= 75:
            return "watch"
        return "healthy"

    @staticmethod
    def abbreviate_path(path: str) -> str:
        home = str(Path.home())
        if path.startswith(home):
            return "~" + path[len(home) :]
        return path

    def directory_sizes(self) -> list[tuple[str, int]]:
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

    def read_diskstats(self) -> dict[str, tuple[int, int]]:
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

    def disk_rates(self) -> tuple[float, float, list[tuple[str, float]]]:
        now = time.time()
        current = self.read_diskstats()
        if self.backend.disk_prev is None:
            previous = current
            time.sleep(0.15)
            now = time.time()
            current = self.read_diskstats()
            previous_time = now - 0.15
        else:
            previous_time, previous = self.backend.disk_prev
        self.backend.disk_prev = (now, current)
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

    def collect(self) -> list[str]:
        lines: list[str] = []
        fs_entries = self.filesystem_usage()
        inode_usage = self.inode_usage()
        dir_sizes = self.backend.cached("dir_sizes", 300.0, self.directory_sizes)
        read_rate, write_rate, busy_devices = self.disk_rates()

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

        ordered_entries = sorted(fs_entries, key=self.filesystem_sort_key)
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
            if self.storage_severity(int(entry["pct"]), inode_pct) != "healthy":
                display_entries.append(entry)

        healthy_count = 0
        watch_count = 0
        critical_count = 0
        for entry in fs_entries:
            severity = self.storage_severity(int(entry["pct"]), inode_usage.get(str(entry["target"])))
            if severity == "critical":
                critical_count += 1
            elif severity == "watch":
                watch_count += 1
            else:
                healthy_count += 1

        lines.append(f"Filesystems: {healthy_count} healthy | {watch_count} watch | {critical_count} critical")

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
            lines.append(f"Disk IO: read {format_bytes(read_rate)}/s | write {format_bytes(write_rate)}/s")
        active_devices = [(name, rate) for name, rate in busy_devices if rate >= 512 * 1024]
        if active_devices:
            lines.append(
                "Active devices: " + ", ".join(f"{name} {format_bytes(rate)}/s" for name, rate in active_devices)
            )

        noisy_dirs = [(path, size) for path, size in dir_sizes if size >= 1024**3]
        if noisy_dirs:
            lines.append(
                "Growth suspects: "
                + ", ".join(
                    f"{self.abbreviate_path(path)} {format_bytes(size)}" for path, size in noisy_dirs[:3]
                )
            )
        else:
            lines.append("Growth suspects: none above 1 GiB in watched paths.")
        return lines
