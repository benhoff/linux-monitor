from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path

from monitor.shared.command import run_command
from monitor.shared.formatting import format_bytes, single_line, summarize_list
from monitor.shared.text import line_list, parse_int, read_lines, shorten


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
VM_IMAGE_DIRS = (
    Path("/var/lib/libvirt/images"),
    Path.home() / ".local/share/libvirt/images",
    Path.home() / "VirtualBox VMs",
)
VM_IMAGE_SUFFIXES = (".qcow2", ".img", ".vdi", ".vmdk", ".vhd", ".vhdx")
PACKAGE_CACHE_NOTICE_BYTES = 5 * 1024**3
PACKAGE_CACHE_NOTICE_AGE = 30 * 86400
LOG_DIR_NOTICE_BYTES = 2 * 1024**3
TEMP_NOTICE_BYTES = 512 * 1024**2
VM_IMAGE_NOTICE_BYTES = 10 * 1024**3


class HygieneCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    @staticmethod
    def _is_permission_note(note: str) -> bool:
        lowered = note.lower()
        return "failed to connect to system scope bus" in lowered or "operation not permitted" in lowered

    @staticmethod
    def _embedded_size_bytes(text: str) -> int | None:
        match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([kmgtpe]?)(?:i?b)?\b", text.strip(), re.IGNORECASE)
        if not match:
            return None
        amount = float(match.group(1))
        unit = match.group(2).upper()
        factors = {
            "": 1,
            "K": 1024,
            "M": 1024**2,
            "G": 1024**3,
            "T": 1024**4,
            "P": 1024**5,
            "E": 1024**6,
        }
        factor = factors.get(unit)
        if factor is None:
            return None
        return int(amount * factor)

    def path_size(self, path: Path, timeout: float = 6.0) -> int | None:
        if not path.exists():
            return None
        result = run_command(["du", "-sx", "-B1", str(path)], timeout=timeout)
        if not result.stdout:
            return None
        return parse_int(result.stdout.split()[0], default=-1)

    def package_cache_stats(self) -> dict[str, object]:
        path = self.backend.package_cache_path
        stats: dict[str, object] = {
            "label": self.backend.package_cache_label,
            "path": str(path) if path is not None else "",
            "size": None,
            "files": 0,
            "oldest_age": None,
        }
        if path is None or not path.exists():
            return stats
        stats["size"] = self.path_size(path, timeout=8.0)
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
                if self.backend.package_backend == "pacman" and ".pkg.tar" not in entry.name:
                    continue
                if self.backend.package_backend == "apt" and not entry.name.endswith(".deb"):
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

    def config_drift_files(self) -> tuple[list[str], str | None]:
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

    def count_crontab_lines(self, path: Path) -> int:
        count = 0
        for raw in read_lines(path):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and not re.match(r"^(@|\d|\*)", line):
                continue
            count += 1
        return count

    def cron_entry_count(self) -> int:
        count = 0
        for path in CRON_FILES:
            if path.exists():
                count += self.count_crontab_lines(path)
        for directory in (*CRON_DIRS, *CRON_SPOOL_DIRS):
            if not directory.exists():
                continue
            try:
                count += sum(1 for entry in directory.iterdir() if entry.is_file() and not entry.name.startswith("."))
            except OSError:
                continue
        return count

    def timer_hygiene(self) -> dict[str, object]:
        enabled_count, enabled_error = self.backend.count_command_lines(
            ["systemctl", "list-unit-files", "--type=timer", "--state=enabled", "--no-legend", "--no-pager"],
            timeout=5.0,
        )
        failed_lines, failed_error = self.backend.command_lines(
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
            "cron_count": self.cron_entry_count(),
        }

    def vm_image_inventory(self) -> list[tuple[str, int]]:
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

    def container_vm_hygiene(self) -> dict[str, object]:
        docker_data = self.path_size(Path("/var/lib/docker"), timeout=8.0)
        podman_root = self.path_size(Path("/var/lib/containers/storage"), timeout=8.0)
        podman_user = self.path_size(Path.home() / ".local/share/containers/storage", timeout=8.0)

        docker_exited: int | None = None
        docker_dangling_images: int | None = None
        docker_dangling_volumes: int | None = None
        if shutil.which("docker") is not None:
            docker_exited, _ = self.backend.count_command_lines(["docker", "ps", "-aq", "--filter", "status=exited"], timeout=5.0)
            docker_dangling_images, _ = self.backend.count_command_lines(["docker", "images", "-q", "--filter", "dangling=true"], timeout=5.0)
            docker_dangling_volumes, _ = self.backend.count_command_lines(["docker", "volume", "ls", "-q", "--filter", "dangling=true"], timeout=5.0)

        podman_exited: int | None = None
        podman_dangling_images: int | None = None
        if shutil.which("podman") is not None:
            podman_exited, _ = self.backend.count_command_lines(["podman", "ps", "-aq", "--filter", "status=exited"], timeout=5.0)
            podman_dangling_images, _ = self.backend.count_command_lines(["podman", "images", "-q", "--filter", "dangling=true"], timeout=5.0)

        vm_images = self.vm_image_inventory()
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

        details = [f"{self.backend._abbreviate_path(path)} {format_bytes(size)}" for path, size in vm_images[:3]]
        return {
            "summary": "Container / VM leftovers: " + (" | ".join(summary_parts) if summary_parts else "none obvious"),
            "details": details,
            "docker_data_bytes": docker_data,
            "docker_exited": docker_exited,
            "docker_dangling_images": docker_dangling_images,
            "docker_dangling_volumes": docker_dangling_volumes,
            "podman_root_bytes": podman_root,
            "podman_user_bytes": podman_user,
            "podman_exited": podman_exited,
            "podman_dangling_images": podman_dangling_images,
            "vm_count": len(vm_images),
            "vm_total_bytes": sum(size for _path, size in vm_images),
        }

    def journal_disk_usage(self) -> str:
        result = run_command(["journalctl", "--disk-usage"], timeout=3.0)
        if result.stdout:
            return result.stdout.replace("Archived and active journals take up ", "").strip(".")
        if result.missing:
            return "journalctl not found"
        if result.stderr:
            return shorten(single_line(result.stderr), 120)
        return "unavailable"

    def collect(self) -> list[str]:
        orphaned, orphan_error = self.backend.cached("orphans_hygiene", 900.0, self.backend._orphan_packages)
        package_cache = self.backend.cached("package_cache_stats", 300.0, self.package_cache_stats)
        dir_sizes = self.backend.cached("dir_sizes", 300.0, self.backend._directory_sizes)
        config_drift, config_error = self.backend.cached("config_drift_files", 600.0, self.config_drift_files)
        timer_hygiene = self.backend.cached("timer_hygiene", 300.0, self.timer_hygiene)
        container_vm = self.backend.cached("container_vm_hygiene", 600.0, self.container_vm_hygiene)
        log_dir = self.backend.cached("log_dir_size", 300.0, lambda: self.path_size(Path("/var/log")))
        tmp_dir = self.backend.cached("tmp_dir_size", 300.0, lambda: self.path_size(Path("/tmp")))
        var_tmp_dir = self.backend.cached("var_tmp_dir_size", 300.0, lambda: self.path_size(Path("/var/tmp")))
        journal_usage = self.backend.cached("journal_disk_usage", 300.0, self.journal_disk_usage)

        lines: list[str] = []
        if orphan_error:
            lines.append(f"Orphans: unavailable ({orphan_error})")
        if orphaned:
            lines.append(f"Orphans: {len(orphaned)}")
            lines.append(f"  {', '.join(orphaned[:10])}")
        if isinstance(package_cache, dict):
            cache_size = package_cache.get("size")
            cache_files = int(package_cache.get("files", 0))
            oldest_age = package_cache.get("oldest_age")
            cache_is_large = isinstance(cache_size, int) and cache_size >= PACKAGE_CACHE_NOTICE_BYTES
            cache_is_stale = isinstance(oldest_age, int) and oldest_age >= PACKAGE_CACHE_NOTICE_AGE
            if cache_is_large or cache_is_stale:
                cache_line = str(package_cache.get("label", self.backend.package_cache_label)) + ": " + (
                    format_bytes(cache_size) if isinstance(cache_size, int) and cache_size >= 0 else "unavailable"
                )
                if cache_files > 0:
                    cache_line += f" across {cache_files} file(s)"
                if isinstance(oldest_age, int) and oldest_age > 0:
                    cache_line += f" | oldest {self.backend._age_label(oldest_age)}"
                lines.append(cache_line)
        else:
            lines.append(self.backend.package_cache_label + ": unavailable")

        journal_size = self._embedded_size_bytes(str(journal_usage))
        if (
            isinstance(log_dir, int)
            and log_dir >= LOG_DIR_NOTICE_BYTES
        ) or (
            isinstance(journal_size, int)
            and journal_size >= LOG_DIR_NOTICE_BYTES
        ):
            parts = []
            if isinstance(log_dir, int) and log_dir >= 0:
                parts.append(f"/var/log {format_bytes(log_dir)}")
            if str(journal_usage).strip() and "unavailable" not in str(journal_usage).lower():
                parts.append(f"journal {journal_usage}")
            if parts:
                lines.append("Logs: " + " | ".join(parts))

        temp_parts = []
        if isinstance(tmp_dir, int) and tmp_dir >= TEMP_NOTICE_BYTES:
            temp_parts.append(f"/tmp {format_bytes(tmp_dir)}")
        if isinstance(var_tmp_dir, int) and var_tmp_dir >= TEMP_NOTICE_BYTES:
            temp_parts.append(f"/var/tmp {format_bytes(var_tmp_dir)}")
        if temp_parts:
            lines.append("Temp usage: " + ", ".join(temp_parts))

        if config_error:
            lines.append(f"Config drift: unavailable ({config_error})")
        elif config_drift:
            lines.append(f"Config drift: {len(config_drift)} tracked leftover file(s) under /etc")
            for item in config_drift[:4]:
                lines.append(f"  {item}")

        if isinstance(timer_hygiene, dict):
            enabled_count = timer_hygiene.get("enabled_count")
            enabled_display = str(enabled_count) if isinstance(enabled_count, int) else "n/a"
            failed_timers = timer_hygiene.get("failed_timers", [])
            no_next_run = timer_hygiene.get("no_next_run", [])
            cron_count = int(timer_hygiene.get("cron_count", 0))
            raw_timer_notes = [
                note
                for note in (
                    timer_hygiene.get("enabled_error"),
                    timer_hygiene.get("failed_error"),
                    timer_hygiene.get("timers_error"),
                )
                if isinstance(note, str) and note
            ]
            timer_notes = [note for note in raw_timer_notes if not self._is_permission_note(note)]
            failed_count = len(failed_timers) if isinstance(failed_timers, list) else 0
            no_next_count = len(no_next_run) if isinstance(no_next_run, list) else 0
            if failed_count or no_next_count or timer_notes:
                lines.append(
                    f"Scheduled tasks: {enabled_display} enabled timer(s) | "
                    f"{failed_count} failed | {cron_count} cron entry/file(s)"
                    + (f" ({', '.join(timer_notes)})" if timer_notes else "")
                )
            if isinstance(failed_timers, list) and failed_timers:
                lines.append(f"  Failed timers: {summarize_list(failed_timers, limit=3)}")
            if isinstance(no_next_run, list) and no_next_run:
                lines.append(f"  No next run: {summarize_list(no_next_run, limit=3)}")

        if isinstance(container_vm, dict):
            has_container_cleanup_issue = any(
                isinstance(container_vm.get(key), int) and int(container_vm.get(key) or 0) > 0
                for key in (
                    "docker_exited",
                    "docker_dangling_images",
                    "docker_dangling_volumes",
                    "podman_exited",
                    "podman_dangling_images",
                )
            )
            vm_total_bytes = container_vm.get("vm_total_bytes")
            show_vm_inventory = isinstance(vm_total_bytes, int) and vm_total_bytes >= VM_IMAGE_NOTICE_BYTES
            if has_container_cleanup_issue or show_vm_inventory:
                summary = str(container_vm.get("summary", "Container / VM leftovers: none obvious"))
                lines.append(summary)
                details = container_vm.get("details", [])
                if isinstance(details, list):
                    for item in details[:2]:
                        lines.append(f"  {shorten(str(item), 140)}")

        if not lines:
            return ["No notable cleanup pressure."]
        return lines
