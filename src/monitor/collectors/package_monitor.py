from __future__ import annotations

import hashlib
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Sequence

from monitor.shared.command import run_command
from monitor.shared.formatting import format_bytes, format_eta, parse_size_bytes, single_line
from monitor.shared.text import line_list, parse_int, read_lines, read_text, shorten


PACKAGE_REFRESH_INTERVAL = 900
PACKAGE_METADATA_INTERVAL = 600
PACKAGE_EST_DOWNLOAD_BYTES_PER_SEC = 10 * 1024 * 1024
PACKAGE_EST_AUR_SECONDS = 45
KERNEL_PACKAGE_NAMES = ("linux", "linux-lts", "linux-zen", "linux-hardened")
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


class PackageMonitor:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def start_worker(self) -> None:
        if not self.backend.package_monitoring_enabled():
            return
        if self.backend.package_worker_started:
            return
        self.backend.package_worker_started = True
        self.backend.package_stop_event.clear()
        self.backend.package_force_event.set()
        self.backend.package_worker = threading.Thread(target=self.package_refresh_loop, daemon=True)
        self.backend.package_worker.start()

    def stop_worker(self) -> None:
        self.backend.package_stop_event.set()
        self.backend.package_force_event.set()
        if self.backend.package_worker is not None:
            self.backend.package_worker.join(timeout=1.0)
            self.backend.package_worker = None
        self.backend.package_worker_started = False

    def request_refresh(self) -> None:
        self.backend.package_force_event.set()

    def cycle_sort_mode(self) -> str:
        self.backend.package_sort_mode = "name" if self.backend.package_sort_mode == "size" else "size"
        return self.backend.package_sort_mode

    def package_refresh_loop(self) -> None:
        next_refresh = 0.0
        while not self.backend.package_stop_event.is_set():
            now = time.time()
            if self.backend.package_force_event.is_set() or now >= next_refresh:
                self.backend.package_force_event.clear()
                self.refresh_state_sync()
                next_refresh = time.time() + PACKAGE_REFRESH_INTERVAL
                continue
            timeout = max(min(next_refresh - now, 1.0), 0.1)
            self.backend.package_force_event.wait(timeout=timeout)

    @staticmethod
    def parse_update_map(lines: Sequence[str]) -> dict[str, tuple[str, str]]:
        updates: dict[str, tuple[str, str]] = {}
        for raw in lines:
            match = re.match(r"^(\S+)\s+(\S+)\s+->\s+(\S+)$", raw)
            if not match:
                continue
            name, current, latest = match.groups()
            updates[name] = (current, latest)
        return updates

    @staticmethod
    def filter_installed_updates(
        updates: dict[str, tuple[str, str]],
        installed: Sequence[str],
    ) -> dict[str, tuple[str, str]]:
        installed_names = set(installed)
        return {name: versions for name, versions in updates.items() if name in installed_names}

    def refresh_state_sync(self) -> None:
        if not self.backend.package_monitoring_enabled():
            with self.backend.package_lock:
                self.backend.package_state = PackageRefreshState(
                    loading=False,
                    last_updated=time.time(),
                    official_updates={},
                    aur_updates={},
                    official_error="package monitoring is only implemented for pacman systems",
                    aur_error=None,
                )
            return
        with self.backend.package_lock:
            previous = self.backend.package_state
            self.backend.package_state = PackageRefreshState(
                loading=True,
                last_updated=previous.last_updated,
                official_updates=previous.official_updates,
                aur_updates=previous.aur_updates,
                official_error=previous.official_error,
                aur_error=previous.aur_error,
            )
        official_lines, official_error = self.official_updates()
        aur_lines: list[str] = []
        aur_error: str | None = None
        if self.backend.supports_aur:
            aur_lines, aur_error = self.aur_updates()
        installed_packages = self.installed_packages()
        official_updates = self.filter_installed_updates(self.parse_update_map(official_lines), installed_packages)
        aur_updates = self.filter_installed_updates(self.parse_update_map(aur_lines), installed_packages)
        with self.backend.package_lock:
            self.backend.package_state = PackageRefreshState(
                loading=False,
                last_updated=time.time(),
                official_updates=official_updates,
                aur_updates=aur_updates,
                official_error=official_error,
                aur_error=aur_error,
            )

    def package_state_snapshot(self) -> PackageRefreshState:
        if not self.backend.package_monitoring_enabled():
            return PackageRefreshState(
                loading=False,
                last_updated=time.time(),
                official_updates={},
                aur_updates={},
                official_error="package monitoring is only implemented for pacman systems",
                aur_error=None,
            )
        if not self.backend.package_worker_started and self.backend.package_state.last_updated == 0.0:
            self.refresh_state_sync()
        with self.backend.package_lock:
            return PackageRefreshState(
                loading=self.backend.package_state.loading,
                last_updated=self.backend.package_state.last_updated,
                official_updates=dict(self.backend.package_state.official_updates),
                aur_updates=dict(self.backend.package_state.aur_updates),
                official_error=self.backend.package_state.official_error,
                aur_error=self.backend.package_state.aur_error,
            )

    def package_refresh_lines(self, state: PackageRefreshState) -> list[str]:
        lines: list[str] = []
        source_label = {
            "pacman": "pacman/checkupdates",
            "apt": "apt package metadata",
        }.get(self.backend.package_backend, "package metadata")
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
    def package_meta_cache_key(prefix: str, updates: dict[str, tuple[str, str]]) -> str:
        digest = hashlib.sha1(
            "\n".join(
                f"{name}\t{current}\t{latest}"
                for name, (current, latest) in sorted(updates.items())
            ).encode("utf-8")
        ).hexdigest()
        return f"{prefix}:{digest}"

    @staticmethod
    def parse_info_blocks(text: str) -> list[dict[str, str]]:
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

    def repo_update_metadata(self, updates: dict[str, tuple[str, str]]) -> tuple[dict[str, dict[str, int | str | None]], str | None]:
        if not updates:
            return {}, None
        names = sorted(updates)
        timeout = min(max(8.0, len(names) * 0.4), 30.0)
        if self.backend.package_backend == "pacman":
            result = run_command(["pacman", "-Si", *names], timeout=timeout)
            if not result.stdout:
                if result.missing:
                    return {}, "pacman not found"
                if result.timed_out:
                    return {}, "pacman -Si timed out"
                if result.stderr:
                    return {}, shorten(single_line(result.stderr), 120)
                return {}, "pacman -Si returned no data"
        elif self.backend.package_backend == "apt":
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
        for block in self.parse_info_blocks(result.stdout):
            name = block.get("Name")
            if not name:
                continue
            if self.backend.package_backend == "pacman":
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

    def aur_update_metadata(self, updates: dict[str, tuple[str, str]]) -> tuple[dict[str, dict[str, int | str | None]], str | None]:
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
        for block in self.parse_info_blocks(result.stdout):
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

    def pending_update_rows(self, state: PackageRefreshState) -> tuple[list[PackageUpdateRow], list[str]]:
        notes: list[str] = []
        repo_meta: dict[str, dict[str, int | str | None]] = {}
        aur_meta: dict[str, dict[str, int | str | None]] = {}
        if state.official_updates and not state.official_error:
            repo_meta, repo_error = self.backend.cached(
                self.package_meta_cache_key("repo_meta", state.official_updates),
                PACKAGE_METADATA_INTERVAL,
                lambda: self.repo_update_metadata(state.official_updates),
            )
            if repo_error:
                notes.append(f"repo size metadata unavailable ({repo_error})")
        if state.aur_updates and not state.aur_error:
            aur_meta, aur_error = self.backend.cached(
                self.package_meta_cache_key("aur_meta", state.aur_updates),
                PACKAGE_METADATA_INTERVAL,
                lambda: self.aur_update_metadata(state.aur_updates),
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

    def sorted_pending_rows(self, rows: Sequence[PackageUpdateRow]) -> list[PackageUpdateRow]:
        if self.backend.package_sort_mode == "name":
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

    def installed_packages(self) -> dict[str, str]:
        packages: dict[str, str] = {}
        if self.backend.package_backend == "pacman":
            result = run_command(["pacman", "-Q"], timeout=6.0)
            for raw in line_list(result.stdout):
                parts = raw.split(None, 1)
                if len(parts) != 2:
                    continue
                packages[parts[0]] = parts[1]
            return packages
        if self.backend.package_backend == "apt":
            result = run_command(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], timeout=10.0)
            for raw in line_list(result.stdout):
                parts = raw.split(None, 1)
                if len(parts) != 2:
                    continue
                packages[parts[0]] = parts[1]
        return packages

    def running_kernel_version(self) -> str:
        result = run_command(["uname", "-r"], timeout=2.0)
        return result.stdout.splitlines()[0] if result.stdout else "unavailable"

    def nvidia_module_version(self) -> str:
        text = read_text(Path("/proc/driver/nvidia/version"))
        match = re.search(r"NVRM version: .*?\s(\d+\.\d+\.\d+)\s+Release Build", text)
        if match:
            return match.group(1)
        return "unavailable"

    def tracked_kernel_packages(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        if self.backend.package_backend == "pacman":
            return [(name, installed[name]) for name in KERNEL_PACKAGE_NAMES if name in installed]
        if self.backend.package_backend == "apt":
            running_kernel_pkg = f"linux-image-{self.running_kernel_version()}"
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

    def tracked_firmware_versions(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        if self.backend.package_backend == "pacman":
            versions = sorted({version for name, version in installed.items() if name.startswith(FIRMWARE_PACKAGE_PREFIXES)})
            rows: list[tuple[str, str]] = []
            if versions:
                rows.append(("linux-firmware*", versions[0] if len(versions) == 1 else ", ".join(versions)))
            for name in FIRMWARE_PACKAGE_NAMES:
                if name in installed:
                    rows.append((name, installed[name]))
            return rows
        if self.backend.package_backend == "apt":
            rows: list[tuple[str, str]] = []
            for name in ("linux-firmware", "intel-microcode", "amd64-microcode"):
                if name in installed:
                    rows.append((name, installed[name]))
            return rows
        return []

    def tracked_nvidia_packages(self, installed: dict[str, str]) -> list[tuple[str, str]]:
        if self.backend.package_backend == "pacman":
            return [(name, installed[name]) for name in NVIDIA_PACKAGE_NAMES if name in installed]
        if self.backend.package_backend == "apt":
            rows = [
                (name, version)
                for name, version in installed.items()
                if name.startswith(("nvidia-driver-", "nvidia-utils-", "linux-modules-nvidia-"))
            ]
            rows.sort(key=lambda item: item[0])
            return rows[:8]
        return []

    @staticmethod
    def package_line(name: str, installed_version: str, latest_version: str | None) -> str:
        if latest_version and latest_version != installed_version:
            return f"{name}: {installed_version} -> {latest_version}"
        return f"{name}: {installed_version} current"

    @staticmethod
    def latest_version_for(name: str, updates: dict[str, tuple[str, str]]) -> str | None:
        if name in updates:
            return updates[name][1]
        if name == "linux-firmware*" and "linux-firmware" in updates:
            return updates["linux-firmware"][1]
        return None

    def command_lines(self, primary: Sequence[str], fallback: Sequence[str] | None = None, timeout: float = 6.0) -> tuple[list[str], str | None]:
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

    def official_updates(self) -> tuple[list[str], str | None]:
        if self.backend.package_backend == "apt":
            result = run_command(["apt", "list", "--upgradable"], timeout=12.0)
            if result.stdout:
                lines: list[str] = []
                for raw in result.stdout.splitlines():
                    line = raw.strip()
                    if not line or line.lower().startswith("listing"):
                        continue
                    match = re.match(r"^([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: (\S+)\]$", line)
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
        if self.backend.package_backend != "pacman":
            return [], "repo update monitoring is unavailable for this package backend"
        return self.command_lines(["checkupdates"], fallback=["pacman", "-Qu"], timeout=8.0)

    def aur_updates(self) -> tuple[list[str], str | None]:
        if not self.backend.supports_aur:
            return [], None
        return self.command_lines(["yay", "-Qua"], timeout=12.0)

    def count_explicit(self) -> tuple[int | None, str | None]:
        if self.backend.package_backend == "apt":
            return self.count_command_lines(["apt-mark", "showmanual"], timeout=6.0)
        if self.backend.package_backend != "pacman":
            return None, "explicit package count is only implemented for pacman systems"
        return self.count_command_lines(["pacman", "-Qe"])

    def count_dependencies(self) -> tuple[int | None, str | None]:
        if self.backend.package_backend == "apt":
            return self.count_command_lines(["apt-mark", "showauto"], timeout=6.0)
        if self.backend.package_backend != "pacman":
            return None, "dependency package count is only implemented for pacman systems"
        return self.count_command_lines(["pacman", "-Qd"])

    def orphan_packages(self) -> tuple[list[str], str | None]:
        if self.backend.package_backend == "apt":
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
        if self.backend.package_backend != "pacman":
            return [], "orphan detection is unavailable for this package backend"
        return self.command_lines(["pacman", "-Qtdq"])

    def foreign_packages(self) -> tuple[list[str], str | None]:
        if self.backend.package_backend != "pacman":
            return [], "foreign package detection is only implemented for pacman systems"
        return self.command_lines(["pacman", "-Qm"])

    def ignored_packages(self) -> list[str]:
        if self.backend.package_backend == "apt":
            result = run_command(["apt-mark", "showhold"], timeout=4.0)
            return line_list(result.stdout)
        if self.backend.package_backend != "pacman":
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

    def recent_upgrades(self) -> list[str]:
        if self.backend.package_backend != "pacman":
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
        installed = self.backend.cached("installed_packages", 30.0, self.installed_packages)
        foreign: list[str] = []
        foreign_error: str | None = None
        if self.backend.package_backend == "pacman":
            foreign, foreign_error = self.backend.cached("foreign", 900.0, self.foreign_packages)
        ignored = self.backend.cached("ignored", 1800.0, self.ignored_packages)
        explicit_count, explicit_error = self.backend.cached("count_explicit", 900.0, self.count_explicit)
        dependency_count, dependency_error = self.backend.cached("count_dependencies", 900.0, self.count_dependencies)
        running_kernel = self.running_kernel_version()
        nvidia_module = self.nvidia_module_version()
        state = self.package_state_snapshot()
        lines: list[str] = []
        total_pending = len(state.official_updates) + len(state.aur_updates)
        lines.extend(self.package_refresh_lines(state))
        kernel_updates = {**state.aur_updates, **state.official_updates}
        kernel_packages = self.tracked_kernel_packages(installed)
        firmware_packages = self.tracked_firmware_versions(installed)
        nvidia_packages = self.tracked_nvidia_packages(installed)
        tracked_rows = [*kernel_packages, *firmware_packages, *nvidia_packages]
        tracked_outdated = sum(
            1
            for name, version in tracked_rows
            if (latest := self.latest_version_for(name, kernel_updates)) is not None and latest != version
        )
        lines.append("Summary:")
        repo_summary = "?" if state.official_error else str(len(state.official_updates))
        if self.backend.supports_aur:
            aur_summary = "?" if state.aur_error else str(len(state.aur_updates))
            total_summary = "unknown" if state.official_error or state.aur_error else str(total_pending)
            lines.append(f"  Pending updates: {total_summary} total | {repo_summary} repo | {aur_summary} AUR")
        else:
            total_summary = "unknown" if state.official_error else str(len(state.official_updates))
            lines.append(f"  Pending updates: {total_summary} repo")
        if self.backend.package_backend == "pacman":
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
                latest = self.latest_version_for(name, kernel_updates)
                lines.append(f"  {self.package_line(name, version, latest)}")
        else:
            lines.append("  no tracked kernel package installed")
        lines.append("Firmware:")
        if firmware_packages:
            for name, version in firmware_packages:
                latest = self.latest_version_for(name, kernel_updates)
                lines.append(f"  {self.package_line(name, version, latest)}")
        else:
            lines.append("  no tracked firmware package installed")
        if self.backend.nvidia_monitoring_enabled() or nvidia_packages:
            lines.append("NVIDIA:")
            lines.append(f"  loaded module: {nvidia_module}")
            if nvidia_packages:
                for name, version in nvidia_packages:
                    latest = self.latest_version_for(name, kernel_updates)
                    lines.append(f"  {self.package_line(name, version, latest)}")
            else:
                lines.append("  no tracked NVIDIA package installed")
        return lines

    def collect_update_backlog(self, source: str) -> list[str]:
        state = self.package_state_snapshot()
        lines = self.package_refresh_lines(state)
        rows, meta_notes = self.pending_update_rows(state)
        filtered_rows = [row for row in rows if row.source == source]
        sorted_rows = self.sorted_pending_rows(filtered_rows)
        repo_count = len(state.official_updates) if not state.official_error else None
        aur_count = len(state.aur_updates) if not state.aur_error else None
        if self.backend.supports_aur:
            if state.official_error or state.aur_error:
                total_summary = "unknown"
            else:
                total_summary = str(len(state.official_updates) + len(state.aur_updates))
        else:
            total_summary = "unknown" if state.official_error else str(len(state.official_updates))
        sort_label = "size desc" if self.backend.package_sort_mode == "size" else "name asc"
        lines.append(f"Sort: {sort_label} | press s to toggle size/name")
        if self.backend.supports_aur:
            lines.append(
                "Backlog: "
                + f"{total_summary} total | {repo_count if repo_count is not None else '?'} repo"
                + f" | {aur_count if aur_count is not None else '?'} AUR"
            )
        else:
            lines.append("Backlog: " + f"{total_summary} total | {repo_count if repo_count is not None else '?'} repo")
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
