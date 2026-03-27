from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from monitor.shared.constants import PRIVILEGED_SNAPSHOT_VERSION
from monitor.shared.formatting import format_bytes
from monitor.shared.paths import diff_snapshot_state_path, legacy_repo_diff_snapshot_path


class DiffSnapshotService:
    def __init__(self, backend: object, privileged_snapshots: object) -> None:
        self.backend = backend
        self.privileged_snapshots = privileged_snapshots

    @staticmethod
    def snapshot_path() -> Path:
        return diff_snapshot_state_path()

    @staticmethod
    def migrate_legacy_snapshot(target: Path) -> None:
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

    def load_snapshot(self) -> dict[str, object] | None:
        path = self.snapshot_path()
        self.migrate_legacy_snapshot(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if isinstance(data, dict):
            return data
        return None

    def write_snapshot(self, payload: dict[str, object]) -> None:
        path = self.snapshot_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            pass

    def current_state_digest(self) -> dict[str, object]:
        return self.backend.cached("current_state_digest", 10.0, self.build_state_digest)

    def build_state_digest(self) -> dict[str, object]:
        now = time.time()
        installed = self.backend.cached("installed_packages", 30.0, self.backend._installed_packages)
        with self.backend.package_lock:
            package_state = {
                "official_updates": dict(self.backend.package_state.official_updates),
                "aur_updates": dict(self.backend.package_state.aur_updates),
                "official_error": self.backend.package_state.official_error,
                "aur_error": self.backend.package_state.aur_error,
            }

        kernel_updates = {
            **package_state["aur_updates"],
            **package_state["official_updates"],
        }
        tracked_rows = self.backend._tracked_priority_packages(installed)
        tracked_outdated = sum(
            1
            for name, version in tracked_rows
            if (latest := self.backend._latest_version_for(name, kernel_updates)) is not None
            and latest != version
        )

        fs_entries = self.backend._filesystem_usage()
        inode_usage = self.backend._inode_usage()
        dir_sizes = self.backend.cached("dir_sizes", 300.0, self.backend._directory_sizes)
        root_entry = next((entry for entry in fs_entries if entry["target"] == "/"), None)
        healthy_count = 0
        watch_count = 0
        critical_count = 0
        for entry in fs_entries:
            severity = self.backend._storage_severity(
                int(entry["pct"]),
                inode_usage.get(str(entry["target"])),
            )
            if severity == "critical":
                critical_count += 1
            elif severity == "watch":
                watch_count += 1
            else:
                healthy_count += 1

        privileged_systemd = self.privileged_snapshots.section("systemd")
        system_state = "unknown"
        failed_services = None
        if privileged_systemd:
            system_state = str(privileged_systemd.get("state", "unknown"))
            failed = privileged_systemd.get("failed_services", [])
            failed_services = len(failed) if isinstance(failed, list) else None
        else:
            system_state = self.backend._systemd_state()
            failed_services = len(self.backend._failed_services())

        privileged_logs = self.privileged_snapshots.section("logs")
        journal_error_count = None
        if privileged_logs:
            errors = privileged_logs.get("journal_errors", [])
            journal_error_count = len(errors) if isinstance(errors, list) else None

        meminfo = self.backend._meminfo()
        mem_total = meminfo.get("MemTotal", 0) * 1024
        mem_available = meminfo.get("MemAvailable", 0) * 1024
        mem_used = max(mem_total - mem_available, 0)
        psi = self.backend._psi(Path("/proc/pressure/memory"))
        psi_full10 = float(psi.get("full", {}).get("avg10", 0.0))

        max_temp = 0.0
        for item in self.backend._thermal_zones():
            match = re.search(r"(-?\d+(?:\.\d+)?)\s*C", item)
            if match:
                max_temp = max(max_temp, float(match.group(1)))

        snapshot_health = self.privileged_snapshots.health()
        wifi_digest = self.backend._wifi_digest()
        bluetooth_digest = self.backend._bluetooth_digest()
        containers_digest = self.backend._docker_digest()

        capture_cards = self.backend.cached("capture_cards", 30.0, self.backend._capture_cards)
        avmatrix_cards = [card for card in capture_cards if "avmatrix" in card.lower()]
        capture_slots = self.backend._capture_slots(avmatrix_cards)
        v4l2_inventory = self.backend.cached("v4l2_inventory", 20.0, self.backend._v4l2_inventory)
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

        growth = {self.backend._abbreviate_path(path): size for path, size in dir_sizes[:5]}

        return {
            "captured_at": now,
            "packages": {
                "repo_pending": None
                if package_state["official_error"]
                else len(package_state["official_updates"]),
                "aur_pending": None
                if package_state["aur_error"]
                else len(package_state["aur_updates"]),
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
                "expected_version": int(
                    snapshot_health.get("expected_version", PRIVILEGED_SNAPSHOT_VERSION)
                ),
                "age": snapshot_health.get("age"),
            },
            "containers": containers_digest,
            "wifi": wifi_digest,
            "bluetooth": bluetooth_digest,
            "capture": {
                "avmatrix_cards": len(avmatrix_cards),
                "kernel_channels": len(avmatrix_sysfs_nodes),
                "video_nodes": len(avmatrix_video_nodes),
            },
        }

    def collect_snapshot(self, write_interval: int) -> list[str]:
        current = self.current_state_digest()
        previous = self.load_snapshot()
        lines: list[str] = []

        if not previous:
            lines.append("No prior diff snapshot yet. A baseline will be written automatically.")
            self.write_snapshot(current)
            return lines

        captured_at = previous.get("captured_at")
        if isinstance(captured_at, (int, float)):
            age = max(int(current["captured_at"] - captured_at), 0)
            lines.append(f"Compared with {self.backend._age_label(age)} ago")
        else:
            lines.append("Compared with previous snapshot")

        changes: list[str] = []
        current_packages = current.get("packages", {})
        previous_packages = previous.get("packages", {})
        if isinstance(current_packages, dict) and isinstance(previous_packages, dict):
            current_total = None
            previous_total = None
            if isinstance(current_packages.get("repo_pending"), int) and isinstance(
                current_packages.get("aur_pending"),
                int,
            ):
                current_total = int(current_packages["repo_pending"]) + int(current_packages["aur_pending"])
            if isinstance(previous_packages.get("repo_pending"), int) and isinstance(
                previous_packages.get("aur_pending"),
                int,
            ):
                previous_total = int(previous_packages["repo_pending"]) + int(previous_packages["aur_pending"])
            if current_total is not None and previous_total is not None and current_total != previous_total:
                delta = current_total - previous_total
                changes.append(f"Packages: {delta:+d} pending updates ({current_total} now)")
            current_tracked = current_packages.get("tracked_outdated")
            previous_tracked = previous_packages.get("tracked_outdated")
            if (
                isinstance(current_tracked, int)
                and isinstance(previous_tracked, int)
                and current_tracked != previous_tracked
            ):
                delta = current_tracked - previous_tracked
                changes.append(f"Tracked priority packages: {delta:+d} outdated ({current_tracked} now)")

        current_storage = current.get("storage", {})
        previous_storage = previous.get("storage", {})
        if isinstance(current_storage, dict) and isinstance(previous_storage, dict):
            current_root_pct = current_storage.get("root_pct")
            previous_root_pct = previous_storage.get("root_pct")
            if (
                isinstance(current_root_pct, int)
                and isinstance(previous_root_pct, int)
                and current_root_pct != previous_root_pct
            ):
                changes.append(f"Root usage: {current_root_pct - previous_root_pct:+d}% ({current_root_pct}% now)")
            current_root_free = current_storage.get("root_free")
            previous_root_free = previous_storage.get("root_free")
            if isinstance(current_root_free, int) and isinstance(previous_root_free, int):
                delta = current_root_free - previous_root_free
                if abs(delta) >= 1024**3:
                    changes.append(
                        f"Root free space: {format_bytes(delta)} change ({format_bytes(current_root_free)} now)"
                    )
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
            if (
                isinstance(current_failed, int)
                and isinstance(previous_failed, int)
                and current_failed != previous_failed
            ):
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

        current_containers = current.get("containers", {})
        previous_containers = previous.get("containers", {})
        if isinstance(current_containers, dict) and isinstance(previous_containers, dict):
            current_unhealthy = current_containers.get("unhealthy")
            previous_unhealthy = previous_containers.get("unhealthy")
            if (
                isinstance(current_unhealthy, int)
                and isinstance(previous_unhealthy, int)
                and current_unhealthy != previous_unhealthy
            ):
                changes.append(
                    f"Docker unhealthy: {current_unhealthy - previous_unhealthy:+d} ({current_unhealthy} now)"
                )
            current_restarting = current_containers.get("restarting")
            previous_restarting = previous_containers.get("restarting")
            if (
                isinstance(current_restarting, int)
                and isinstance(previous_restarting, int)
                and current_restarting != previous_restarting
            ):
                changes.append(
                    f"Docker restarting: {current_restarting - previous_restarting:+d} ({current_restarting} now)"
                )
            current_dead = current_containers.get("dead")
            previous_dead = previous_containers.get("dead")
            if (
                isinstance(current_dead, int)
                and isinstance(previous_dead, int)
                and current_dead != previous_dead
            ):
                changes.append(f"Docker dead: {current_dead - previous_dead:+d} ({current_dead} now)")
            current_data = current_containers.get("docker_data_bytes")
            previous_data = previous_containers.get("docker_data_bytes")
            if isinstance(current_data, int) and isinstance(previous_data, int):
                delta = current_data - previous_data
                if abs(delta) >= 1024**3:
                    changes.append(
                        f"Docker data: {format_bytes(delta)} change ({format_bytes(current_data)} now)"
                    )
            current_reclaimable = current_containers.get("reclaimable_bytes")
            previous_reclaimable = previous_containers.get("reclaimable_bytes")
            if isinstance(current_reclaimable, int) and isinstance(previous_reclaimable, int):
                delta = current_reclaimable - previous_reclaimable
                if abs(delta) >= 1024**3:
                    changes.append(
                        f"Docker reclaimable: {format_bytes(delta)} change ({format_bytes(current_reclaimable)} now)"
                    )
            current_stale = current_containers.get("stale_images_90d")
            previous_stale = previous_containers.get("stale_images_90d")
            if (
                isinstance(current_stale, int)
                and isinstance(previous_stale, int)
                and current_stale != previous_stale
            ):
                changes.append(
                    f"Docker stale images (>90d): {current_stale - previous_stale:+d} ({current_stale} now)"
                )

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
            if (
                current_connected
                and previous_connected
                and current_ssid
                and previous_ssid
                and current_ssid != previous_ssid
            ):
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
            if (
                isinstance(current_connected, int)
                and isinstance(previous_connected, int)
                and current_connected != previous_connected
            ):
                changes.append(
                    f"Bluetooth: {current_connected - previous_connected:+d} connected devices ({current_connected} now)"
                )
            current_blocked = bool(current_bluetooth.get("blocked"))
            previous_blocked = bool(previous_bluetooth.get("blocked"))
            if current_blocked != previous_blocked:
                changes.append("Bluetooth radio: blocked" if current_blocked else "Bluetooth radio: unblocked")
            current_powered = current_bluetooth.get("powered")
            previous_powered = previous_bluetooth.get("powered")
            if (
                isinstance(current_powered, bool)
                and isinstance(previous_powered, bool)
                and current_powered != previous_powered
            ):
                changes.append(
                    "Bluetooth controller: powered on"
                    if current_powered
                    else "Bluetooth controller: powered off"
                )

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

        if (
            not isinstance(captured_at, (int, float))
            or current["captured_at"] - captured_at >= write_interval
        ):
            self.write_snapshot(current)
        return lines
