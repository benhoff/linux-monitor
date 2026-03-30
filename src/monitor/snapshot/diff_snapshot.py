from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from monitor.shared.constants import PRIVILEGED_SNAPSHOT_VERSION
from monitor.shared.parsing_journal import summarize_journal_entries
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

    @staticmethod
    def state_rank(state: str) -> int:
        return {
            "unknown": 0,
            "ok": 1,
            "watch": 2,
            "critical": 3,
        }.get(state, 0)

    @staticmethod
    def alert_prefix(severity: int) -> str:
        return "!" if severity >= 80 else "?"

    def transition_line(
        self,
        domain: str,
        previous_state: str,
        current_state: str,
        current_summary: str,
        severity: int,
    ) -> tuple[int, str] | None:
        previous_rank = self.state_rank(previous_state)
        current_rank = self.state_rank(current_state)
        if current_rank > previous_rank:
            return severity, f"{self.alert_prefix(severity)} {domain} regressed: {current_summary}"
        if current_rank < previous_rank:
            return 5, f"Resolved: {domain} {current_summary}"
        return None

    def storage_state(self, payload: object) -> tuple[str, int, str]:
        if not isinstance(payload, dict):
            return "unknown", 0, "state unavailable"
        root_pct = payload.get("root_pct")
        critical_count = payload.get("critical_count")
        watch_count = payload.get("watch_count")
        if isinstance(root_pct, int) and root_pct >= 90:
            return "critical", 95, f"root is {root_pct}% full"
        if isinstance(critical_count, int) and critical_count > 0:
            return "critical", 95, f"{critical_count} filesystem(s) are in critical capacity"
        if isinstance(root_pct, int) and root_pct >= 75:
            return "watch", 70, f"root is {root_pct}% full"
        if isinstance(watch_count, int) and watch_count > 0:
            return "watch", 60, f"{watch_count} filesystem(s) are approaching capacity"
        return "ok", 0, "returned to healthy capacity"

    def systemd_state(self, payload: object) -> tuple[str, int, str]:
        if not isinstance(payload, dict):
            return "unknown", 0, "state unavailable"
        failed_services = payload.get("failed_services")
        state_value = str(payload.get("state", "unknown"))
        if isinstance(failed_services, int) and failed_services > 0:
            severity = 100 if failed_services >= 3 else 80
            return "critical", severity, f"{failed_services} failed service(s) ({state_value})"
        if state_value in {"degraded", "failed"}:
            return "watch", 75, f"state is {state_value}"
        return "ok", 0, "returned to running"

    def privileged_snapshot_state(self, payload: object) -> tuple[str, int, str]:
        if not isinstance(payload, dict):
            return "unknown", 0, "state unavailable"
        status = str(payload.get("status", "missing"))
        version = payload.get("version")
        expected = int(payload.get("expected_version", PRIVILEGED_SNAPSHOT_VERSION))
        age = payload.get("age")
        version_label = f"v{version}" if isinstance(version, int) else "missing schema"
        if status == "healthy":
            return "ok", 0, "is healthy again"
        if status == "stale":
            age_label = self.backend._age_label(age) if isinstance(age, int) else "unknown age"
            return "watch", 65, f"is stale ({version_label}, {age_label} old)"
        if status == "version_drift":
            return "critical", 95, f"has schema drift ({version_label}, need v{expected})"
        if status == "unreadable":
            return "critical", 90, "is unreadable"
        if status == "invalid":
            return "critical", 90, "is invalid"
        return "watch", 70, "is missing"

    def docker_state(self, payload: object) -> tuple[str, int, str]:
        if not isinstance(payload, dict):
            return "unknown", 0, "state unavailable"
        if not payload.get("detected"):
            return "ok", 0, "has no detected runtime issues"
        unhealthy = int(payload.get("unhealthy", 0) or 0)
        restarting = int(payload.get("restarting", 0) or 0)
        dead = int(payload.get("dead", 0) or 0)
        if unhealthy or restarting or dead:
            parts = []
            if unhealthy:
                parts.append(f"{unhealthy} unhealthy")
            if restarting:
                parts.append(f"{restarting} restarting")
            if dead:
                parts.append(f"{dead} dead")
            return "critical", 90, "reports " + " | ".join(parts) + " container(s)"
        available = bool(payload.get("available"))
        service_state = str(payload.get("docker_service", "")).strip()
        if not available and service_state == "active":
            return "watch", 70, "daemon is no longer reachable"
        return "ok", 0, "is healthy again"

    def capture_state(self, payload: object) -> tuple[str, int, str]:
        if not isinstance(payload, dict):
            return "unknown", 0, "state unavailable"
        cards = int(payload.get("avmatrix_cards", 0) or 0)
        kernel = int(payload.get("kernel_channels", 0) or 0)
        nodes = int(payload.get("video_nodes", 0) or 0)
        if cards <= 0:
            return "ok", 0, "has no AVMatrix regression"
        if kernel == 0:
            return "critical", 95, "card is present but kernel channels are missing"
        if nodes == 0:
            return "critical", 100, f"has {kernel} kernel channel(s) but no /dev/video nodes"
        if nodes < kernel:
            return "watch", 80, f"exposes only {nodes}/{kernel} /dev/video nodes"
        return "ok", 0, "device nodes are healthy again"

    def compare_storage(self, current: object, previous: object) -> tuple[int, str] | None:
        current_state, severity, summary = self.storage_state(current)
        previous_state, _previous_severity, _previous_summary = self.storage_state(previous)
        return self.transition_line("Storage", previous_state, current_state, summary, severity)

    def compare_systemd(self, current: object, previous: object) -> tuple[int, str] | None:
        current_state, severity, summary = self.systemd_state(current)
        previous_state, _previous_severity, _previous_summary = self.systemd_state(previous)
        return self.transition_line("Systemd", previous_state, current_state, summary, severity)

    def compare_privileged_snapshot(self, current: object, previous: object) -> tuple[int, str] | None:
        current_state, severity, summary = self.privileged_snapshot_state(current)
        previous_state, _previous_severity, _previous_summary = self.privileged_snapshot_state(previous)
        return self.transition_line("Privileged snapshot", previous_state, current_state, summary, severity)

    def compare_docker(self, current: object, previous: object) -> tuple[int, str] | None:
        current_state, severity, summary = self.docker_state(current)
        previous_state, _previous_severity, _previous_summary = self.docker_state(previous)
        return self.transition_line("Docker", previous_state, current_state, summary, severity)

    def compare_capture(self, current: object, previous: object) -> tuple[int, str] | None:
        current_state, severity, summary = self.capture_state(current)
        previous_state, _previous_severity, _previous_summary = self.capture_state(previous)
        return self.transition_line("AVMatrix", previous_state, current_state, summary, severity)

    def compare_ethernet(self, current: object, previous: object) -> tuple[int, str] | None:
        if not isinstance(current, dict) or not isinstance(previous, dict):
            return None
        current_iface = str(current.get("interface", "")).strip()
        previous_iface = str(previous.get("interface", "")).strip()
        current_default = bool(current.get("default_route"))
        previous_default = bool(previous.get("default_route"))
        current_connected = bool(current.get("connected"))
        previous_connected = bool(previous.get("connected"))
        iface_label = current_iface or previous_iface or "ethernet"
        if not (current_default or previous_default):
            return None
        if current_connected == previous_connected:
            return None
        if current_connected:
            return 5, f"Resolved: Ethernet link restored on {iface_label}"
        return 85, f"! Ethernet regressed: default-route link went down on {iface_label}"

    def compare_wifi(self, current: object, previous: object, ethernet_current: object) -> tuple[int, str] | None:
        if not isinstance(current, dict) or not isinstance(previous, dict):
            return None
        ethernet_default_route_up = (
            isinstance(ethernet_current, dict)
            and bool(ethernet_current.get("default_route"))
            and bool(ethernet_current.get("connected"))
        )
        current_blocked = bool(current.get("blocked"))
        previous_blocked = bool(previous.get("blocked"))
        if current_blocked != previous_blocked:
            if current_blocked:
                return 85, "! Wi-Fi regressed: radio became rfkill-blocked"
            return 5, "Resolved: Wi-Fi radio unblocked"

        current_connected = bool(current.get("connected"))
        previous_connected = bool(previous.get("connected"))
        if current_connected == previous_connected or ethernet_default_route_up:
            return None
        if current_connected:
            ssid = str(current.get("ssid", "")).strip()
            return 5, f"Resolved: Wi-Fi connected to {ssid or 'network'}"
        return 75, "! Wi-Fi regressed: link dropped"

    def build_state_digest(self) -> dict[str, object]:
        now = time.time()
        installed = self.backend.cached("installed_packages", 30.0, self.backend._installed_packages)
        package_state_snapshot = self.backend.package_monitor.package_state_snapshot()
        package_state = {
            "official_updates": dict(package_state_snapshot.official_updates),
            "aur_updates": dict(package_state_snapshot.aur_updates),
            "official_error": package_state_snapshot.official_error,
            "aur_error": package_state_snapshot.aur_error,
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
            if isinstance(errors, list):
                summarized_errors = summarize_journal_entries(errors, limit=20)
                journal_error_count = len(self.backend.logs.filtered_entries(summarized_errors, "journal_errors"))

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
        ethernet_digest = self.backend._ethernet_digest()
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
            "ethernet": ethernet_digest,
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

        changes: list[tuple[int, str]] = []
        comparators = (
            self.compare_storage(current.get("storage", {}), previous.get("storage", {})),
            self.compare_systemd(current.get("systemd", {}), previous.get("systemd", {})),
            self.compare_privileged_snapshot(
                current.get("privileged_snapshot", {}),
                previous.get("privileged_snapshot", {}),
            ),
            self.compare_docker(current.get("containers", {}), previous.get("containers", {})),
            self.compare_ethernet(current.get("ethernet", {}), previous.get("ethernet", {})),
            self.compare_wifi(
                current.get("wifi", {}),
                previous.get("wifi", {}),
                current.get("ethernet", {}),
            ),
            self.compare_capture(current.get("capture", {}), previous.get("capture", {})),
        )
        for item in comparators:
            if item is not None:
                changes.append(item)

        if not changes:
            lines.append("No high-signal changes since the last diff snapshot.")
        else:
            for _severity, message in sorted(changes, key=lambda item: item[0], reverse=True)[:5]:
                lines.append(message)

        if (
            not isinstance(captured_at, (int, float))
            or current["captured_at"] - captured_at >= write_interval
        ):
            self.write_snapshot(current)
        return lines
