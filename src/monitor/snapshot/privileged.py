from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path

from monitor.shared.constants import (
    DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE,
    DEFAULT_PRIVILEGED_SNAPSHOT_PATH,
    PRIVILEGED_SNAPSHOT_VERSION,
)


class PrivilegedSnapshotService:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    @staticmethod
    def snapshot_path() -> Path:
        return Path(
            os.environ.get(
                "MONITOR_PRIVILEGED_SNAPSHOT",
                str(DEFAULT_PRIVILEGED_SNAPSHOT_PATH),
            )
        )

    def load_snapshot(self) -> dict[str, object]:
        path = self.snapshot_path()
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def snapshot(self) -> dict[str, object]:
        return self.backend.cached("privileged_snapshot", 2.0, self.load_snapshot)

    @staticmethod
    def snapshot_max_age() -> int:
        raw = os.environ.get("MONITOR_PRIVILEGED_SNAPSHOT_MAX_AGE")
        if raw is None:
            return DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE
        try:
            value = int(raw)
        except ValueError:
            return DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE
        return value if value > 0 else DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE

    def compute_health(self) -> dict[str, object]:
        path = self.snapshot_path()
        max_age = self.snapshot_max_age()
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
        except PermissionError:
            health["status"] = "unreadable"
            health["reason"] = "snapshot exists but current user cannot read it"
            return health
        except OSError as exc:
            health["status"] = "unreadable"
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
                health["reason"] = (
                    f"snapshot schema v{version}, expected v{PRIVILEGED_SNAPSHOT_VERSION}"
                )
            else:
                health["reason"] = (
                    f"snapshot schema missing, expected v{PRIVILEGED_SNAPSHOT_VERSION}"
                )
            return health

        if not isinstance(generated, (int, float)):
            health["status"] = "invalid"
            health["reason"] = "generated_at missing from snapshot"
            return health

        health["usable"] = True
        if int(health["age"]) > max_age:
            health["status"] = "stale"
            health["reason"] = f"snapshot older than {self.backend._age_label(max_age)}"
        else:
            health["status"] = "healthy"
        return health

    def health(self) -> dict[str, object]:
        return self.backend.cached("privileged_snapshot_health", 2.0, self.compute_health)

    def section(self, name: str) -> dict[str, object] | None:
        health = self.health()
        if not health.get("usable"):
            return None
        snapshot = health.get("snapshot", {})
        if not isinstance(snapshot, dict):
            return None
        section = snapshot.get(name)
        if isinstance(section, dict):
            return section
        return None

    def snapshot_line(self) -> str | None:
        health = self.health()
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
            return f"? Snapshot: {version_label} | {self.backend._age_label(age)} old | stale"
        return None

    def collect_health(self) -> list[str]:
        health = self.health()
        status = str(health.get("status", "missing"))
        version = health.get("version")
        expected = int(health.get("expected_version", PRIVILEGED_SNAPSHOT_VERSION))
        path = str(health.get("path", self.snapshot_path()))
        writer = health.get("writer")
        generated = health.get("generated_at")
        age = health.get("age")
        max_age = int(health.get("max_age", DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE))
        reason = str(health.get("reason", "")).strip()
        age_label = self.backend._age_label(age) if isinstance(age, int) else "unknown age"
        version_label = f"v{version}" if isinstance(version, int) else "schema?"

        lines: list[str] = []
        if status == "healthy":
            lines.append(f"Status: healthy | {version_label} | {age_label} old")
            lines.append("Mode: privileged sections are using the snapshot")
            return lines

        if status == "stale":
            lines.append(f"? Status: stale | {version_label} | {age_label} old")
            lines.append(
                f"? Older than {self.backend._age_label(max_age)}; privileged sections may lag reality"
            )
            lines.append("Refresh: monitor-privileged-refresh")
            return lines

        if status == "version_drift":
            found = f"v{version}" if isinstance(version, int) else "missing schema"
            lines.append(f"! Status: version drift | found {found} | need v{expected}")
            lines.append("! Privileged sections fell back to unprivileged probes")
            lines.append(f"Path: {path}")
            lines.append("Refresh: monitor-privileged-refresh")
            return lines

        if status == "unreadable":
            lines.append("! Status: unreadable")
            lines.append(f"! {reason or 'Snapshot exists but could not be read'}")
            lines.append("! Privileged sections fell back to unprivileged probes")
            lines.append(f"Path: {path}")
            lines.append("Refresh: monitor-privileged-refresh")
            return lines

        if status == "invalid":
            lines.append("! Status: invalid")
            lines.append(f"! {reason or 'Snapshot contents are invalid'}")
            lines.append("! Privileged sections fell back to unprivileged probes")
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
