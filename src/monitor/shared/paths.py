from __future__ import annotations

import os
from pathlib import Path


def monitor_state_dir() -> Path:
    root = os.environ.get("XDG_STATE_HOME")
    if root:
        return Path(root) / "monitor"
    return Path.home() / ".local" / "state" / "monitor"


def package_cleanup_state_path() -> Path:
    return monitor_state_dir() / "package_cleanup_state.json"


def diff_snapshot_state_path() -> Path:
    override = os.environ.get("MONITOR_DIFF_SNAPSHOT")
    if override:
        return Path(override)
    return monitor_state_dir() / "diff_snapshot.json"


def legacy_repo_diff_snapshot_path(cwd: Path | None = None) -> Path:
    base = cwd if cwd is not None else Path.cwd()
    return base / ".monitor_state" / "diff_snapshot.json"
