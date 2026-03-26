from __future__ import annotations

import json
import os
from pathlib import Path

from monitor.packages.common import CandidatePreview, STATE_VERSION


def state_path() -> Path:
    root = os.environ.get("XDG_STATE_HOME")
    if root:
        return Path(root) / "monitor" / "package_cleanup_state.json"
    return Path.home() / ".local" / "state" / "monitor" / "package_cleanup_state.json"


def load_state() -> dict[str, object]:
    path = state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "version": STATE_VERSION,
            "protected_packages": [],
            "preview_cache": {"fingerprint": "", "entries": {}},
        }
    if not isinstance(data, dict):
        return {
            "version": STATE_VERSION,
            "protected_packages": [],
            "preview_cache": {"fingerprint": "", "entries": {}},
        }
    protected = data.get("protected_packages", [])
    if not isinstance(protected, list):
        protected = []
    preview_cache = data.get("preview_cache", {})
    if not isinstance(preview_cache, dict):
        preview_cache = {"fingerprint": "", "entries": {}}
    fingerprint = str(preview_cache.get("fingerprint", ""))
    raw_entries = preview_cache.get("entries", {})
    if not isinstance(raw_entries, dict):
        raw_entries = {}
    entries: dict[str, dict[str, object]] = {}
    for name, payload in raw_entries.items():
        if not isinstance(payload, dict):
            continue
        removal_names = payload.get("removal_names", [])
        reclaimable_size = payload.get("reclaimable_size", 0)
        if not isinstance(removal_names, list):
            continue
        entries[str(name)] = {
            "removal_names": [str(item) for item in removal_names if str(item).strip()],
            "reclaimable_size": int(reclaimable_size),
        }
    return {
        "version": STATE_VERSION,
        "protected_packages": [str(item) for item in protected if str(item).strip()],
        "preview_cache": {
            "fingerprint": fingerprint,
            "entries": entries,
        },
    }


def save_state(protected_packages: set[str], fingerprint: str, cache: dict[str, CandidatePreview]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "version": STATE_VERSION,
        "protected_packages": sorted(protected_packages),
        "preview_cache": {
            "fingerprint": fingerprint,
            "entries": {
                name: {
                    "removal_names": list(preview.removal_names),
                    "reclaimable_size": preview.reclaimable_size,
                }
                for name, preview in sorted(cache.items())
            },
        },
    }
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)

