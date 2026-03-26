#!/usr/bin/env python3

from __future__ import annotations

import argparse
import concurrent.futures
import curses
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable


STATE_VERSION = 1
PREVIEW_WORKERS = 6
TREE_MAX_DEPTH = 4
REFRESH_POLL_INTERVAL = 0.05
MESSAGE_TTL_SECONDS = 8.0

BUILTIN_PROTECTED_EXACT = {
    "amd-ucode",
    "archlinux-keyring",
    "base",
    "base-devel",
    "coreutils",
    "dhcpcd",
    "dracut",
    "efibootmgr",
    "filesystem",
    "gdm",
    "glibc",
    "grub",
    "iwd",
    "intel-ucode",
    "lightdm",
    "linux",
    "linux-firmware",
    "linux-hardened",
    "linux-lts",
    "linux-zen",
    "mesa",
    "mkinitcpio",
    "modemmanager",
    "networkmanager",
    "openssh",
    "openresolv",
    "os-prober",
    "pacman",
    "pacman-contrib",
    "plasma-desktop",
    "plasma-login-manager",
    "plasma-workspace",
    "refind",
    "refind-efi",
    "sddm",
    "sbctl",
    "sudo",
    "systemd",
    "systemd-sysvcompat",
    "wayland",
    "wpa_supplicant",
    "xorg-server",
    "xorg-xinit",
}

BUILTIN_PROTECTED_PREFIXES = (
    "linux-firmware-",
    "nvidia",
    "xf86-video-",
)


@dataclass
class CommandResult:
    args: list[str]
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    missing: bool = False
    timed_out: bool = False


@dataclass
class PackageInfo:
    name: str
    version: str
    description: str
    installed_size: int
    install_reason: str
    required_by: list[str]
    depends: list[str]
    provides: list[str]
    groups: list[str]
    official: bool
    resolved_dep_names: list[str] = field(default_factory=list)

    @property
    def explicit(self) -> bool:
        return self.install_reason == "explicit"


@dataclass(frozen=True)
class CandidatePreview:
    root: str
    removal_names: tuple[str, ...]
    reclaimable_size: int


@dataclass(frozen=True)
class RemovalPlan:
    roots: tuple[str, ...]
    removal_names: tuple[str, ...]
    reclaimable_size: int


@dataclass
class RefreshSnapshot:
    packages: dict[str, PackageInfo] = field(default_factory=dict)
    candidates: dict[str, CandidatePreview] = field(default_factory=dict)
    roots_total: int = 0
    validated_count: int = 0
    loading: bool = True
    status: str = "Loading package metadata..."
    fingerprint: str = ""


def run_command(args: list[str], timeout: float = 10.0) -> CommandResult:
    env = os.environ.copy()
    env.setdefault("LC_ALL", "C")
    env.setdefault("LANG", "C")
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return CommandResult(args, False, 127, "", "command not found", missing=True)
    except subprocess.TimeoutExpired:
        return CommandResult(args, False, 124, "", "command timed out", timed_out=True)
    return CommandResult(
        args=list(args),
        ok=completed.returncode == 0,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def format_bytes(value: int) -> str:
    size = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if unit == units[-1] or abs(size) < 1024.0:
            if unit == "B":
                return f"{int(size)} {unit}"
            if size >= 100:
                return f"{size:.0f} {unit}"
            if size >= 10:
                return f"{size:.1f} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TiB"


def format_count(value: int, singular: str, plural: str | None = None) -> str:
    if value == 1:
        return f"1 {singular}"
    return f"{value} {plural or singular + 's'}"


def format_name_list(names: Iterable[str], limit: int = 4) -> str:
    items = [name for name in dict.fromkeys(name for name in names if name)]
    if not items:
        return "(none)"
    if len(items) <= limit:
        return ", ".join(items)
    remainder = len(items) - limit
    return f"{', '.join(items[:limit])}, +{remainder} more"


def parse_size_bytes(text: str) -> int:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?i?B)\b", text, re.IGNORECASE)
    if not match:
        return 0
    amount = float(match.group(1))
    unit = match.group(2).upper()
    factors = {
        "B": 1,
        "KIB": 1024,
        "MIB": 1024**2,
        "GIB": 1024**3,
        "TIB": 1024**4,
        "PIB": 1024**5,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
        "PB": 1000**5,
    }
    return int(amount * factors.get(unit, 1))


def single_line(text: str) -> str:
    return " ".join(text.split())


def strip_dep_version(token: str) -> str:
    return re.split(r"(?<![<>])(?:>=|<=|=|<|>)", token, maxsplit=1)[0].strip()


def split_field_values(lines: list[str]) -> list[str]:
    if not lines:
        return []
    value = "  ".join(line.strip() for line in lines if line.strip())
    if not value or value == "None":
        return []
    return [item.strip() for item in re.split(r"\s{2,}", value) if item.strip() and item.strip() != "None"]


def built_in_protected(name: str) -> bool:
    if name in BUILTIN_PROTECTED_EXACT:
        return True
    return any(name.startswith(prefix) for prefix in BUILTIN_PROTECTED_PREFIXES)


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
    protected = data.get("protected_packages")
    cache = data.get("preview_cache")
    return {
        "version": STATE_VERSION,
        "protected_packages": sorted({str(item) for item in protected or [] if str(item).strip()}),
        "preview_cache": cache if isinstance(cache, dict) else {"fingerprint": "", "entries": {}},
    }


def save_state(protected_packages: set[str], fingerprint: str, cache: dict[str, CandidatePreview]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
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
    fd, temp_path = tempfile.mkstemp(prefix="package_cleanup_", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temp_path, path)
    finally:
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass


def parse_pacman_qi_block(block: str) -> PackageInfo | None:
    fields: dict[str, list[str]] = {}
    current: str | None = None
    for raw in block.splitlines():
        if not raw.strip():
            continue
        if raw[0].isspace():
            if current is not None:
                fields[current].append(raw.strip())
            continue
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        current = key.strip()
        fields[current] = [value.strip()]
    name = fields.get("Name", [""])[0]
    version = fields.get("Version", [""])[0]
    if not name or not version:
        return None
    reason_text = fields.get("Install Reason", [""])[0].lower()
    install_reason = "explicit" if "explicit" in reason_text else "dependency"
    return PackageInfo(
        name=name,
        version=version,
        description=fields.get("Description", [""])[0],
        installed_size=parse_size_bytes(fields.get("Installed Size", ["0 B"])[0]),
        install_reason=install_reason,
        required_by=split_field_values(fields.get("Required By", [])),
        depends=split_field_values(fields.get("Depends On", [])),
        provides=split_field_values(fields.get("Provides", [])),
        groups=split_field_values(fields.get("Groups", [])),
        official=True,
    )


def resolve_dependency_names(packages: dict[str, PackageInfo]) -> None:
    provider_map: dict[str, set[str]] = {}
    for pkg in packages.values():
        keys = {pkg.name, strip_dep_version(pkg.name)}
        for token in pkg.provides:
            keys.add(token)
            keys.add(strip_dep_version(token))
        for key in keys:
            provider_map.setdefault(key, set()).add(pkg.name)

    for pkg in packages.values():
        resolved: list[str] = []
        seen: set[str] = set()
        for dep in pkg.depends:
            candidates = provider_map.get(dep)
            base = strip_dep_version(dep)
            if not candidates and base != dep:
                candidates = provider_map.get(base)
            if not candidates:
                continue
            if base in candidates:
                choice = base
            else:
                choice = sorted(candidates)[0]
            if choice in packages and choice not in seen:
                resolved.append(choice)
                seen.add(choice)
        pkg.resolved_dep_names = resolved


def inventory_fingerprint(packages: dict[str, PackageInfo]) -> str:
    lines = [f"{pkg.name}\t{pkg.version}" for pkg in packages.values()]
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def load_package_inventory() -> tuple[dict[str, PackageInfo], str]:
    info_result = run_command(["pacman", "-Qi"], timeout=60.0)
    if not info_result.ok:
        raise RuntimeError(single_line(info_result.stderr or "pacman -Qi failed"))
    foreign_result = run_command(["pacman", "-Qqm"], timeout=20.0)
    if foreign_result.missing:
        foreign_names: set[str] = set()
    elif foreign_result.ok:
        foreign_names = {line.strip() for line in foreign_result.stdout.splitlines() if line.strip()}
    else:
        raise RuntimeError(single_line(foreign_result.stderr or "pacman -Qqm failed"))

    packages: dict[str, PackageInfo] = {}
    fingerprint_builder: list[str] = []
    for block in info_result.stdout.split("\n\n"):
        pkg = parse_pacman_qi_block(block)
        if pkg is None:
            continue
        pkg.official = pkg.name not in foreign_names
        packages[pkg.name] = pkg
        fingerprint_builder.append(f"{pkg.name}\t{pkg.version}")
    resolve_dependency_names(packages)
    fingerprint = hashlib.sha256("\n".join(sorted(fingerprint_builder)).encode("utf-8")).hexdigest()
    return packages, fingerprint


def removal_preview(roots: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(roots, str):
        root_names = [roots]
    else:
        root_names = [name for name in roots if name]
    if not root_names:
        raise RuntimeError("No package roots selected.")
    root_names = list(dict.fromkeys(root_names))
    result = run_command(
        ["pacman", "-Rsup", "--print-format", "%n", *root_names],
        timeout=20.0,
    )
    if not result.ok:
        roots_text = ", ".join(root_names)
        raise RuntimeError(single_line(result.stderr or f"Failed to preview {roots_text}"))
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    for root in reversed(root_names):
        if root not in names:
            names.insert(0, root)
    return tuple(dict.fromkeys(names))


def validate_removal_plan(
    roots: Iterable[str],
    names: Iterable[str],
    packages: dict[str, PackageInfo],
    protected_packages: set[str],
    official_only: bool = True,
) -> RemovalPlan | None:
    error = removal_plan_error(
        roots,
        names,
        packages,
        protected_packages,
        official_only=official_only,
    )
    if error is not None:
        return None
    root_names = tuple(dict.fromkeys(name for name in roots if name))
    removal_names = tuple(name for name in names if name)
    reclaimable_size = sum(packages[name].installed_size for name in removal_names if name in packages)
    return RemovalPlan(
        roots=root_names,
        removal_names=removal_names,
        reclaimable_size=reclaimable_size,
    )


def removal_plan_error(
    roots: Iterable[str],
    names: Iterable[str],
    packages: dict[str, PackageInfo],
    protected_packages: set[str],
    official_only: bool = True,
) -> str | None:
    root_names = tuple(dict.fromkeys(name for name in roots if name))
    removal_names = tuple(name for name in names if name)
    if not root_names or not removal_names:
        if not root_names:
            return "No packages are selected for removal."
        return (
            f"pacman returned an empty removal preview for {format_name_list(root_names)}. "
            "Refresh with r and try again."
        )

    missing_roots = [root for root in root_names if root not in removal_names]
    if missing_roots:
        return (
            f"pacman preview no longer includes selected root(s): {format_name_list(missing_roots)}. "
            "The package state likely changed; refresh with r and retry."
        )

    missing_packages = [name for name in removal_names if name not in packages]
    if missing_packages:
        return (
            f"Removal preview includes package(s) missing from the current snapshot: "
            f"{format_name_list(missing_packages)}. Refresh with r and retry."
        )

    foreign_packages: list[str] = []
    protected_hits: list[str] = []
    for name in removal_names:
        pkg = packages.get(name)
        if pkg is None:
            continue
        if official_only and not pkg.official:
            foreign_packages.append(name)
        if name in protected_packages or built_in_protected(name):
            protected_hits.append(name)

    if foreign_packages:
        return (
            f"Removal preview includes foreign/AUR package(s): {format_name_list(foreign_packages)}. "
            "That selection is only allowed from the orphan view."
        )

    if protected_hits:
        return (
            f"Removal preview includes protected package(s): {format_name_list(protected_hits)}. "
            "Unprotect them first or adjust the selection."
        )

    return None


def validate_preview(
    root: str,
    names: Iterable[str],
    packages: dict[str, PackageInfo],
    protected_packages: set[str],
) -> CandidatePreview | None:
    plan = validate_removal_plan((root,), names, packages, protected_packages)
    if plan is None:
        return None
    return CandidatePreview(root=root, removal_names=plan.removal_names, reclaimable_size=plan.reclaimable_size)


def preview_tree_lines(
    preview: CandidatePreview,
    packages: dict[str, PackageInfo],
    width: int,
    max_depth: int = TREE_MAX_DEPTH,
) -> list[str]:
    preview_set = set(preview.removal_names)
    global_seen: set[str] = set()
    lines: list[str] = []

    def walk(name: str, depth: int, prefix: str, is_last: bool, active_path: set[str]) -> None:
        pkg = packages.get(name)
        label = name
        if pkg is not None:
            label = f"{name} ({format_bytes(pkg.installed_size)})"
        branch = ""
        if depth > 0:
            branch = prefix + ("└─ " if is_last else "├─ ")
        if name in global_seen and depth > 0:
            label += " [shared]"
            lines.append((branch + label)[:width])
            return
        global_seen.add(name)
        lines.append((branch + label)[:width])
        if depth >= max_depth - 1:
            children = [
                dep for dep in (pkg.resolved_dep_names if pkg else [])
                if dep in preview_set and dep not in active_path
            ]
            if children:
                ellipsis_prefix = prefix + ("   " if is_last else "│  ")
                lines.append((ellipsis_prefix + "...")[:width])
            return
        children = [
            dep for dep in (pkg.resolved_dep_names if pkg else [])
            if dep in preview_set and dep not in active_path
        ]
        for index, child in enumerate(children):
            next_prefix = prefix + ("   " if is_last else "│  ")
            walk(
                child,
                depth + 1,
                next_prefix,
                index == len(children) - 1,
                active_path | {child},
            )

    walk(preview.root, 0, "", True, {preview.root})
    return lines or [preview.root[:width]]


def shell_command_for_removal(roots: str | Iterable[str]) -> list[str]:
    if isinstance(roots, str):
        root_names = [roots]
    else:
        root_names = [name for name in roots if name]
    root_names = list(dict.fromkeys(root_names))
    if os.geteuid() == 0:
        return ["pacman", "-Rsu", "--confirm", *root_names]
    return ["sudo", "pacman", "-Rsu", "--confirm", *root_names]


class PackageCleanupModel:
    def __init__(self) -> None:
        state = load_state()
        protected = state.get("protected_packages", [])
        self.user_protected: set[str] = {str(item) for item in protected}
        preview_cache = state.get("preview_cache", {})
        self.cached_fingerprint = str(preview_cache.get("fingerprint", "")) if isinstance(preview_cache, dict) else ""
        raw_entries = preview_cache.get("entries", {}) if isinstance(preview_cache, dict) else {}
        self.preview_cache: dict[str, CandidatePreview] = {}
        if isinstance(raw_entries, dict):
            for name, payload in raw_entries.items():
                if not isinstance(payload, dict):
                    continue
                removal_names = payload.get("removal_names", [])
                if not isinstance(removal_names, list):
                    continue
                reclaimable_size = int(payload.get("reclaimable_size", 0))
                root = str(name)
                self.preview_cache[root] = CandidatePreview(
                    root=root,
                    removal_names=tuple(str(item) for item in removal_names if str(item).strip()),
                    reclaimable_size=reclaimable_size,
                )

        self.lock = threading.Lock()
        self.snapshot = RefreshSnapshot()
        self.message = ""
        self.message_until = 0.0
        self.pending_packages: dict[str, PackageInfo] | None = None
        self.pending_fingerprint = ""
        self.pending_status = ""
        self.refresh_requested = threading.Event()
        self.stop_event = threading.Event()
        self.worker = threading.Thread(target=self._refresh_loop, daemon=True)

    def start(self) -> None:
        self.worker.start()
        self.request_refresh("Refreshing package catalog...")

    def stop(self) -> None:
        self.stop_event.set()
        self.refresh_requested.set()
        self.worker.join(timeout=1.0)

    def request_refresh(self, message: str | None = None) -> None:
        if message:
            self.set_message(message)
        with self.lock:
            self.pending_packages = None
            self.pending_fingerprint = ""
            self.pending_status = ""
        self.refresh_requested.set()

    def set_message(self, message: str, ttl: float = MESSAGE_TTL_SECONDS) -> None:
        with self.lock:
            self.message = message
            self.message_until = time.time() + ttl

    def clear_expired_message(self) -> None:
        with self.lock:
            if self.message and time.time() >= self.message_until:
                self.message = ""
                self.message_until = 0.0

    def protect_package(self, name: str) -> None:
        if not name or built_in_protected(name):
            return
        self.user_protected.add(name)
        self._save_cache()
        self.request_refresh(f"Protected {name}.")

    def unprotect_package(self, name: str) -> None:
        if name in self.user_protected:
            self.user_protected.remove(name)
            self._save_cache()
            self.request_refresh(f"Unprotected {name}.")

    def _save_cache(self) -> None:
        with self.lock:
            fingerprint = self.snapshot.fingerprint
        save_state(self.user_protected, fingerprint or self.cached_fingerprint, self.preview_cache)

    def current_snapshot(self) -> tuple[RefreshSnapshot, str]:
        self.clear_expired_message()
        with self.lock:
            message = self.message
            snapshot = RefreshSnapshot(
                packages=dict(self.snapshot.packages),
                candidates=dict(self.snapshot.candidates),
                roots_total=self.snapshot.roots_total,
                validated_count=self.snapshot.validated_count,
                loading=self.snapshot.loading,
                status=self.snapshot.status,
                fingerprint=self.snapshot.fingerprint,
            )
        return snapshot, message

    def protected_names(self, packages: dict[str, PackageInfo]) -> list[str]:
        return sorted(name for name in self.user_protected if name in packages or name)

    def _queue_rebuild(
        self,
        packages: dict[str, PackageInfo],
        fingerprint: str,
        status: str,
    ) -> None:
        with self.lock:
            self.pending_packages = packages
            self.pending_fingerprint = fingerprint
            self.pending_status = status
        self.refresh_requested.set()

    def _prepare_cached_candidates(
        self,
        packages: dict[str, PackageInfo],
        fingerprint: str,
    ) -> tuple[set[str], list[str], dict[str, CandidatePreview], list[str], int, bool]:
        protected = set(self.user_protected)
        roots = sorted(
            pkg.name
            for pkg in packages.values()
            if pkg.official
            and not pkg.required_by
            and pkg.name not in protected
            and not built_in_protected(pkg.name)
        )
        valid_candidates: dict[str, CandidatePreview] = {}
        cached_missing: list[str] = []
        validated = 0
        save_needed = False
        allowed_roots = set(roots)

        for name in list(self.preview_cache):
            if name not in allowed_roots:
                self.preview_cache.pop(name, None)
                save_needed = True

        for root in roots:
            cached = self.preview_cache.get(root)
            if cached is None:
                cached_missing.append(root)
                continue
            candidate = validate_preview(root, cached.removal_names, packages, protected)
            if candidate is None:
                self.preview_cache.pop(root, None)
                cached_missing.append(root)
                save_needed = True
                continue
            validated += 1
            valid_candidates[root] = candidate
            if candidate != cached:
                self.preview_cache[root] = candidate
                save_needed = True

        self.cached_fingerprint = fingerprint
        return protected, roots, valid_candidates, cached_missing, validated, save_needed

    def apply_local_removal(self, plan: RemovalPlan) -> None:
        with self.lock:
            current_packages = dict(self.snapshot.packages)
        if not current_packages:
            self.request_refresh(
                f"Removed {format_count(len(plan.roots), 'root package')}. Refreshing package catalog..."
            )
            return

        removed = set(plan.removal_names)
        remaining_packages = {
            name: replace(pkg)
            for name, pkg in current_packages.items()
            if name not in removed
        }
        for name, pkg in list(remaining_packages.items()):
            pkg.required_by = [dep for dep in pkg.required_by if dep not in removed]
            pkg.resolved_dep_names = [dep for dep in pkg.resolved_dep_names if dep not in removed]
            remaining_packages[name] = pkg
        resolve_dependency_names(remaining_packages)
        fingerprint = inventory_fingerprint(remaining_packages)

        _protected, roots, valid_candidates, cached_missing, validated, save_needed = self._prepare_cached_candidates(
            remaining_packages,
            fingerprint,
        )

        if cached_missing:
            status = f"Validated {validated}/{len(roots)} removable roots..."
        else:
            status = f"Loaded {len(valid_candidates)} removable candidates."
        with self.lock:
            self.snapshot.packages = remaining_packages
            self.snapshot.fingerprint = fingerprint
            self.snapshot.roots_total = len(roots)
            self.snapshot.validated_count = validated
            self.snapshot.candidates = dict(valid_candidates)
            self.snapshot.loading = bool(cached_missing)
            self.snapshot.status = status

        removed_roots = format_count(len(plan.roots), "root package")
        if cached_missing:
            self.set_message(f"Removed {removed_roots}. Updating cached candidates...")
            self._queue_rebuild(remaining_packages, fingerprint, status)
        else:
            self.set_message(f"Removed {removed_roots}.")
        if save_needed or not cached_missing:
            self._save_cache()

    def _refresh_loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_requested.wait()
            self.refresh_requested.clear()
            if self.stop_event.is_set():
                break
            self._refresh_once()

    def _refresh_once(self) -> None:
        with self.lock:
            packages = self.pending_packages
            fingerprint = self.pending_fingerprint
            status = self.pending_status
            self.pending_packages = None
            self.pending_fingerprint = ""
            self.pending_status = ""
            self.snapshot.loading = True
            self.snapshot.status = status or "Loading pacman metadata..."
        if packages is None:
            try:
                packages, fingerprint = load_package_inventory()
            except RuntimeError as exc:
                with self.lock:
                    self.snapshot.loading = False
                    self.snapshot.status = str(exc)
                self.set_message(str(exc), ttl=15.0)
                return

        protected, roots, valid_candidates, cached_missing, validated, save_needed = self._prepare_cached_candidates(
            packages,
            fingerprint,
        )
        with self.lock:
            self.snapshot.packages = packages
            self.snapshot.fingerprint = fingerprint
            self.snapshot.roots_total = len(roots)
            self.snapshot.candidates = dict(valid_candidates)
            self.snapshot.validated_count = validated
            self.snapshot.status = f"Validated {validated}/{len(roots)} removable roots..."

        if not cached_missing:
            with self.lock:
                self.snapshot.loading = False
                self.snapshot.status = f"Loaded {len(valid_candidates)} removable candidates."
            self._save_cache()
            return

        def task(root: str) -> tuple[str, tuple[str, ...] | None, str | None]:
            try:
                return root, removal_preview(root), None
            except RuntimeError as exc:
                return root, None, str(exc)

        cache_dirty = save_needed
        with concurrent.futures.ThreadPoolExecutor(max_workers=PREVIEW_WORKERS) as executor:
            futures = {executor.submit(task, root): root for root in cached_missing}
            for future in concurrent.futures.as_completed(futures):
                if self.stop_event.is_set():
                    break
                root, removal_names, error = future.result()
                validated += 1
                if removal_names is not None:
                    cache_dirty = True
                    candidate = validate_preview(root, removal_names, packages, protected)
                    if candidate is not None:
                        valid_candidates[root] = candidate
                        self.preview_cache[root] = candidate
                    else:
                        self.preview_cache.pop(root, None)
                elif error:
                    self.set_message(error)
                with self.lock:
                    self.snapshot.candidates = dict(valid_candidates)
                    self.snapshot.validated_count = validated
                    self.snapshot.status = (
                        f"Validated {validated}/{len(roots)} removable roots..."
                    )

        with self.lock:
            self.snapshot.candidates = dict(valid_candidates)
            self.snapshot.validated_count = validated
            self.snapshot.loading = False
            self.snapshot.status = f"Loaded {len(valid_candidates)} removable candidates."
        if cache_dirty or cached_missing:
            self._save_cache()


class PackageCleanupUI:
    def __init__(self, model: PackageCleanupModel) -> None:
        self.model = model
        self.mode = "main"
        self.sort_mode = "reclaim"
        self.main_index = 0
        self.main_offset = 0
        self.orphan_index = 0
        self.orphan_offset = 0
        self.protected_index = 0
        self.protected_offset = 0
        self.selected_roots: set[str] = set()
        self.orphan_deselected: set[str] = set()
        self.detail_root: str | None = None
        self.confirm_plan: RemovalPlan | None = None

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr: curses.window) -> None:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        stdscr.keypad(True)
        stdscr.nodelay(True)
        if curses.has_colors():
            curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(2, curses.COLOR_CYAN, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
            curses.init_pair(4, curses.COLOR_GREEN, -1)
            curses.init_pair(5, curses.COLOR_YELLOW, -1)
            curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_YELLOW)

        while True:
            self.draw(stdscr)
            key = stdscr.getch()
            if key == -1:
                time.sleep(REFRESH_POLL_INTERVAL)
                continue
            if self.confirm_plan is not None:
                if key in (ord("y"), ord("Y")):
                    self._perform_removal(stdscr)
                elif key in (ord("n"), ord("N"), 27):
                    self.confirm_plan = None
                continue
            if key in (ord("q"), ord("Q")):
                if self.mode == "main":
                    break
                self.mode = "main"
                self.detail_root = None
                continue
            if key in (ord("r"), ord("R")):
                self.model.request_refresh("Refreshing package catalog...")
                continue
            if self.mode == "main":
                if not self._handle_main_key(key):
                    continue
            elif self.mode == "detail":
                if not self._handle_detail_key(key):
                    continue
            elif self.mode == "orphans":
                if not self._handle_orphan_key(key):
                    continue
            elif self.mode == "protected":
                if not self._handle_protected_key(key):
                    continue

    def _sorted_candidates(self, snapshot: RefreshSnapshot) -> list[CandidatePreview]:
        candidates = list(snapshot.candidates.values())
        if self.sort_mode == "name":
            candidates.sort(key=lambda item: item.root)
        elif self.sort_mode == "size":
            candidates.sort(
                key=lambda item: (
                    snapshot.packages.get(item.root).installed_size if item.root in snapshot.packages else 0,
                    item.root,
                ),
                reverse=True,
            )
        else:
            candidates.sort(key=lambda item: (item.reclaimable_size, item.root), reverse=True)
        return candidates

    def _handle_main_key(self, key: int) -> bool:
        snapshot, _message = self.model.current_snapshot()
        candidates = self._sorted_candidates(snapshot)
        if key in (curses.KEY_DOWN, ord("j")):
            if candidates:
                self.main_index = min(self.main_index + 1, len(candidates) - 1)
        elif key in (curses.KEY_UP, ord("k")):
            self.main_index = max(self.main_index - 1, 0)
        elif key == curses.KEY_NPAGE:
            self.main_index = min(self.main_index + 15, max(len(candidates) - 1, 0))
        elif key == curses.KEY_PPAGE:
            self.main_index = max(self.main_index - 15, 0)
        elif key == curses.KEY_HOME:
            self.main_index = 0
        elif key == curses.KEY_END:
            self.main_index = max(len(candidates) - 1, 0)
        elif key in (10, 13, curses.KEY_ENTER):
            if candidates:
                self.detail_root = candidates[self.main_index].root
                self.mode = "detail"
        elif key == ord(" "):
            if candidates:
                root = candidates[self.main_index].root
                if root in self.selected_roots:
                    self.selected_roots.remove(root)
                else:
                    self.selected_roots.add(root)
        elif key in (ord("c"), ord("C")):
            self.selected_roots.clear()
        elif key in (ord("s"), ord("S")):
            self.sort_mode = {
                "reclaim": "size",
                "size": "name",
                "name": "reclaim",
            }[self.sort_mode]
        elif key in (ord("m"), ord("M")):
            if candidates:
                root = candidates[self.main_index].root
                self.selected_roots.discard(root)
                self.model.protect_package(root)
        elif key in (ord("o"), ord("O")):
            self.mode = "orphans"
        elif key in (ord("p"), ord("P")):
            self.mode = "protected"
        elif key in (ord("x"), ord("X")):
            roots = [root for root in self.selected_roots if root in snapshot.candidates]
            if not roots and candidates:
                roots = [candidates[self.main_index].root]
            if roots:
                self._open_confirmation(snapshot, roots)
        return True

    def _handle_detail_key(self, key: int) -> bool:
        snapshot, _message = self.model.current_snapshot()
        if self.detail_root not in snapshot.candidates:
            self.mode = "main"
            self.detail_root = None
            return True
        if key in (27, curses.KEY_BACKSPACE, ord("h")):
            self.mode = "main"
            self.detail_root = None
        elif key == ord(" ") and self.detail_root:
            if self.detail_root in self.selected_roots:
                self.selected_roots.remove(self.detail_root)
            else:
                self.selected_roots.add(self.detail_root)
        elif key in (ord("m"), ord("M")) and self.detail_root:
            self.selected_roots.discard(self.detail_root)
            self.model.protect_package(self.detail_root)
            self.mode = "main"
            self.detail_root = None
        elif key in (ord("x"), ord("X")):
            self._open_confirmation(snapshot, [self.detail_root])
        return True

    def _orphan_rows(self, snapshot: RefreshSnapshot) -> list[PackageInfo]:
        protected = set(self.model.user_protected)
        rows = [
            pkg
            for pkg in snapshot.packages.values()
            if pkg.install_reason == "dependency"
            and not pkg.required_by
            and pkg.name not in protected
            and not built_in_protected(pkg.name)
        ]
        rows.sort(
            key=lambda item: (
                0 if item.official else 1,
                -item.installed_size,
                item.name,
            )
        )
        return rows

    def _selected_orphan_names(self, rows: list[PackageInfo]) -> list[str]:
        return [pkg.name for pkg in rows if pkg.name not in self.orphan_deselected]

    def _handle_orphan_key(self, key: int) -> bool:
        snapshot, _message = self.model.current_snapshot()
        rows = self._orphan_rows(snapshot)
        if key in (27, curses.KEY_BACKSPACE, ord("h"), ord("q"), ord("Q")):
            self.mode = "main"
            return True
        if key in (curses.KEY_DOWN, ord("j")):
            if rows:
                self.orphan_index = min(self.orphan_index + 1, len(rows) - 1)
        elif key in (curses.KEY_UP, ord("k")):
            self.orphan_index = max(self.orphan_index - 1, 0)
        elif key == curses.KEY_NPAGE:
            self.orphan_index = min(self.orphan_index + 15, max(len(rows) - 1, 0))
        elif key == curses.KEY_PPAGE:
            self.orphan_index = max(self.orphan_index - 15, 0)
        elif key == curses.KEY_HOME:
            self.orphan_index = 0
        elif key == curses.KEY_END:
            self.orphan_index = max(len(rows) - 1, 0)
        elif key == ord(" ") and rows:
            name = rows[self.orphan_index].name
            if name in self.orphan_deselected:
                self.orphan_deselected.remove(name)
            else:
                self.orphan_deselected.add(name)
        elif key in (ord("a"), ord("A")):
            self.orphan_deselected.clear()
        elif key in (ord("c"), ord("C")):
            self.orphan_deselected.update(pkg.name for pkg in rows)
        elif key in (ord("m"), ord("M")) and rows:
            name = rows[self.orphan_index].name
            self.orphan_deselected.discard(name)
            self.model.protect_package(name)
        elif key in (ord("x"), ord("X")):
            roots = self._selected_orphan_names(rows)
            if roots:
                self._open_confirmation(snapshot, roots, official_only=False)
            else:
                self.model.set_message("No orphan packages selected.", ttl=12.0)
        return True

    def _handle_protected_key(self, key: int) -> bool:
        snapshot, _message = self.model.current_snapshot()
        names = self.model.protected_names(snapshot.packages)
        if key in (27, curses.KEY_BACKSPACE, ord("h"), ord("q"), ord("Q")):
            self.mode = "main"
            return True
        if key in (curses.KEY_DOWN, ord("j")):
            if names:
                self.protected_index = min(self.protected_index + 1, len(names) - 1)
        elif key in (curses.KEY_UP, ord("k")):
            self.protected_index = max(self.protected_index - 1, 0)
        elif key == curses.KEY_NPAGE:
            self.protected_index = min(self.protected_index + 15, max(len(names) - 1, 0))
        elif key == curses.KEY_PPAGE:
            self.protected_index = max(self.protected_index - 15, 0)
        elif key == curses.KEY_HOME:
            self.protected_index = 0
        elif key == curses.KEY_END:
            self.protected_index = max(len(names) - 1, 0)
        elif key in (ord("u"), ord("U")) and names:
            self.model.unprotect_package(names[self.protected_index])
        return True

    def draw(self, stdscr: curses.window) -> None:
        snapshot, message = self.model.current_snapshot()
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if self.mode == "main":
            self._draw_main(stdscr, snapshot, message, height, width)
        elif self.mode == "detail":
            self._draw_detail(stdscr, snapshot, message, height, width)
        elif self.mode == "orphans":
            self._draw_orphans(stdscr, snapshot, message, height, width)
        else:
            self._draw_protected(stdscr, snapshot, message, height, width)
        if self.confirm_plan is not None:
            self._draw_confirmation(stdscr, snapshot, height, width)
        stdscr.refresh()

    def _open_confirmation(
        self,
        snapshot: RefreshSnapshot,
        roots: Iterable[str],
        official_only: bool = True,
    ) -> None:
        selected_roots = tuple(
            dict.fromkeys(
                root
                for root in roots
                if root and root in snapshot.packages
            )
        )
        if not selected_roots:
            self.model.set_message("No removable packages selected.")
            return
        try:
            removal_names = removal_preview(selected_roots)
        except RuntimeError as exc:
            self.model.set_message(str(exc), ttl=12.0)
            return
        plan = validate_removal_plan(
            selected_roots,
            removal_names,
            snapshot.packages,
            set(self.model.user_protected),
            official_only=official_only,
        )
        if plan is None:
            error = removal_plan_error(
                selected_roots,
                removal_names,
                snapshot.packages,
                set(self.model.user_protected),
                official_only=official_only,
            )
            if error is None:
                error = (
                    f"Selection {format_name_list(selected_roots)} is no longer a valid removable set. "
                    "Refresh with r and try again."
                )
            self.model.set_message(error, ttl=16.0)
            return
        self.confirm_plan = plan

    def _draw_main(
        self,
        stdscr: curses.window,
        snapshot: RefreshSnapshot,
        message: str,
        height: int,
        width: int,
    ) -> None:
        candidates = self._sorted_candidates(snapshot)
        if self.main_index >= len(candidates):
            self.main_index = max(len(candidates) - 1, 0)
        body_top = 3
        body_height = max(height - 5, 1)
        max_offset = max(len(candidates) - body_height, 0)
        if self.main_index < self.main_offset:
            self.main_offset = self.main_index
        elif self.main_index >= self.main_offset + body_height:
            self.main_offset = self.main_index - body_height + 1
        self.main_offset = min(self.main_offset, max_offset)

        title = "Package Cleanup TUI"
        subtitle = "Official installed packages only | unsafe packages hidden | multiselect bulk removal"
        help_text = "Space mark | x remove marked/current | c clear marks | o orphans | Enter inspect | m protect | p protected | s sort | r refresh | q quit"
        self._safe_addstr(stdscr, 0, 0, title[: max(width - 1, 1)], curses.color_pair(2) | curses.A_BOLD)
        self._safe_addstr(stdscr, 1, 0, subtitle[: max(width - 1, 1)], curses.A_DIM)
        self._safe_addstr(stdscr, 2, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

        marker_width = 3
        name_width = max(min(width // 4, 28), 18)
        size_width = 0
        size_label = ""
        if self.sort_mode == "size":
            size_width = 10
            size_label = "Size"
        elif self.sort_mode == "reclaim":
            size_width = 10
            size_label = "Reclaim"
        desc_width = max(width - marker_width - name_width - size_width - (3 if size_width else 2), 20)
        header_attr = curses.color_pair(5) | curses.A_BOLD
        self._safe_addstr(stdscr, 3, 0, "Sel"[:marker_width], header_attr)
        self._safe_addstr(stdscr, 3, marker_width + 1, "Package"[:name_width], header_attr)
        size_col = marker_width + name_width + 2
        desc_col = marker_width + name_width + 2
        if size_width:
            self._safe_addstr(stdscr, 3, size_col, size_label[:size_width], header_attr)
            desc_col = marker_width + name_width + size_width + 3
        self._safe_addstr(stdscr, 3, desc_col, "Description"[:desc_width], header_attr)
        body_top = 4
        body_height = max(height - 6, 1)
        visible = candidates[self.main_offset : self.main_offset + body_height]
        for row, preview in enumerate(visible, start=body_top):
            selected = candidates[self.main_index].root == preview.root if candidates else False
            pkg = snapshot.packages.get(preview.root)
            marker = "[x]" if preview.root in self.selected_roots else "[ ]"
            name = preview.root[: name_width - 1]
            desc = (pkg.description if pkg else "")[: desc_width - 1]
            attr = curses.color_pair(1) | curses.A_BOLD if selected else curses.A_NORMAL
            self._safe_addstr(stdscr, row, 0, marker[:marker_width], attr)
            self._safe_addstr(stdscr, row, marker_width + 1, name.ljust(name_width), attr)
            if size_width:
                size_value = ""
                if self.sort_mode == "size" and pkg is not None:
                    size_value = format_bytes(pkg.installed_size)
                elif self.sort_mode == "reclaim":
                    size_value = format_bytes(preview.reclaimable_size)
                self._safe_addstr(stdscr, row, size_col, size_value.rjust(size_width), attr)
            self._safe_addstr(stdscr, row, desc_col, desc, attr)

        status_parts = [
            snapshot.status,
            f"sort {self.sort_mode}",
            format_count(len(candidates), "candidate"),
            f"selected {len(self.selected_roots)}",
            f"protected {len(self.model.user_protected)}",
        ]
        if candidates:
            selected = candidates[self.main_index]
            pkg = snapshot.packages.get(selected.root)
            if pkg is not None:
                status_parts.append(f"pkg {format_bytes(pkg.installed_size)}")
            status_parts.append(f"reclaim {format_bytes(selected.reclaimable_size)}")
        footer = " | ".join(status_parts)
        if message:
            footer = f"{footer} | {message}"
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))

    def _draw_detail(
        self,
        stdscr: curses.window,
        snapshot: RefreshSnapshot,
        message: str,
        height: int,
        width: int,
    ) -> None:
        if self.detail_root is None or self.detail_root not in snapshot.candidates:
            self.mode = "main"
            self.detail_root = None
            self._draw_main(stdscr, snapshot, message, height, width)
            return
        preview = snapshot.candidates[self.detail_root]
        pkg = snapshot.packages.get(preview.root)
        left_width = max(min(width // 4, 28), 22)
        right_width = max(min(width // 4, 32), 22)
        center_width = max(width - left_width - right_width - 2, 20)

        title = f"Inspect {preview.root}"
        marked = "yes" if preview.root in self.selected_roots else "no"
        help_text = "Space mark | x remove current | m protect/hide | Esc back | removal uses pacman with confirmation"
        self._safe_addstr(stdscr, 0, 0, title[: max(width - 1, 1)], curses.color_pair(2) | curses.A_BOLD)
        self._safe_addstr(stdscr, 1, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

        left_lines = [
            f"Package: {preview.root}",
            f"Marked: {marked}",
            f"Version: {pkg.version if pkg else '?'}",
            f"Installed size: {format_bytes(pkg.installed_size) if pkg else '?'}",
            f"Reclaimable: {format_bytes(preview.reclaimable_size)}",
            f"Removal set: {format_count(len(preview.removal_names), 'package')}",
            f"Install reason: {pkg.install_reason if pkg else '?'}",
            "",
            "Description:",
        ]
        if pkg:
            left_lines.extend(textwrap.wrap(pkg.description, width=max(left_width - 2, 16)) or [""])

        tree_lines = preview_tree_lines(preview, snapshot.packages, max(center_width - 1, 10))
        removal_items = sorted(
            (
                snapshot.packages[name]
                for name in preview.removal_names
                if name in snapshot.packages
            ),
            key=lambda item: item.installed_size,
            reverse=True,
        )
        right_lines = ["Packages to remove:"]
        for item in removal_items[: max(height - 5, 1)]:
            size = format_bytes(item.installed_size)
            label = f"{item.name} ({size})"
            right_lines.extend(textwrap.wrap(label, width=max(right_width - 1, 16)) or [""])

        self._draw_panel(stdscr, 3, 0, height - 4, left_width, left_lines, title="Summary")
        self._draw_panel(
            stdscr,
            3,
            left_width + 1,
            height - 4,
            center_width,
            tree_lines,
            title=f"Removal tree ({TREE_MAX_DEPTH} levels)",
        )
        self._draw_panel(
            stdscr,
            3,
            left_width + center_width + 2,
            height - 4,
            right_width,
            right_lines,
            title="Impact",
        )

        footer = snapshot.status
        if message:
            footer = f"{footer} | {message}"
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))

    def _draw_orphans(
        self,
        stdscr: curses.window,
        snapshot: RefreshSnapshot,
        message: str,
        height: int,
        width: int,
    ) -> None:
        rows = self._orphan_rows(snapshot)
        if self.orphan_index >= len(rows):
            self.orphan_index = max(len(rows) - 1, 0)
        body_top = 3
        body_height = max(height - 5, 1)
        max_offset = max(len(rows) - body_height, 0)
        if self.orphan_index < self.orphan_offset:
            self.orphan_offset = self.orphan_index
        elif self.orphan_index >= self.orphan_offset + body_height:
            self.orphan_offset = self.orphan_index - body_height + 1
        self.orphan_offset = min(self.orphan_offset, max_offset)

        selected_names = self._selected_orphan_names(rows)
        selected_size = sum(snapshot.packages[name].installed_size for name in selected_names if name in snapshot.packages)
        title = "Orphan Packages"
        subtitle = "Dependency-installed packages with no reverse deps. All are selected by default."
        help_text = "Space unselect/reselect | x remove selected | a select all | c clear all | m protect | q back"
        self._safe_addstr(stdscr, 0, 0, title[: max(width - 1, 1)], curses.color_pair(2) | curses.A_BOLD)
        self._safe_addstr(stdscr, 1, 0, subtitle[: max(width - 1, 1)], curses.A_DIM)
        self._safe_addstr(stdscr, 2, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

        marker_width = 3
        repo_width = 4
        name_width = max(min(width // 4, 28), 18)
        size_width = 10
        desc_width = max(width - marker_width - repo_width - name_width - size_width - 5, 18)
        header_attr = curses.color_pair(5) | curses.A_BOLD
        self._safe_addstr(stdscr, 3, 0, "Sel"[:marker_width], header_attr)
        self._safe_addstr(stdscr, 3, marker_width + 1, "Repo"[:repo_width], header_attr)
        self._safe_addstr(stdscr, 3, marker_width + repo_width + 2, "Package"[:name_width], header_attr)
        size_col = marker_width + repo_width + name_width + 3
        desc_col = size_col + size_width + 1
        self._safe_addstr(stdscr, 3, size_col, "Size"[:size_width], header_attr)
        self._safe_addstr(stdscr, 3, desc_col, "Description"[:desc_width], header_attr)

        body_top = 4
        body_height = max(height - 6, 1)
        visible = rows[self.orphan_offset : self.orphan_offset + body_height]
        for row, pkg in enumerate(visible, start=body_top):
            selected = rows[self.orphan_index].name == pkg.name if rows else False
            marker = "[ ]" if pkg.name in self.orphan_deselected else "[x]"
            repo = "off" if pkg.official else "aur"
            attr = curses.color_pair(1) | curses.A_BOLD if selected else curses.A_NORMAL
            self._safe_addstr(stdscr, row, 0, marker[:marker_width], attr)
            self._safe_addstr(stdscr, row, marker_width + 1, repo[:repo_width], attr)
            self._safe_addstr(stdscr, row, marker_width + repo_width + 2, pkg.name[: name_width - 1].ljust(name_width), attr)
            self._safe_addstr(stdscr, row, size_col, format_bytes(pkg.installed_size).rjust(size_width), attr)
            self._safe_addstr(stdscr, row, desc_col, pkg.description[: desc_width - 1], attr)

        if not rows:
            self._safe_addstr(stdscr, body_top, 0, "No orphan packages.", curses.A_DIM)

        status_parts = [
            snapshot.status,
            format_count(len(rows), "orphan"),
            f"selected {len(selected_names)}",
            f"size {format_bytes(selected_size)}",
        ]
        footer = " | ".join(status_parts)
        if message:
            footer = f"{footer} | {message}"
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))

    def _draw_protected(
        self,
        stdscr: curses.window,
        snapshot: RefreshSnapshot,
        message: str,
        height: int,
        width: int,
    ) -> None:
        names = self.model.protected_names(snapshot.packages)
        if self.protected_index >= len(names):
            self.protected_index = max(len(names) - 1, 0)
        body_top = 3
        body_height = max(height - 5, 1)
        max_offset = max(len(names) - body_height, 0)
        if self.protected_index < self.protected_offset:
            self.protected_offset = self.protected_index
        elif self.protected_index >= self.protected_offset + body_height:
            self.protected_offset = self.protected_index - body_height + 1
        self.protected_offset = min(self.protected_offset, max_offset)

        title = "Protected Packages"
        help_text = "u unprotect | q back"
        subtitle = f"Built-in protected defaults are always hidden. User protected: {len(names)}"
        self._safe_addstr(stdscr, 0, 0, title[: max(width - 1, 1)], curses.color_pair(2) | curses.A_BOLD)
        self._safe_addstr(stdscr, 1, 0, subtitle[: max(width - 1, 1)], curses.A_DIM)
        self._safe_addstr(stdscr, 2, 0, help_text[: max(width - 1, 1)], curses.A_DIM)

        visible = names[self.protected_offset : self.protected_offset + body_height]
        for row, name in enumerate(visible, start=body_top):
            selected = names[self.protected_index] == name if names else False
            pkg = snapshot.packages.get(name)
            label = name if pkg is None else f"{name}  {pkg.description}"
            attr = curses.color_pair(1) | curses.A_BOLD if selected else curses.A_NORMAL
            self._safe_addstr(stdscr, row, 0, label[: max(width - 1, 1)], attr)
        if not names:
            self._safe_addstr(stdscr, body_top, 0, "No user-protected packages.", curses.A_DIM)

        footer = snapshot.status
        if message:
            footer = f"{footer} | {message}"
        self._safe_addstr(stdscr, height - 1, 0, footer[: max(width - 1, 1)], curses.color_pair(4))

    def _draw_panel(
        self,
        stdscr: curses.window,
        top: int,
        left: int,
        height: int,
        width: int,
        lines: list[str],
        title: str,
    ) -> None:
        if height <= 1 or width <= 2:
            return
        self._safe_addstr(stdscr, top, left, f"[{title}]"[:width], curses.color_pair(5) | curses.A_BOLD)
        for row_offset, line in enumerate(lines[: max(height - 1, 1)], start=1):
            self._safe_addstr(stdscr, top + row_offset, left, line[: max(width - 1, 1)], curses.A_NORMAL)

    def _draw_confirmation(
        self,
        stdscr: curses.window,
        snapshot: RefreshSnapshot,
        height: int,
        width: int,
    ) -> None:
        if self.confirm_plan is None:
            return
        roots = ", ".join(self.confirm_plan.roots[:3])
        if len(self.confirm_plan.roots) > 3:
            roots = f"{roots}, ..."
        box_width = min(max(width - 8, 30), 70)
        box_height = 9
        top = max((height - box_height) // 2, 0)
        left = max((width - box_width) // 2, 0)
        for row in range(box_height):
            self._safe_addstr(stdscr, top + row, left, " " * box_width, curses.color_pair(6) | curses.A_BOLD)
        lines = [
            "Confirm removal",
            f"Selected roots: {len(self.confirm_plan.roots)}",
            f"Roots: {roots}",
            f"Packages removed: {len(self.confirm_plan.removal_names)}",
            f"Reclaimable size: {format_bytes(self.confirm_plan.reclaimable_size)}",
            "Press y to run pacman, n to cancel.",
        ]
        for offset, line in enumerate(lines, start=1):
            self._safe_addstr(
                stdscr,
                top + offset,
                left + 2,
                line[: max(box_width - 4, 1)],
                curses.A_BOLD if offset == 1 else curses.A_NORMAL,
            )

    def _perform_removal(self, stdscr: curses.window) -> None:
        plan = self.confirm_plan
        if plan is None:
            return
        command = shell_command_for_removal(plan.roots)
        self.confirm_plan = None
        curses.def_prog_mode()
        curses.endwin()
        print(f"Running: {' '.join(shlex.quote(part) for part in command)}")
        print("pacman will ask for confirmation before removing anything.")
        print()
        try:
            completed = subprocess.run(command, check=False)
            returncode = completed.returncode
        except FileNotFoundError as exc:
            returncode = 127
            print(str(exc))
        input("\nPress Enter to return to the TUI...")
        curses.reset_prog_mode()
        stdscr.keypad(True)
        stdscr.nodelay(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        if returncode == 0:
            self.selected_roots.difference_update(plan.roots)
            self.orphan_deselected.difference_update(plan.roots)
            self.mode = "main"
            self.detail_root = None
            self.model.apply_local_removal(plan)
        else:
            self.model.set_message(f"Removal exited with code {returncode}.", ttl=12.0)

    @staticmethod
    def _safe_addstr(
        window: curses.window,
        y: int,
        x: int,
        text: str,
        attr: int = curses.A_NORMAL,
    ) -> None:
        try:
            window.addnstr(y, x, text, max(len(text), 0), attr)
        except curses.error:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Conservative Arch package cleanup TUI for installed official packages."
    )
    return parser.parse_args()


def main() -> int:
    parse_args()
    model = PackageCleanupModel()
    model.start()
    try:
        PackageCleanupUI(model).run()
    finally:
        model.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
