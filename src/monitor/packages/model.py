from __future__ import annotations

import concurrent.futures
import time
from dataclasses import replace
import threading

from monitor.packages.common import (
    CandidatePreview,
    MESSAGE_TTL_SECONDS,
    PREVIEW_WORKERS,
    PackageInfo,
    RefreshSnapshot,
    RemovalPlan,
    built_in_protected,
    format_count,
)
from monitor.packages.inventory import inventory_fingerprint, load_package_inventory, resolve_dependency_names
from monitor.packages.removal import removal_preview, validate_preview
from monitor.packages.state import load_state, save_state


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
                    self.snapshot.status = f"Validated {validated}/{len(roots)} removable roots..."

        with self.lock:
            self.snapshot.candidates = dict(valid_candidates)
            self.snapshot.validated_count = validated
            self.snapshot.loading = False
            self.snapshot.status = f"Loaded {len(valid_candidates)} removable candidates."
        if cache_dirty or cached_missing:
            self._save_cache()

