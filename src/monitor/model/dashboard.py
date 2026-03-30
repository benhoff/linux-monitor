from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from monitor.app.monitor_tui import BASE_TAB_ORDER, BASE_TAB_TITLES, MonitorBackend


@dataclass
class SectionState:
    title: str
    lines: list[str] = field(default_factory=lambda: ["Loading..."])
    loading: bool = True
    last_updated: float = 0.0
    duration: float = 0.0
    last_error: str | None = None


@dataclass(frozen=True)
class Collector:
    key: str
    tab: str
    title: str
    interval: int
    func: Callable[[], list[str]]


class DashboardModel:
    def __init__(self) -> None:
        self.backend = MonitorBackend()
        self.collectors = self._build_collectors()
        self.tab_order = tuple(
            tab for tab in BASE_TAB_ORDER if any(collector.tab == tab for collector in self.collectors)
        )
        self.tab_titles = {tab: BASE_TAB_TITLES[tab] for tab in self.tab_order}
        self.states = {collector.key: SectionState(title=collector.title) for collector in self.collectors}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.force_refresh = threading.Event()

    def _build_collectors(self) -> list[Collector]:
        backend = self.backend
        collectors = [
            Collector("top_problems", "tier1", "Top Problems", 15, backend.collect_top_problems),
            Collector("snapshot_health", "tier1", "Privileged Snapshot", 15, backend.collect_snapshot_health),
            Collector("systemd", "tier1", "Systemd / Service Health", 20, backend.collect_systemd),
            Collector("logs", "tier1", "Logs / Errors", 20, backend.collect_logs),
            Collector("storage", "tier1", "Storage / Capacity", 20, backend.collect_storage),
            Collector("diff_snapshot", "tier1", "Diff Snapshot", 15, backend.collect_diff_snapshot),
            Collector("uptime", "tier1", "Uptime", 15, backend.collect_uptime),
            Collector("memory", "tier2", "Memory / Pressure", 10, backend.collect_memory),
            Collector("cpu", "tier2", "CPU / System Load", 10, backend.collect_cpu),
            Collector("thermal", "tier2", "Thermal / Power", 10, backend.collect_thermal),
            Collector("hardware", "tier2", "Hardware Health", 30, backend.collect_hardware),
            Collector("fs_integrity", "tier2", "Filesystem Integrity", 30, backend.collect_fs_integrity),
            Collector("network", "tier3", "Network State", 30, backend.collect_network),
            Collector("ethernet", "tier3", "Ethernet Intelligence", 30, backend.collect_ethernet),
            Collector("wifi", "tier3", "Wi-Fi Intelligence", 30, backend.collect_wifi),
            Collector("bluetooth", "tier3", "Bluetooth", 30, backend.collect_bluetooth),
            Collector("security", "tier3", "Security / Exposure Surface", 30, backend.collect_security),
            Collector("hygiene", "tier3", "System Hygiene", 300, backend.collect_hygiene),
            Collector("boot", "tier3", "Boot / Regression Signals", 300, backend.collect_boot),
        ]
        if backend.container_monitoring_enabled():
            collectors.insert(-2, Collector("containers", "tier3", "Containers / Docker", 45, backend.collect_containers))
        if backend.package_monitoring_enabled():
            collectors.insert(
                4,
                Collector("packages", "tier1", "Priority Packages", 30, backend.collect_packages),
            )
            collectors.append(
                Collector("pending_updates", "packages", "Official Repo Updates", 60, backend.collect_pending_updates)
            )
            if backend.supports_aur:
                collectors.append(Collector("aur_updates", "aur", "AUR Updates", 60, backend.collect_aur_updates))
        if backend.capture_monitoring_enabled():
            collectors.insert(
                13 if backend.package_monitoring_enabled() else 12,
                Collector("device_specific", "tier2", "Device-Specific Signals", 30, backend.collect_device_specific),
            )
        return collectors

    def start_background_tasks(self) -> None:
        self.backend.start_package_worker()

    def refresh_sync(self, tab: str | None = None) -> None:
        for collector in self.collectors:
            if tab is not None and tab != "all" and collector.tab != tab:
                continue
            self._refresh_collector(collector)

    def _refresh_collector(self, collector: Collector) -> None:
        started = time.time()
        with self.lock:
            state = self.states[collector.key]
            state.loading = True
        error = None
        try:
            lines = collector.func()
            if not lines:
                lines = ["No data returned."]
        except Exception as exc:  # pragma: no cover - defensive path
            error = str(exc)
            lines = [f"Collector failed: {exc}"]
        finished = time.time()
        with self.lock:
            state = self.states[collector.key]
            state.lines = lines
            state.loading = False
            state.last_updated = finished
            state.duration = finished - started
            state.last_error = error

    def refresh_loop(self) -> None:
        while not self.stop_event.is_set():
            now = time.time()
            force = self.force_refresh.is_set()
            if force:
                self.force_refresh.clear()
            due: list[Collector] = []
            with self.lock:
                for collector in self.collectors:
                    state = self.states[collector.key]
                    if force or state.last_updated == 0.0 or now - state.last_updated >= collector.interval:
                        due.append(collector)
            if not due:
                self.stop_event.wait(0.25)
                continue
            for collector in due:
                if self.stop_event.is_set():
                    break
                self._refresh_collector(collector)

    def request_refresh(self) -> None:
        self.backend.request_package_refresh()
        self.force_refresh.set()

    def toggle_package_sort(self) -> None:
        self.backend.cycle_package_sort_mode()
        self.force_refresh.set()

    def snapshot(self, tab: str) -> list[tuple[Collector, SectionState]]:
        with self.lock:
            selected = [
                (collector, self.states[collector.key])
                for collector in self.collectors
                if collector.tab == tab
            ]
            return [
                (
                    collector,
                    SectionState(
                        title=state.title,
                        lines=list(state.lines),
                        loading=state.loading,
                        last_updated=state.last_updated,
                        duration=state.duration,
                        last_error=state.last_error,
                    ),
                )
                for collector, state in selected
            ]

    def overall_status(self) -> str:
        with self.lock:
            loading = sum(1 for state in self.states.values() if state.loading)
            updated = [state.last_updated for state in self.states.values() if state.last_updated]
        last = datetime.fromtimestamp(max(updated)).strftime("%H:%M:%S") if updated else "never"
        return f"loading {loading} | last update {last}"

    def stop(self) -> None:
        self.stop_event.set()
        self.backend.stop_background_tasks()
