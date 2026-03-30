from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from monitor.shared.command import run_command
from monitor.shared.constants import ETHERNET_LOG_PATTERN, WIFI_LOG_PATTERN
from monitor.shared.formatting import first_nonempty_line, format_bytes, format_duration_compact, single_line
from monitor.shared.parsing_bluetooth import (
    parse_bluetoothctl_devices,
    parse_bluetoothctl_info,
    parse_bluetoothctl_show,
)
from monitor.shared.parsing_journal import parse_journal_lines
from monitor.shared.parsing_network import (
    parse_ethtool_output,
    parse_iw_channel_details,
    parse_iw_link_output,
    parse_iw_station_dump,
    parse_proc_net_wireless_text,
    parse_rfkill_output,
)
from monitor.shared.text import line_list, parse_float, parse_int, read_lines, read_text, shorten


BLUETOOTH_LOG_PATTERN = r"bluetooth|BlueZ|btusb|btintel|btmtk|hci\d+"
INTERFACE_STATES = frozenset({"UP", "DOWN", "UNKNOWN", "DORMANT", "LOWERLAYERDOWN", "NOTPRESENT"})


class NetworkCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    @staticmethod
    def _default_route_interface(route: str) -> str | None:
        match = re.search(r"\bdev\s+(\S+)", route)
        if not match:
            return None
        return match.group(1)

    @staticmethod
    def _parse_interface_line(line: str) -> tuple[str, str]:
        parts = line.split()
        if len(parts) < 2:
            return "", ""
        return parts[0], parts[1].upper()

    def visible_interfaces(self, interfaces: Sequence[str], default_route: str) -> list[str]:
        default_iface = self._default_route_interface(default_route)
        visible: list[str] = []
        fallback: list[str] = []
        for raw in interfaces:
            line = str(raw).strip()
            if not line:
                continue
            name, state = self._parse_interface_line(line)
            if not name or name == "lo":
                continue
            if state not in INTERFACE_STATES:
                return [line]
            fallback.append(line)
            if name == default_iface or state != "DOWN":
                visible.append(line)
        return visible[:4] if visible else fallback[:2]

    def interface_summary(self) -> list[str]:
        result = run_command(["ip", "-brief", "address"], timeout=3.0)
        if result.stdout:
            return line_list(result.stdout, limit=8)
        if result.missing:
            return ["ip not found."]
        return [shorten(single_line(result.stderr), 140) or "No interfaces available."]

    def default_route(self) -> str:
        result = run_command(["ip", "route", "show", "default"], timeout=3.0)
        if result.stdout:
            return result.stdout.splitlines()[0]
        if result.missing:
            return "ip not found"
        if result.stderr:
            return shorten(single_line(result.stderr), 140)
        return "no default route"

    def dns_servers(self) -> str:
        resolvectl = run_command(["resolvectl", "dns"], timeout=3.0)
        if resolvectl.stdout:
            servers = []
            for raw in resolvectl.stdout.splitlines():
                parts = raw.split(":", 1)
                if len(parts) == 2:
                    servers.append(parts[1].strip())
            if servers:
                return " | ".join(servers[:4])
        nameservers = []
        for raw in read_lines(Path("/etc/resolv.conf")):
            if raw.startswith("nameserver "):
                nameservers.append(raw.split(None, 1)[1])
        if nameservers:
            return ", ".join(nameservers)
        return "no nameservers found"

    def dns_check(self) -> str:
        result = run_command(["getent", "ahosts", self.backend.dns_probe_host], timeout=3.0)
        if result.stdout:
            return result.stdout.splitlines()[0].split()[0]
        if result.stderr:
            return shorten(single_line(result.stderr), 120)
        return "resolution failed"

    def socket_counts(self) -> tuple[int | None, int | None]:
        established = run_command(["ss", "-tun", "state", "established", "-H"], timeout=3.0)
        listening = run_command(["ss", "-ltnu", "-H"], timeout=3.0)
        established_count = None if established.stderr and not established.stdout else len(line_list(established.stdout))
        listening_count = None if listening.stderr and not listening.stdout else len(line_list(listening.stdout))
        return established_count, listening_count

    def collect(self) -> list[str]:
        privileged = self.backend._privileged_section("network")
        if privileged:
            snapshot_line = self.backend._privileged_snapshot_line()
            interfaces = privileged.get("interfaces", [])
            default_route = str(privileged.get("default_route", "no default route"))
            dns_servers = str(privileged.get("dns_servers", "no nameservers found"))
            dns_check = str(privileged.get("dns_check", "resolution failed"))
            connections = privileged.get("connections", {})
            established = None
            listening = None
            if isinstance(connections, dict):
                established = connections.get("established")
                listening = connections.get("listening")
            lines = []
            if snapshot_line:
                lines.append(snapshot_line)
            visible_interfaces = self.visible_interfaces(
                [str(item) for item in interfaces] if isinstance(interfaces, list) else [],
                default_route,
            )
            lines.append("Interfaces:")
            if visible_interfaces:
                for item in visible_interfaces:
                    lines.append(f"  {item}")
            else:
                lines.append("  No interfaces available.")
            lines.append(f"Default route: {default_route}")
            lines.append(f"DNS: {dns_servers} | {self.backend.dns_probe_host} -> {dns_check}")
            if established is None or listening is None:
                lines.append("Connections: unavailable (socket inspection failed)")
            else:
                lines.append(f"Connections: {established} established | {listening} listening sockets")
            return lines

        interfaces = self.interface_summary()
        default_route = self.default_route()
        dns_servers = self.dns_servers()
        dns_check = self.backend.cached("dns_check", 60.0, self.dns_check)
        established, listening = self.socket_counts()
        visible_interfaces = self.visible_interfaces(interfaces, default_route)

        lines = ["Interfaces:"]
        for item in visible_interfaces[:6]:
            lines.append(f"  {item}")
        if not visible_interfaces:
            lines.append("  No interfaces available.")
        lines.append(f"Default route: {default_route}")
        lines.append(f"DNS: {dns_servers} | {self.backend.dns_probe_host} -> {dns_check}")
        if established is None or listening is None:
            lines.append("Connections: unavailable (socket inspection failed)")
        else:
            lines.append(f"Connections: {established} established | {listening} listening sockets")
        return lines


class EthernetCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    @staticmethod
    def ethernet_interface_sort_key(entry: dict[str, object]) -> tuple[int, int, int, str]:
        default_route = 0 if entry.get("default_route") else 1
        connected = 0 if entry.get("connected") else 1
        carrier = 0 if entry.get("carrier") else 1
        return (default_route, connected, carrier, str(entry.get("interface", "")))

    @staticmethod
    def _read_nonnegative_int(path: Path) -> int | None:
        raw = read_text(path).strip()
        if not raw:
            return None
        value = parse_int(raw, default=-1)
        return value if value >= 0 else None

    @staticmethod
    def _default_route_interface(route: str) -> str | None:
        match = re.search(r"\bdev\s+(\S+)", route)
        if not match:
            return None
        return match.group(1)

    def ethernet_interfaces(self) -> list[str]:
        root = Path("/sys/class/net")
        if not root.exists():
            return []
        names = []
        for path in sorted(root.iterdir()):
            if path.name == "lo":
                continue
            if (path / "wireless").exists() or (path / "phy80211").exists():
                continue
            if parse_int(read_text(path / "type"), default=0) != 1:
                continue
            if not (path / "device").exists():
                continue
            names.append(path.name)
        return names

    def ethernet_logs(self) -> list[str]:
        pattern = ETHERNET_LOG_PATTERN
        interfaces = self.ethernet_interfaces()
        if interfaces:
            pattern = pattern + "|" + "|".join(re.escape(name) for name in interfaces[:6])
        result = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={pattern}",
                "-n",
                "12",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        return parse_journal_lines(result, limit=8)

    @staticmethod
    def issue_logs(entries: Sequence[str]) -> list[str]:
        issue_keywords = (
            "error",
            "fail",
            "failed",
            "timeout",
            "reset",
            "down",
            "lost",
            "carrier",
            "degraded",
            "flap",
        )
        return [entry for entry in entries if any(token in entry.lower() for token in issue_keywords)][:4]

    def live_state(self) -> dict[str, object]:
        default_route = self.backend.cached("default_route", 60.0, self.backend.network.default_route)
        default_route_iface = self._default_route_interface(str(default_route))
        interfaces: list[dict[str, object]] = []
        for name in self.ethernet_interfaces():
            sysfs = Path("/sys/class/net") / name
            carrier = read_text(sysfs / "carrier").strip() == "1"
            entry: dict[str, object] = {
                "interface": name,
                "operstate": read_text(sysfs / "operstate").strip() or "unknown",
                "carrier": carrier,
                "connected": carrier,
                "mac": read_text(sysfs / "address").strip() or "",
                "mtu": parse_int(read_text(sysfs / "mtu"), default=0),
                "default_route": name == default_route_iface,
            }
            try:
                entry["driver"] = (sysfs / "device" / "driver").resolve().name
            except OSError:
                pass

            speed = self._read_nonnegative_int(sysfs / "speed")
            if isinstance(speed, int) and speed > 0:
                entry["speed_mbps"] = speed

            duplex = read_text(sysfs / "duplex").strip().lower()
            if duplex and "unknown" not in duplex:
                entry["duplex"] = duplex

            for key in (
                "carrier_changes",
                "carrier_up_count",
                "carrier_down_count",
            ):
                value = self._read_nonnegative_int(sysfs / key)
                if value is not None:
                    entry[key] = value

            stats_dir = sysfs / "statistics"
            for key in (
                "rx_bytes",
                "tx_bytes",
                "rx_packets",
                "tx_packets",
                "rx_errors",
                "tx_errors",
                "rx_dropped",
                "tx_dropped",
            ):
                value = self._read_nonnegative_int(stats_dir / key)
                if value is not None:
                    entry[key] = value

            ethtool = run_command(["ethtool", name], timeout=3.0)
            if ethtool.stdout:
                entry.update(parse_ethtool_output(ethtool.stdout))
            interfaces.append(entry)

        logs = self.backend.cached("ethernet_logs", 60.0, self.ethernet_logs)
        return {
            "interfaces": interfaces,
            "logs": logs,
        }

    def state(self) -> dict[str, object]:
        privileged = self.backend._privileged_section("ethernet")
        if privileged:
            return privileged
        live = self.backend.cached("ethernet_live_state", 30.0, self.live_state)
        if isinstance(live, dict):
            return live
        return {}

    def summary_line(self, entry: dict[str, object]) -> str:
        iface = str(entry.get("interface", "ethernet"))
        operstate = str(entry.get("operstate", "unknown")).strip()
        speed = entry.get("speed_mbps")
        duplex = str(entry.get("duplex", "")).strip()
        parts = [iface]
        if entry.get("default_route"):
            parts.append("default route")
        if entry.get("connected"):
            parts.append(operstate or "up")
        else:
            parts.append("link down")
        if isinstance(speed, int) and speed > 0:
            parts.append(f"{speed} Mb/s")
        if duplex:
            parts.append(f"{duplex} duplex")
        return " | ".join(parts)

    @staticmethod
    def significant_error_count(entry: dict[str, object]) -> int:
        total = 0
        for key in ("rx_errors", "tx_errors"):
            value = entry.get(key)
            if isinstance(value, int) and value > 0:
                total += value
        return total

    @staticmethod
    def significant_drop_count(entry: dict[str, object]) -> int:
        total = 0
        for key in ("rx_dropped", "tx_dropped"):
            value = entry.get(key)
            if isinstance(value, int) and value > 0:
                total += value
        return total if total >= 10 else 0

    @staticmethod
    def link_down_count(entry: dict[str, object]) -> int:
        down_count = entry.get("carrier_down_count")
        if isinstance(down_count, int) and down_count >= 0:
            return down_count
        carrier_changes = entry.get("carrier_changes")
        if isinstance(carrier_changes, int) and carrier_changes >= 0:
            return carrier_changes // 2
        return 0

    def issue_summary(self, entry: dict[str, object]) -> list[str]:
        if not entry.get("connected"):
            operstate = str(entry.get("operstate", "unknown")).strip()
            return [f"link down ({operstate})"]

        issues: list[str] = []
        speed = entry.get("speed_mbps")
        duplex = str(entry.get("duplex", "")).strip()
        autoneg = str(entry.get("autoneg", "")).strip()
        error_count = self.significant_error_count(entry)
        drop_count = self.significant_drop_count(entry)
        down_count = self.link_down_count(entry)

        if isinstance(speed, int) and 0 < speed < 100:
            issues.append(f"negotiated {speed} Mb/s")
        if duplex == "half":
            issues.append("half-duplex")
        if autoneg == "off":
            issues.append("autoneg off")
        if error_count > 0:
            issues.append(f"{error_count} error counters")
        if drop_count > 0:
            issues.append(f"{drop_count} dropped packets")
        if down_count >= 5:
            issues.append(f"{down_count} link drops")
        return issues

    def link_line(self, entry: dict[str, object]) -> str | None:
        if not entry.get("connected"):
            return "Link: no carrier"
        port = str(entry.get("port", "")).strip()
        autoneg = str(entry.get("autoneg", "")).strip()
        parts = []
        if port and port != "twisted pair":
            parts.append(port)
        if autoneg == "off":
            parts.append(f"autoneg {autoneg}")
        if not parts:
            return None
        return "Link: " + " | ".join(parts)

    def health_line(self, entry: dict[str, object], issue_logs: Sequence[str]) -> str:
        issues = self.issue_summary(entry)
        if issues:
            return "Health: " + " | ".join(issues)
        if issue_logs:
            return "Health: link up | recent Ethernet warnings present"
        if entry.get("connected"):
            speed = entry.get("speed_mbps")
            if isinstance(speed, int) and speed >= 2500:
                label = "multi-gig link"
            elif isinstance(speed, int) and speed >= 1000:
                label = "gigabit link"
            elif isinstance(speed, int) and speed > 0:
                label = f"{speed} Mb/s link"
            else:
                label = "link up"
            return f"Health: stable {label}"
        return "Health: no carrier"

    def digest(self) -> dict[str, object]:
        state = self.state()
        interfaces = state.get("interfaces", [])
        logs = state.get("logs", [])
        digest: dict[str, object] = {
            "present": False,
            "connected": False,
        }
        if isinstance(logs, list):
            digest["issue_count"] = len(self.issue_logs(logs))
        if not isinstance(interfaces, list) or not interfaces:
            return digest
        parsed = [entry for entry in interfaces if isinstance(entry, dict)]
        if not parsed:
            return digest
        parsed.sort(key=self.ethernet_interface_sort_key)
        active = parsed[0]
        digest["present"] = True
        digest["interface"] = str(active.get("interface", ""))
        digest["connected"] = bool(active.get("connected"))
        digest["default_route"] = bool(active.get("default_route"))
        speed = active.get("speed_mbps")
        if isinstance(speed, int):
            digest["speed_mbps"] = speed
        error_count = self.significant_error_count(active)
        if error_count:
            digest["error_count"] = error_count
        drop_count = self.significant_drop_count(active)
        if drop_count:
            digest["drop_count"] = drop_count
        link_down_count = self.link_down_count(active)
        if link_down_count:
            digest["link_down_count"] = link_down_count
        carrier_changes = active.get("carrier_changes")
        if isinstance(carrier_changes, int):
            digest["carrier_changes"] = carrier_changes
        return digest

    def collect(self) -> list[str]:
        state = self.state()
        snapshot_line = self.backend._privileged_snapshot_line() if self.backend._privileged_section("ethernet") else None
        interfaces = state.get("interfaces", [])
        logs = state.get("logs", [])

        lines: list[str] = []
        if snapshot_line:
            lines.append(snapshot_line)

        parsed = [entry for entry in interfaces if isinstance(entry, dict)] if isinstance(interfaces, list) else []
        if not parsed:
            lines.append("No physical Ethernet interfaces detected.")
            return lines

        parsed.sort(key=self.ethernet_interface_sort_key)
        issue_logs = self.issue_logs(logs) if isinstance(logs, list) else []
        for index, entry in enumerate(parsed[:2]):
            lines.append(self.summary_line(entry))
            entry_issue_logs = issue_logs if index == 0 else []
            health_line = self.health_line(entry, entry_issue_logs)
            if health_line:
                lines.append("  " + health_line)
            link_line = self.link_line(entry)
            if link_line:
                lines.append("  " + link_line)
            if index == 0 and issue_logs:
                lines.append("  Recent Ethernet issues:")
                for item in issue_logs[:3]:
                    lines.append(f"    {item}")
            if index < min(len(parsed[:2]), 2) - 1:
                lines.append("")

        if not issue_logs and parsed and not self.issue_summary(parsed[0]):
            return lines

        return lines


class BluetoothCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def unit_status(self, action: str, unit: str) -> str:
        result = run_command(["systemctl", action, unit], timeout=3.0)
        if result.stdout:
            return first_nonempty_line(result.stdout)
        if result.missing:
            return "systemctl not found"
        if result.timed_out:
            return "systemctl timed out"
        if result.stderr:
            lowered = result.stderr.lower()
            if "failed to connect to system scope bus" in lowered or "operation not permitted" in lowered:
                return "system bus unavailable"
            return shorten(single_line(first_nonempty_line(result.stderr)), 120)
        return "unknown"

    def rfkill_radios_from_sysfs(self, allowed_types: Sequence[str]) -> list[dict[str, object]]:
        type_filters = {entry.strip().lower() for entry in allowed_types}
        root = Path("/sys/class/rfkill")
        if not root.exists():
            return []
        radios: list[dict[str, object]] = []
        for path in sorted(root.iterdir()):
            radio_type = read_text(path / "type").strip().lower()
            if radio_type not in type_filters:
                continue
            radios.append(
                {
                    "name": read_text(path / "name").strip() or path.name,
                    "type": radio_type,
                    "soft_blocked": read_text(path / "soft").strip() == "1",
                    "hard_blocked": read_text(path / "hard").strip() == "1",
                }
            )
        return radios

    def bluetooth_adapters(self) -> list[str]:
        root = Path("/sys/class/bluetooth")
        if not root.exists():
            return []
        return sorted(path.name for path in root.iterdir())

    def bluetooth_logs(self) -> list[str]:
        result = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={BLUETOOTH_LOG_PATTERN}",
                "-n",
                "12",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        return parse_journal_lines(result, limit=8)

    def bluetoothctl_text(self, args: Sequence[str], timeout: float = 4.0) -> tuple[str, str | None]:
        result = run_command(["bluetoothctl", *args], timeout=timeout)
        if result.stdout:
            return result.stdout, None
        if result.missing:
            return "", "bluetoothctl not found"
        if result.timed_out:
            return "", "bluetoothctl timed out"
        if result.stderr:
            lowered = result.stderr.lower()
            if "dbus_connection_get_object_path_data" in lowered or "connection != null" in lowered:
                return "", "bluetoothctl failed to connect to D-Bus"
            return "", shorten(single_line(first_nonempty_line(result.stderr)), 120)
        return "", f"bluetoothctl exited {result.returncode}"

    @staticmethod
    def bluetooth_device_sort_key(entry: dict[str, object]) -> tuple[int, int, int, str]:
        connected = 0 if entry.get("connected") else 1
        trusted = 0 if entry.get("trusted") else 1
        paired = 0 if entry.get("paired") else 1
        name = str(entry.get("alias") or entry.get("name") or entry.get("address") or "")
        return (connected, trusted, paired, name.lower())

    @staticmethod
    def bluetooth_issue_logs(entries: Sequence[str]) -> list[str]:
        issue_keywords = (
            "error",
            "fail",
            "failed",
            "timeout",
            "disconnect",
            "denied",
            "blocked",
            "abort",
            "missing",
        )
        issues: list[str] = []
        for entry in entries:
            lowered = entry.lower()
            if "bluetoothctl" in lowered and "abort" in lowered:
                continue
            if "abort (libc.so.6" in lowered:
                continue
            if "_dbus_warn_check_failed" in lowered or "libdbus" in lowered:
                continue
            if any(token in lowered for token in issue_keywords):
                issues.append(entry)
        return issues[:4]

    @staticmethod
    def service_line(active: str, enabled: str) -> str:
        active_value = active.strip() or "unknown"
        enabled_value = enabled.strip() or "unknown"
        combined = " ".join((active_value, enabled_value)).lower()
        if "system bus unavailable" in combined:
            return "Service: unavailable (system bus unavailable)"
        if active_value == enabled_value:
            return f"Service: {active_value}"
        return f"Service: {active_value} | {enabled_value}"

    def live_state(self) -> dict[str, object]:
        service_active = self.unit_status("is-active", "bluetooth.service")
        service_enabled = self.unit_status("is-enabled", "bluetooth.service")
        adapters = self.bluetooth_adapters()
        rfkill = self.rfkill_radios_from_sysfs(("bluetooth",))
        if not rfkill:
            rfkill_result = run_command(["rfkill", "list"], timeout=3.0)
            rfkill = parse_rfkill_output(rfkill_result.stdout, allowed_types=("bluetooth",)) if rfkill_result.stdout else []

        controller: dict[str, object] = {}
        devices: list[dict[str, object]] = []
        notes: list[str] = []
        should_query_bluetoothctl = bool(adapters) or service_active in {"active", "activating"}
        if should_query_bluetoothctl:
            show_text, show_error = self.bluetoothctl_text(["show"], timeout=4.0)
            if show_text and "No default controller available" not in show_text:
                controller = parse_bluetoothctl_show(show_text)
            elif show_error:
                notes.append(show_error)

            paired_text, paired_error = self.bluetoothctl_text(["paired-devices"], timeout=4.0)
            connected_text, connected_error = self.bluetoothctl_text(["devices", "Connected"], timeout=4.0)

            known_devices: dict[str, dict[str, object]] = {}
            if paired_text:
                for entry in parse_bluetoothctl_devices(paired_text):
                    address = str(entry.get("address", "")).upper()
                    if not address:
                        continue
                    known_devices[address] = {**entry, "paired": True}
            if connected_text:
                for entry in parse_bluetoothctl_devices(connected_text):
                    address = str(entry.get("address", "")).upper()
                    if not address:
                        continue
                    known = known_devices.setdefault(address, dict(entry))
                    known.update(entry)
                    known["connected"] = True
            for error in (paired_error, connected_error):
                if error and error not in notes:
                    notes.append(error)

            for address in list(known_devices)[:10]:
                info_text, info_error = self.bluetoothctl_text(["info", address], timeout=4.0)
                if info_text:
                    known_devices[address].update(parse_bluetoothctl_info(info_text))
                elif info_error and info_error not in notes:
                    notes.append(info_error)
            devices = sorted(known_devices.values(), key=self.bluetooth_device_sort_key)

        logs = self.backend.cached("bluetooth_logs", 60.0, self.bluetooth_logs)
        return {
            "service_active": service_active,
            "service_enabled": service_enabled,
            "adapters": adapters,
            "rfkill": rfkill,
            "controller": controller,
            "devices": devices,
            "logs": logs,
            "notes": notes,
        }

    def state(self) -> dict[str, object]:
        live = self.backend.cached("bluetooth_live_state", 30.0, self.live_state)
        if isinstance(live, dict):
            return live
        return {}

    @staticmethod
    def bluetooth_device_line(entry: dict[str, object]) -> str:
        name = str(entry.get("alias") or entry.get("name") or entry.get("address") or "device").strip()
        address = str(entry.get("address", "")).strip()
        icon = str(entry.get("icon", "")).strip()
        parts = [name]
        if address and address != name:
            parts.append(address)
        if icon:
            parts.append(icon)
        flags = []
        if entry.get("connected"):
            flags.append("connected")
        if entry.get("trusted"):
            flags.append("trusted")
        if entry.get("paired"):
            flags.append("paired")
        if entry.get("blocked"):
            flags.append("blocked")
        battery = entry.get("battery_pct")
        rssi = entry.get("rssi_dbm")
        tx_power = entry.get("tx_power_dbm")
        if isinstance(battery, int) and battery >= 0:
            parts.append(f"battery {battery}%")
        if isinstance(rssi, (int, float)):
            parts.append(f"RSSI {rssi:.0f} dBm")
        if isinstance(tx_power, (int, float)):
            parts.append(f"tx {tx_power:.0f} dBm")
        if flags:
            parts.append("/".join(flags))
        return " | ".join(parts)

    def digest(self) -> dict[str, object]:
        state = self.state()
        adapters = state.get("adapters", [])
        rfkill = state.get("rfkill", [])
        controller = state.get("controller", {})
        devices = state.get("devices", [])
        logs = state.get("logs", [])
        digest: dict[str, object] = {
            "adapter_count": len(adapters) if isinstance(adapters, list) else 0,
            "blocked": False,
            "connected_count": 0,
            "paired_count": 0,
            "trusted_count": 0,
            "service_active": str(state.get("service_active", "unknown")),
        }
        if isinstance(rfkill, list):
            for radio in rfkill:
                if not isinstance(radio, dict):
                    continue
                if radio.get("soft_blocked") or radio.get("hard_blocked"):
                    digest["blocked"] = True
                    break
        if isinstance(controller, dict) and controller:
            powered = controller.get("powered")
            if isinstance(powered, bool):
                digest["powered"] = powered
            discovering = controller.get("discovering")
            if isinstance(discovering, bool):
                digest["discovering"] = discovering
        if isinstance(devices, list):
            parsed_devices = [entry for entry in devices if isinstance(entry, dict)]
            digest["connected_count"] = sum(1 for entry in parsed_devices if entry.get("connected"))
            digest["paired_count"] = sum(1 for entry in parsed_devices if entry.get("paired"))
            digest["trusted_count"] = sum(1 for entry in parsed_devices if entry.get("trusted"))
        if isinstance(logs, list):
            digest["issue_count"] = len(self.bluetooth_issue_logs(logs))
        return digest

    def collect(self) -> list[str]:
        state = self.state()
        adapters = state.get("adapters", [])
        rfkill = state.get("rfkill", [])
        controller = state.get("controller", {})
        devices = state.get("devices", [])
        logs = state.get("logs", [])
        notes = state.get("notes", [])
        service_active = str(state.get("service_active", "unknown"))
        service_enabled = str(state.get("service_enabled", "unknown"))

        lines: list[str] = [self.service_line(service_active, service_enabled)]

        if isinstance(adapters, list) and adapters:
            lines.append(f"Adapters: {len(adapters)} detected ({', '.join(adapters[:4])})")
        else:
            lines.append("Adapters: none detected")

        if isinstance(rfkill, list) and rfkill:
            radio_parts = []
            for radio in rfkill[:4]:
                if not isinstance(radio, dict):
                    continue
                name = str(radio.get("name", "bluetooth"))
                status = (
                    "hard-blocked"
                    if radio.get("hard_blocked")
                    else "soft-blocked"
                    if radio.get("soft_blocked")
                    else "unblocked"
                )
                radio_parts.append(f"{name} {status}")
            if radio_parts:
                lines.append("RFKill: " + " | ".join(radio_parts))

        if isinstance(controller, dict) and controller:
            parts = []
            name = str(controller.get("alias") or controller.get("name") or controller.get("address") or "controller").strip()
            address = str(controller.get("address", "")).strip()
            parts.append(name)
            if address and address != name:
                parts.append(address)
            powered = controller.get("powered")
            discoverable = controller.get("discoverable")
            pairable = controller.get("pairable")
            discovering = controller.get("discovering")
            if isinstance(powered, bool):
                parts.append("powered" if powered else "powered off")
            if isinstance(discoverable, bool):
                parts.append("discoverable" if discoverable else "non-discoverable")
            if isinstance(pairable, bool):
                parts.append("pairable" if pairable else "non-pairable")
            if isinstance(discovering, bool):
                parts.append("scanning" if discovering else "idle")
            lines.append("Controller: " + " | ".join(parts))

        parsed_devices = [entry for entry in devices if isinstance(entry, dict)] if isinstance(devices, list) else []
        connected_devices = [entry for entry in parsed_devices if entry.get("connected")]
        trusted_count = sum(1 for entry in parsed_devices if entry.get("trusted"))
        paired_count = sum(1 for entry in parsed_devices if entry.get("paired"))
        if paired_count or trusted_count or connected_devices:
            lines.append("Devices: " + f"{paired_count} paired | {trusted_count} trusted | {len(connected_devices)} connected")
        else:
            lines.append("Devices: none paired or connected")

        if connected_devices:
            lines.append("Connected devices:")
            for entry in connected_devices[:4]:
                lines.append(f"  {self.bluetooth_device_line(entry)}")
        elif parsed_devices and (paired_count or trusted_count):
            lines.append("Known devices:")
            for entry in parsed_devices[:4]:
                lines.append(f"  {self.bluetooth_device_line(entry)}")
        filtered_notes = []
        for note in notes if isinstance(notes, list) else []:
            note_text = str(note).strip()
            if not note_text:
                continue
            if "failed to connect to d-bus" in note_text.lower() and "system bus unavailable" in lines[0].lower():
                continue
            if note_text not in filtered_notes:
                filtered_notes.append(note_text)
        if filtered_notes:
            lines.append("Collector notes:")
            for note in filtered_notes[:3]:
                lines.append(f"  {note}")

        issues = self.bluetooth_issue_logs(logs) if isinstance(logs, list) else []
        if issues:
            lines.append("Recent Bluetooth logs:")
            for item in issues[:4]:
                lines.append(f"  {item}")
        return lines


class WifiCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def wireless_interfaces(self) -> list[str]:
        root = Path("/sys/class/net")
        if not root.exists():
            return []
        names = []
        for path in sorted(root.iterdir()):
            if (path / "wireless").exists() or (path / "phy80211").exists():
                names.append(path.name)
        return names

    def proc_net_wireless(self) -> dict[str, dict[str, object]]:
        return parse_proc_net_wireless_text(read_text(Path("/proc/net/wireless")))

    def wireless_logs(self) -> list[str]:
        result = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={WIFI_LOG_PATTERN}",
                "-n",
                "10",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        return parse_journal_lines(result, limit=6)

    def live_state(self) -> dict[str, object]:
        quality = self.backend.cached("proc_net_wireless", 30.0, self.proc_net_wireless)
        interfaces: list[dict[str, object]] = []
        for name in self.wireless_interfaces():
            sysfs = Path("/sys/class/net") / name
            entry: dict[str, object] = {
                "interface": name,
                "operstate": read_text(sysfs / "operstate").strip() or "unknown",
                "mac": read_text(sysfs / "address").strip() or "",
                "carrier": read_text(sysfs / "carrier").strip() == "1",
                "mtu": parse_int(read_text(sysfs / "mtu"), default=0),
            }
            try:
                entry["driver"] = (sysfs / "device" / "driver").resolve().name
            except OSError:
                pass

            info_result = run_command(["iw", "dev", name, "info"], timeout=3.0)
            if info_result.stdout:
                for raw in info_result.stdout.splitlines():
                    line = raw.strip()
                    if line.startswith("type "):
                        entry["type"] = line.split(None, 1)[1].strip()
                    elif line.startswith("channel "):
                        entry.update(parse_iw_channel_details(line))
                    elif line.startswith("txpower "):
                        number = parse_float(line)
                        if number is not None:
                            entry["tx_power_dbm"] = number

            link_result = run_command(["iw", "dev", name, "link"], timeout=3.0)
            if link_result.stdout:
                entry.update(parse_iw_link_output(link_result.stdout))

            station_result = run_command(["iw", "dev", name, "station", "dump"], timeout=4.0)
            if station_result.stdout:
                entry.update(parse_iw_station_dump(station_result.stdout))

            power_save_result = run_command(["iw", "dev", name, "get", "power_save"], timeout=3.0)
            if power_save_result.stdout:
                for raw in power_save_result.stdout.splitlines():
                    line = raw.strip()
                    if line.lower().startswith("power save:"):
                        entry["power_save"] = line.split(":", 1)[1].strip().lower()
                        break

            if isinstance(quality, dict) and name in quality:
                entry.update(quality[name])
            interfaces.append(entry)

        rfkill_result = run_command(["rfkill", "list"], timeout=3.0)
        radios = parse_rfkill_output(rfkill_result.stdout) if rfkill_result.stdout else []
        logs = self.backend.cached("wifi_logs", 60.0, self.wireless_logs)
        return {
            "interfaces": interfaces,
            "rfkill": radios,
            "logs": logs,
        }

    def state(self) -> dict[str, object]:
        privileged = self.backend._privileged_section("wifi")
        if privileged:
            return privileged
        live = self.backend.cached("wifi_live_state", 30.0, self.live_state)
        if isinstance(live, dict):
            return live
        return {}

    @staticmethod
    def interface_sort_key(entry: dict[str, object]) -> tuple[int, int, str]:
        connected = 0 if entry.get("connected") else 1
        carrier = 0 if entry.get("carrier") else 1
        return (connected, carrier, str(entry.get("interface", "")))

    @staticmethod
    def signal_label(signal_dbm: float | int | None) -> str:
        if not isinstance(signal_dbm, (int, float)):
            return "unknown signal"
        if signal_dbm >= -60:
            return "excellent signal"
        if signal_dbm >= -67:
            return "good signal"
        if signal_dbm >= -75:
            return "fair signal"
        return "weak signal"

    @staticmethod
    def issue_logs(entries: Sequence[str]) -> list[str]:
        issue_keywords = (
            "error",
            "fail",
            "failed",
            "warn",
            "timeout",
            "disconnect",
            "roam",
            "deauth",
            "auth",
            "blocked",
        )
        issues = []
        for entry in entries:
            lowered = entry.lower()
            if "wireless extensions" in lowered:
                continue
            if "will stop working for wi-fi 7 hardware" in lowered:
                continue
            if any(token in lowered for token in issue_keywords):
                issues.append(entry)
        return issues[:3]

    @staticmethod
    def rfkill_blocked(radios: Sequence[object]) -> bool:
        for radio in radios:
            if not isinstance(radio, dict):
                continue
            if radio.get("soft_blocked") or radio.get("hard_blocked"):
                return True
        return False

    @staticmethod
    def disconnected_assessment(entry: dict[str, object], blocked: bool) -> str:
        operstate = str(entry.get("operstate", "unknown")).strip()
        if blocked:
            return f"Assessment: blocked by RFKill | operstate {operstate}"
        return f"Assessment: disconnected | operstate {operstate}"

    @staticmethod
    def reliability_has_issue(text: str) -> bool:
        lowered = text.lower()
        return any(
            token in lowered
            for token in ("failed", "beacon loss", "driver retry discards", "missed beacon", "not authorized")
        )

    def summary_line(self, entry: dict[str, object]) -> str:
        iface = str(entry.get("interface", "wifi"))
        driver = str(entry.get("driver", "")).strip()
        operstate = str(entry.get("operstate", "unknown"))
        carrier = "carrier" if entry.get("carrier") else "no-carrier"
        mode = str(entry.get("type", "")).strip()
        parts = [f"{iface} {operstate}", carrier]
        if driver:
            parts.append(driver)
        if mode:
            parts.append(mode)
        return " | ".join(parts)

    def link_line(self, entry: dict[str, object]) -> str:
        if not entry.get("connected"):
            return "Link: not associated"
        ssid = str(entry.get("ssid", "")).strip() or "hidden SSID"
        bssid = str(entry.get("bssid", "")).strip()
        band = str(entry.get("band", "")).strip()
        channel = entry.get("channel")
        frequency = entry.get("frequency_mhz")
        width = entry.get("width_mhz")
        parts = [ssid]
        if bssid:
            parts.append(bssid)
        if band:
            parts.append(band)
        if isinstance(channel, int) and channel > 0:
            parts.append(f"ch {channel}")
        if isinstance(width, int) and width > 0:
            parts.append(f"{width} MHz")
        elif isinstance(frequency, int) and frequency > 0:
            parts.append(f"{frequency} MHz")
        return "Link: " + " | ".join(parts)

    def signal_line(self, entry: dict[str, object]) -> str:
        signal = entry.get("signal_dbm")
        noise = entry.get("noise_dbm")
        quality = entry.get("quality_pct")
        tx_power = entry.get("tx_power_dbm")
        parts = []
        if isinstance(signal, (int, float)):
            parts.append(f"{signal:.0f} dBm")
            parts.append(self.signal_label(signal))
        if isinstance(quality, (int, float)):
            parts.append(f"{quality:.0f}% quality")
        if isinstance(noise, (int, float)):
            parts.append(f"noise {noise:.0f} dBm")
        if isinstance(tx_power, (int, float)):
            parts.append(f"txpower {tx_power:.1f} dBm")
        return "Signal: " + (" | ".join(parts) if parts else "unavailable")

    @staticmethod
    def phy_line(entry: dict[str, object]) -> str:
        rx = entry.get("rx_bitrate_mbps")
        tx = entry.get("tx_bitrate_mbps")
        expected = entry.get("expected_throughput_mbps")
        power_save = str(entry.get("power_save", "")).strip()
        parts = []
        if isinstance(rx, (int, float)):
            parts.append(f"rx {rx:.1f} Mb/s")
        if isinstance(tx, (int, float)):
            parts.append(f"tx {tx:.1f} Mb/s")
        if isinstance(expected, (int, float)):
            parts.append(f"expected {expected:.1f} Mb/s")
        if power_save:
            parts.append(f"power save {power_save}")
        return "PHY: " + (" | ".join(parts) if parts else "unavailable")

    @staticmethod
    def traffic_line(entry: dict[str, object]) -> str:
        rx_bytes = entry.get("rx_bytes")
        tx_bytes = entry.get("tx_bytes")
        rx_packets = entry.get("rx_packets")
        tx_packets = entry.get("tx_packets")
        connected_seconds = entry.get("connected_seconds")
        parts = []
        if isinstance(rx_bytes, int) and rx_bytes >= 0:
            rx_label = format_bytes(rx_bytes)
            if isinstance(rx_packets, int):
                rx_label += f" / {rx_packets} pkts"
            parts.append(f"rx {rx_label}")
        if isinstance(tx_bytes, int) and tx_bytes >= 0:
            tx_label = format_bytes(tx_bytes)
            if isinstance(tx_packets, int):
                tx_label += f" / {tx_packets} pkts"
            parts.append(f"tx {tx_label}")
        if isinstance(connected_seconds, int) and connected_seconds >= 0:
            parts.append(f"connected {format_duration_compact(connected_seconds)}")
        return "Traffic: " + (" | ".join(parts) if parts else "unavailable")

    @staticmethod
    def reliability_line(entry: dict[str, object]) -> str:
        inactive_ms = entry.get("inactive_ms")
        retries = entry.get("tx_retries")
        failed = entry.get("tx_failed")
        beacon_loss = entry.get("beacon_loss")
        discard_retry = entry.get("discard_retry")
        missed_beacon = entry.get("missed_beacon")
        authorized = entry.get("authorized")
        authenticated = entry.get("authenticated")
        associated = entry.get("associated")
        parts = []
        if isinstance(inactive_ms, int):
            parts.append(f"idle {inactive_ms} ms")
        if isinstance(retries, int):
            parts.append(f"retries {retries}")
        if isinstance(failed, int):
            parts.append(f"failed {failed}")
        if isinstance(beacon_loss, int):
            parts.append(f"beacon loss {beacon_loss}")
        if isinstance(discard_retry, int) and discard_retry > 0:
            parts.append(f"driver retry discards {discard_retry}")
        if isinstance(missed_beacon, int) and missed_beacon > 0:
            parts.append(f"missed beacon {missed_beacon}")
        auth_states = []
        if isinstance(authorized, bool):
            auth_states.append("authorized" if authorized else "not authorized")
        if isinstance(authenticated, bool):
            auth_states.append("authenticated" if authenticated else "not authenticated")
        if isinstance(associated, bool):
            auth_states.append("associated" if associated else "not associated")
        if auth_states:
            parts.append(", ".join(auth_states))
        return "Reliability: " + (" | ".join(parts) if parts else "no station metrics")

    def assessment_line(self, entry: dict[str, object]) -> str:
        if not entry.get("connected"):
            operstate = str(entry.get("operstate", "unknown"))
            return f"Assessment: disconnected | operstate {operstate}"
        signal = entry.get("signal_dbm")
        band = str(entry.get("band", "")).strip()
        expected = entry.get("expected_throughput_mbps")
        power_save = str(entry.get("power_save", "")).strip()
        retries = entry.get("tx_retries")
        failed = entry.get("tx_failed")
        beacon_loss = entry.get("beacon_loss")
        parts = []
        parts.append(self.signal_label(signal if isinstance(signal, (int, float)) else None))
        if band:
            parts.append(f"{band} link")
        if isinstance(expected, (int, float)):
            if expected >= 400:
                parts.append("high expected throughput")
            elif expected >= 100:
                parts.append("moderate expected throughput")
            else:
                parts.append("low expected throughput")
        if isinstance(beacon_loss, int) and beacon_loss > 0:
            parts.append("beacon loss observed")
        elif isinstance(failed, int) and failed > 0:
            parts.append("tx failures observed")
        elif isinstance(retries, int) and retries > 200:
            parts.append("retry-heavy link")
        else:
            parts.append("no obvious retry pressure")
        if power_save == "on":
            parts.append("power save enabled")
        return "Assessment: " + " | ".join(parts)

    def digest(self) -> dict[str, object]:
        state = self.state()
        interfaces = state.get("interfaces", [])
        radios = state.get("rfkill", [])
        digest: dict[str, object] = {
            "present": False,
            "blocked": False,
            "connected": False,
        }
        if isinstance(radios, list):
            for radio in radios:
                if not isinstance(radio, dict):
                    continue
                if radio.get("soft_blocked") or radio.get("hard_blocked"):
                    digest["blocked"] = True
                    break
        if not isinstance(interfaces, list) or not interfaces:
            return digest
        parsed_interfaces = [entry for entry in interfaces if isinstance(entry, dict)]
        if not parsed_interfaces:
            return digest
        parsed_interfaces.sort(key=self.interface_sort_key)
        active = parsed_interfaces[0]
        digest["present"] = True
        digest["interface"] = str(active.get("interface", ""))
        digest["connected"] = bool(active.get("connected"))
        if active.get("connected"):
            digest["ssid"] = str(active.get("ssid", ""))
        signal = active.get("signal_dbm")
        if isinstance(signal, (int, float)):
            digest["signal_dbm"] = float(signal)
        retries = active.get("tx_retries")
        failed = active.get("tx_failed")
        beacon_loss = active.get("beacon_loss")
        if isinstance(retries, int):
            digest["tx_retries"] = retries
        if isinstance(failed, int):
            digest["tx_failed"] = failed
        if isinstance(beacon_loss, int):
            digest["beacon_loss"] = beacon_loss
        return digest

    def collect(self) -> list[str]:
        state = self.state()
        snapshot_line = self.backend._privileged_snapshot_line() if self.backend._privileged_section("wifi") else None
        interfaces = state.get("interfaces", [])
        radios = state.get("rfkill", [])
        logs = state.get("logs", [])

        lines: list[str] = []
        if snapshot_line:
            lines.append(snapshot_line)

        if isinstance(radios, list) and radios:
            radio_parts = []
            for radio in radios[:4]:
                if not isinstance(radio, dict):
                    continue
                name = str(radio.get("name", "wifi"))
                status = (
                    "hard-blocked"
                    if radio.get("hard_blocked")
                    else "soft-blocked"
                    if radio.get("soft_blocked")
                    else "unblocked"
                )
                radio_parts.append(f"{name} {status}")
            if radio_parts:
                lines.append("RFKill: " + " | ".join(radio_parts))

        parsed_interfaces = [entry for entry in interfaces if isinstance(entry, dict)] if isinstance(interfaces, list) else []
        if not parsed_interfaces:
            lines.append("No wireless interfaces detected.")
            return lines

        blocked = self.rfkill_blocked(radios if isinstance(radios, list) else [])
        parsed_interfaces.sort(key=self.interface_sort_key)
        for entry in parsed_interfaces[:2]:
            lines.append(self.summary_line(entry))
            if entry.get("connected"):
                lines.append("  " + self.link_line(entry))
                lines.append("  " + self.signal_line(entry))
                reliability = self.reliability_line(entry)
                if self.reliability_has_issue(reliability):
                    lines.append("  " + reliability)
                lines.append("  " + self.assessment_line(entry))
            else:
                lines.append("  " + self.disconnected_assessment(entry, blocked))

        issues = self.issue_logs(logs) if isinstance(logs, list) else []
        if issues:
            lines.append("Recent Wi-Fi logs:")
            for item in issues[:3]:
                lines.append(f"  {item}")
        return lines
