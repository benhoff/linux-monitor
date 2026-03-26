from __future__ import annotations

import re

from monitor.shared.text import parse_float, parse_int


def parse_bluetoothctl_devices(text: str) -> list[dict[str, object]]:
    devices: list[dict[str, object]] = []
    for raw in text.splitlines():
        match = re.match(r"^Device\s+([0-9A-F:]{17})\s+(.+)$", raw.strip(), re.IGNORECASE)
        if not match:
            continue
        devices.append(
            {
                "address": match.group(1).upper(),
                "name": match.group(2).strip(),
            }
        )
    return devices


def parse_bluetoothctl_show(text: str) -> dict[str, object]:
    state: dict[str, object] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        header = re.match(r"^Controller\s+([0-9A-F:]{17})\s+(.+?)(?:\s+\[default\])?$", line, re.IGNORECASE)
        if header:
            state["address"] = header.group(1).upper()
            state["name"] = header.group(2).strip()
            continue
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        lower = key.lower()
        if lower in {"powered", "discoverable", "discovering", "pairable"}:
            state[lower] = value.lower() == "yes"
        elif lower in {"name", "alias", "class", "modalias"}:
            state[lower] = value
    return state


def parse_bluetoothctl_info(text: str) -> dict[str, object]:
    state: dict[str, object] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        header = re.match(r"^Device\s+([0-9A-F:]{17})\s+(.+)$", line, re.IGNORECASE)
        if header:
            state["address"] = header.group(1).upper()
            state["name"] = header.group(2).strip()
            continue
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        lower = key.lower()
        if lower in {"name", "alias", "icon"}:
            state[lower] = value
        elif lower in {"paired", "trusted", "blocked", "connected", "legacypairing", "wakeallowed"}:
            state[lower] = value.lower() == "yes"
        elif lower == "battery percentage":
            match = re.search(r"\((\d+)\)", value)
            state["battery_pct"] = int(match.group(1)) if match else parse_int(value, default=-1)
        elif lower == "rssi":
            number = parse_float(value)
            if number is not None:
                state["rssi_dbm"] = number
        elif lower == "txpower":
            number = parse_float(value)
            if number is not None:
                state["tx_power_dbm"] = number
    return state
