from __future__ import annotations

import re
from typing import Sequence

from monitor.shared.text import parse_float, parse_int


def wireless_band_label(frequency_mhz: int | None) -> str | None:
    if frequency_mhz is None:
        return None
    if frequency_mhz >= 5925:
        return "6 GHz"
    if frequency_mhz >= 4900:
        return "5 GHz"
    if frequency_mhz >= 2400:
        return "2.4 GHz"
    return f"{frequency_mhz} MHz"


def parse_iw_channel_details(raw: str) -> dict[str, object]:
    details: dict[str, object] = {}
    channel_match = re.search(r"\bchannel\s+(\d+)\b", raw)
    freq_match = re.search(r"\((\d+)\s*MHz\)", raw)
    width_match = re.search(r"width:\s*([0-9]+)\s*MHz", raw)
    center1_match = re.search(r"center1:\s*(\d+)", raw)
    if channel_match:
        details["channel"] = int(channel_match.group(1))
    if freq_match:
        frequency = int(freq_match.group(1))
        details["frequency_mhz"] = frequency
        details["band"] = wireless_band_label(frequency)
    if width_match:
        details["width_mhz"] = int(width_match.group(1))
    if center1_match:
        details["center1_mhz"] = int(center1_match.group(1))
    return details


def parse_iw_rate_mbps(raw: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.\d+)?)\s*MBit/s", raw)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def parse_proc_net_wireless_text(text: str) -> dict[str, dict[str, object]]:
    stats: dict[str, dict[str, object]] = {}
    for raw in text.splitlines()[2:]:
        if ":" not in raw:
            continue
        iface, rest = raw.split(":", 1)
        fields = rest.split()
        if len(fields) < 10:
            continue
        link = parse_float(fields[1])
        level = parse_float(fields[2])
        noise = parse_float(fields[3])
        if link is None or level is None or noise is None:
            continue
        quality_pct = max(0.0, min(link / 70.0 * 100.0, 100.0))
        stats[iface.strip()] = {
            "link_quality": round(link, 1),
            "quality_pct": round(quality_pct, 1),
            "signal_dbm": round(level, 1),
            "noise_dbm": round(noise, 1),
            "discard_nwid": parse_int(fields[4]),
            "discard_crypt": parse_int(fields[5]),
            "discard_frag": parse_int(fields[6]),
            "discard_retry": parse_int(fields[7]),
            "discard_misc": parse_int(fields[8]),
            "missed_beacon": parse_int(fields[9]),
        }
    return stats


def parse_iw_link_output(text: str) -> dict[str, object]:
    state: dict[str, object] = {"connected": False}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Connected to "):
            state["connected"] = True
            match = re.match(r"Connected to ([0-9a-f:]{17})", line, re.IGNORECASE)
            if match:
                state["bssid"] = match.group(1).lower()
        elif line == "Not connected.":
            state["connected"] = False
        elif line.startswith("SSID:"):
            state["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("freq:"):
            frequency = parse_int(line)
            if frequency > 0:
                state["frequency_mhz"] = frequency
                state["band"] = wireless_band_label(frequency)
        elif line.startswith("signal:"):
            value = parse_float(line)
            if value is not None:
                state["signal_dbm"] = value
        elif line.startswith("rx bitrate:"):
            bitrate = parse_iw_rate_mbps(line)
            if bitrate is not None:
                state["rx_bitrate_mbps"] = bitrate
        elif line.startswith("tx bitrate:"):
            bitrate = parse_iw_rate_mbps(line)
            if bitrate is not None:
                state["tx_bitrate_mbps"] = bitrate
        elif line.startswith("RX:"):
            match = re.search(r"RX:\s*(\d+)\s+bytes\s+\((\d+)\s+packets\)", line)
            if match:
                state["rx_bytes"] = int(match.group(1))
                state["rx_packets"] = int(match.group(2))
        elif line.startswith("TX:"):
            match = re.search(r"TX:\s*(\d+)\s+bytes\s+\((\d+)\s+packets\)", line)
            if match:
                state["tx_bytes"] = int(match.group(1))
                state["tx_packets"] = int(match.group(2))
    return state


def parse_iw_station_dump(text: str) -> dict[str, object]:
    state: dict[str, object] = {}
    in_station = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Station "):
            if in_station:
                break
            in_station = True
            continue
        if not in_station or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        lower = key.lower()
        if lower == "inactive time":
            number = parse_float(value)
            if number is not None:
                state["inactive_ms"] = int(number)
        elif lower == "connected time":
            number = parse_float(value)
            if number is not None:
                state["connected_seconds"] = int(number)
        elif lower == "signal avg":
            number = parse_float(value)
            if number is not None:
                state["signal_avg_dbm"] = number
        elif lower == "tx retries":
            number = parse_float(value)
            if number is not None:
                state["tx_retries"] = int(number)
        elif lower == "tx failed":
            number = parse_float(value)
            if number is not None:
                state["tx_failed"] = int(number)
        elif lower == "beacon loss":
            number = parse_float(value)
            if number is not None:
                state["beacon_loss"] = int(number)
        elif lower == "expected throughput":
            bitrate = parse_iw_rate_mbps(value)
            if bitrate is not None:
                state["expected_throughput_mbps"] = bitrate
        elif lower == "authorized":
            state["authorized"] = value.lower() == "yes"
        elif lower == "authenticated":
            state["authenticated"] = value.lower() == "yes"
        elif lower == "associated":
            state["associated"] = value.lower() == "yes"
        elif lower == "wmm/wme":
            state["wmm"] = value.lower() == "yes"
        elif lower == "mfp":
            state["mfp"] = value.lower() == "yes"
    return state


def parse_rfkill_output(text: str, allowed_types: Sequence[str] | None = None) -> list[dict[str, object]]:
    type_filters = {
        entry.strip().lower()
        for entry in (allowed_types or ("wireless lan", "wlan", "wifi"))
    }
    radios: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        header = re.match(r"^\d+:\s+([^:]+):\s+(.+)$", line.strip())
        if header:
            if current and str(current.get("type", "")).lower() in type_filters:
                radios.append(current)
            current = {
                "name": header.group(1).strip(),
                "type": header.group(2).strip(),
            }
            continue
        if current is None or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        lower = key.lower()
        if lower == "soft blocked":
            current["soft_blocked"] = value.lower() == "yes"
        elif lower == "hard blocked":
            current["hard_blocked"] = value.lower() == "yes"
    if current and str(current.get("type", "")).lower() in type_filters:
        radios.append(current)
    return radios
