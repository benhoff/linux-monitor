from __future__ import annotations

import ipaddress
import re
from typing import Sequence


def format_bytes(value: float | int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    size = float(value)
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            if size >= 100:
                return f"{size:.0f} {unit}"
            if size >= 10:
                return f"{size:.1f} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PiB"


def format_percent(numerator: float, denominator: float) -> str:
    if denominator <= 0:
        return "n/a"
    return f"{(numerator / denominator) * 100:.1f}%"


def parse_size_bytes(value: str) -> int | None:
    text = value.strip()
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?i?B)\b", text, re.IGNORECASE)
    if not match:
        return None
    amount = float(match.group(1))
    unit = match.group(2).upper()
    factors = {
        "B": 1,
        "KIB": 1024,
        "MIB": 1024**2,
        "GIB": 1024**3,
        "TIB": 1024**4,
        "PIB": 1024**5,
        "EIB": 1024**6,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
        "PB": 1000**5,
        "EB": 1000**6,
    }
    factor = factors.get(unit)
    if factor is None:
        return None
    return int(amount * factor)


def format_duration_compact(seconds: int | float) -> str:
    total = max(int(seconds), 0)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def format_eta(seconds: int | float) -> str:
    total = max(int(seconds), 0)
    if total < 60:
        return f"{total}s"
    if total < 3600:
        minutes, secs = divmod(total, 60)
        if secs >= 30:
            minutes += 1
        return f"{minutes}m"
    return format_duration_compact(total)


def single_line(value: str) -> str:
    return " ".join(value.split())


def first_nonempty_line(value: str) -> str:
    for line in value.splitlines():
        if line.strip():
            return line.strip()
    return ""


def summarize_list(items: Sequence[str], limit: int = 3) -> str:
    values = [item for item in items if item]
    if not values:
        return "none"
    if len(values) <= limit:
        return ", ".join(values)
    return ", ".join(values[:limit]) + f", +{len(values) - limit} more"


def split_socket_endpoint(endpoint: str) -> tuple[str, str]:
    value = endpoint.strip()
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            host = value[1:end]
            remainder = value[end + 1 :]
            if remainder.startswith(":"):
                return host, remainder[1:]
            return host, ""
    host, sep, port = value.rpartition(":")
    if sep:
        return host, port
    return value, ""


def is_loopback_endpoint(endpoint: str) -> bool:
    host, _port = split_socket_endpoint(endpoint)
    host = host.strip().strip("[]")
    if not host:
        return False
    lowered = host.lower()
    if lowered in {"localhost", "ip6-localhost"}:
        return True
    if lowered == "*":
        return False
    host = host.split("%", 1)[0]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
