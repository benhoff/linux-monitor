from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
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

