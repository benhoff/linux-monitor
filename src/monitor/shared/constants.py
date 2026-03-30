from __future__ import annotations

from pathlib import Path


DEFAULT_PRIVILEGED_SNAPSHOT_PATH = Path("/run/monitor/privileged_snapshot.json")
PRIVILEGED_SNAPSHOT_VERSION = 4
DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE = 15 * 60
DEFAULT_PRIVILEGED_SNAPSHOT_MODE = 0o644

PSEUDO_FILESYSTEMS = frozenset(
    {
        "autofs",
        "binfmt_misc",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "efivarfs",
        "fusectl",
        "hugetlbfs",
        "mqueue",
        "nsfs",
        "overlay",
        "proc",
        "pstore",
        "securityfs",
        "selinuxfs",
        "squashfs",
        "sysfs",
        "tmpfs",
        "tracefs",
    }
)

FS_LOG_PATTERN = (
    r"EXT4-fs error|BTRFS|XFS|Buffer I/O error|I/O error|"
    r"read-only file system|Remounting filesystem read-only|mount failure|corrupt"
)
HARDWARE_LOG_PATTERN = r"gpu|drm|hdmi|edid|nvme|ata|usb|pci|v4l2|camera|csi"
WIFI_LOG_PATTERN = r"wlan|wifi|wireless|wpa_supplicant|NetworkManager|cfg80211|mac80211"
ETHERNET_LOG_PATTERN = r"NIC Link is Up|NIC Link is Down|link is up|link is down|carrier|ethernet|e1000|e1000e|igc|r8169|r8152|atlantic"
