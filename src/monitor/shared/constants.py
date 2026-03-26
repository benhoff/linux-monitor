from __future__ import annotations

from pathlib import Path


DEFAULT_PRIVILEGED_SNAPSHOT_PATH = Path("/run/monitor/privileged_snapshot.json")
PRIVILEGED_SNAPSHOT_VERSION = 3
DEFAULT_PRIVILEGED_SNAPSHOT_MAX_AGE = 15 * 60

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

