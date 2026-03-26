from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Sequence

from monitor.shared.command import run_command
from monitor.shared.formatting import single_line
from monitor.shared.parsing_journal import parse_journal_lines
from monitor.shared.text import line_list, read_text, shorten


CAPTURE_LOG_PATTERN = r"AVMatrix|HwsCapture|uvcvideo|videodev|v4l2|capture"
CAPTURE_STACK_MODULES = (
    "HwsCapture",
    "uvcvideo",
    "videodev",
    "videobuf2_v4l2",
    "videobuf2_common",
    "videobuf2_dma_contig",
)
ENCODER_KEYWORDS = ("nvenc", "vaapi", "v4l2m2m", "qsv", "amf", "rkmpp")


class CaptureCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def drm_connectors(self) -> list[str]:
        connectors = []
        for status_path in sorted(Path("/sys/class/drm").glob("card*-*/status")):
            connector = status_path.parent.name
            status = read_text(status_path).strip() or "unknown"
            connectors.append(f"{connector} {status}")
        return connectors

    @staticmethod
    def capture_slots(cards: Sequence[str]) -> set[str]:
        slots: set[str] = set()
        for raw in cards:
            match = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\b", raw, re.IGNORECASE)
            if match:
                slots.add(match.group(1))
        return slots

    def capture_cards(self) -> list[str]:
        result = run_command(["lspci", "-D", "-nn", "-k"], timeout=4.0)
        if not result.stdout:
            return []
        cards = []
        blocks = re.split(r"\n(?=[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\s)", result.stdout, flags=re.IGNORECASE)
        for block in blocks:
            lines = [line.rstrip() for line in block.splitlines() if line.strip()]
            if not lines:
                continue
            header = lines[0].strip()
            lowered = header.lower()
            if "avmatrix" not in lowered and "multimedia video controller" not in lowered and "capture" not in lowered:
                continue
            driver = ""
            modules = ""
            for raw in lines[1:]:
                stripped = raw.strip()
                lowered_detail = stripped.lower()
                if lowered_detail.startswith("kernel driver in use:"):
                    driver = stripped.split(":", 1)[1].strip()
                elif lowered_detail.startswith("kernel modules:"):
                    modules = stripped.split(":", 1)[1].strip()
            summary = header
            if driver:
                summary += f" | driver {driver}"
            elif modules:
                summary += f" | modules {modules}"
            cards.append(summary)
        return cards[:6]

    def capture_modules(self) -> list[str]:
        result = run_command(["lsmod"], timeout=3.0)
        if not result.stdout:
            return []
        modules = []
        for raw in line_list(result.stdout):
            name = raw.split()[0]
            if name in CAPTURE_STACK_MODULES:
                modules.append(name)
        return modules

    def capture_driver_params(self) -> list[str]:
        params_dir = Path("/sys/module/HwsCapture/parameters")
        if not params_dir.exists():
            return []
        params = []
        for path in sorted(params_dir.iterdir()):
            if path.is_file():
                params.append(f"{path.name}={read_text(path).strip()}")
        return params

    @staticmethod
    def capture_driver_overrides(params: Sequence[str]) -> list[str]:
        overrides = []
        for item in params:
            lowered = item.lower()
            if lowered.endswith("=n") or lowered.endswith("=0") or lowered.endswith("=false"):
                continue
            overrides.append(item)
        return overrides

    @staticmethod
    def capture_card_brief(card: str) -> str:
        slot_match = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+", card, re.IGNORECASE)
        slot = slot_match.group(1) if slot_match else "unknown"
        description = card
        if ": " in description:
            description = description.split(": ", 1)[1]
        if " | " in description:
            description = description.split(" | ", 1)[0]
        description = description.replace("Silicon Magic ", "")
        driver_match = re.search(r"\|\s*driver\s+(.+)$", card)
        driver = driver_match.group(1).strip() if driver_match else "unknown"
        return shorten(f"{slot} | {description} | {driver}", 120)

    @staticmethod
    def probe_v4l2_node(node: str) -> dict[str, str]:
        info: dict[str, str] = {}
        result = run_command(["v4l2-ctl", "-D", "-d", node], timeout=3.0)
        if result.stdout:
            for raw in result.stdout.splitlines():
                if ":" not in raw:
                    continue
                key, value = [part.strip() for part in raw.split(":", 1)]
                if key in {"Driver name", "Card type", "Bus info"}:
                    info[key] = value
        fmt_result = run_command(["v4l2-ctl", "--get-fmt-video", "-d", node], timeout=3.0)
        if fmt_result.stdout:
            width = None
            height = None
            pixfmt = None
            for raw in fmt_result.stdout.splitlines():
                raw = raw.strip()
                if raw.startswith("Width/Height"):
                    match = re.search(r"(\d+)\s*/\s*(\d+)", raw)
                    if match:
                        width, height = match.groups()
                elif raw.startswith("Pixel Format"):
                    match = re.search(r"'([^']+)'", raw)
                    if match:
                        pixfmt = match.group(1)
            if width and height:
                info["Format"] = f"{width}x{height}" + (f" {pixfmt}" if pixfmt else "")
        return info

    def sysfs_v4l2_nodes(self) -> list[dict[str, object]]:
        root = Path("/sys/class/video4linux")
        if not root.exists():
            return []
        nodes: list[dict[str, object]] = []
        for path in sorted(root.glob("video*")):
            devname = f"/dev/{path.name}"
            resolved = str(path.resolve())
            slots = re.findall(r"(0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])", resolved, re.IGNORECASE)
            nodes.append(
                {
                    "sysfs_name": path.name,
                    "label": read_text(path / "name").strip() or path.name,
                    "devname": devname,
                    "present": Path(devname).exists(),
                    "major_minor": read_text(path / "dev").strip() or "unknown",
                    "index": read_text(path / "index").strip() or "",
                    "slot": slots[-1] if slots else "unknown",
                    "detail": self.probe_v4l2_node(devname) if Path(devname).exists() else {},
                }
            )
        return nodes

    @staticmethod
    def format_sysfs_v4l2_node(entry: dict[str, object]) -> str:
        label = str(entry.get("label") or entry.get("sysfs_name") or "video")
        devname = str(entry.get("devname") or entry.get("sysfs_name") or "unknown")
        state = "present" if entry.get("present") else "missing"
        parts = [f"{devname} {state}"]
        major_minor = str(entry.get("major_minor") or "")
        if major_minor and major_minor != "unknown":
            parts.append(major_minor)
        slot = str(entry.get("slot") or "")
        if slot and slot != "unknown":
            parts.append(f"pci {slot}")
        detail = entry.get("detail")
        if isinstance(detail, dict):
            for key in ("Driver name", "Card type", "Format"):
                value = detail.get(key)
                if value:
                    parts.append(str(value))
        return f"{label}: {' | '.join(parts)}"

    def v4l2_inventory(self) -> dict[str, object]:
        sysfs_nodes = self.sysfs_v4l2_nodes()
        video_nodes = sorted(str(path) for path in Path("/dev").glob("video*"))
        media_nodes = sorted(str(path) for path in Path("/dev").glob("media*"))
        result = run_command(["v4l2-ctl", "--list-devices"], timeout=4.0)
        if result.missing:
            return {
                "video_nodes": video_nodes,
                "media_nodes": media_nodes,
                "sysfs_nodes": sysfs_nodes,
                "userspace_lines": ["v4l2-ctl not found."],
            }
        if result.stderr:
            return {
                "video_nodes": video_nodes,
                "media_nodes": media_nodes,
                "sysfs_nodes": sysfs_nodes,
                "userspace_lines": [shorten(single_line(result.stderr), 140)],
            }
        if not result.stdout:
            if sysfs_nodes:
                userspace_lines = [f"No V4L2 devices listed despite {len(sysfs_nodes)} kernel video4linux channel(s)."]
            else:
                userspace_lines = ["No V4L2 devices listed."]
            return {
                "video_nodes": video_nodes,
                "media_nodes": media_nodes,
                "sysfs_nodes": sysfs_nodes,
                "userspace_lines": userspace_lines,
            }

        devices: list[dict[str, object]] = []
        current: dict[str, object] | None = None
        for raw in result.stdout.splitlines():
            if raw and not raw.startswith("\t"):
                current = {"name": raw.strip().rstrip(":"), "nodes": []}
                devices.append(current)
            elif current is not None and raw.strip():
                current["nodes"].append(raw.strip())

        lines = []
        for device in devices[:6]:
            nodes = [node for node in device.get("nodes", []) if node.startswith("/dev/video")]
            media = [node for node in device.get("nodes", []) if node.startswith("/dev/media")]
            primary = nodes[0] if nodes else (media[0] if media else None)
            detail = self.probe_v4l2_node(primary) if primary and Path(primary).exists() else {}
            detail_parts = []
            if detail.get("Driver name"):
                detail_parts.append(detail["Driver name"])
            if detail.get("Card type"):
                detail_parts.append(detail["Card type"])
            if detail.get("Bus info"):
                detail_parts.append(detail["Bus info"])
            if detail.get("Format"):
                detail_parts.append(detail["Format"])
            node_summary = ", ".join(nodes[:4] + media[:2]) if nodes or media else "no nodes"
            suffix = f" | {' | '.join(detail_parts)}" if detail_parts else ""
            lines.append(f"{device['name']}: {node_summary}{suffix}")
        if not lines:
            lines.append("No V4L2 devices listed.")
        return {
            "video_nodes": video_nodes,
            "media_nodes": media_nodes,
            "sysfs_nodes": sysfs_nodes,
            "userspace_lines": lines,
        }

    def capture_log_hints(self) -> list[str]:
        result = run_command(
            [
                "journalctl",
                "-b",
                f"--grep={CAPTURE_LOG_PATTERN}",
                "-n",
                "10",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        return parse_journal_lines(result, limit=6)

    @staticmethod
    def capture_log_issues(entries: Sequence[str]) -> list[str]:
        issue_keywords = (
            "error",
            "fail",
            "failed",
            "warn",
            "timeout",
            "reset",
            "disconnect",
            "missing",
            "invalid",
            "no signal",
        )
        issues = [entry for entry in entries if any(token in entry.lower() for token in issue_keywords)]
        return issues[:3]

    @staticmethod
    def connected_drm_connectors(connectors: Sequence[str]) -> list[str]:
        connected = []
        for item in connectors:
            lowered = item.lower()
            if "connected" in lowered and "disconnected" not in lowered:
                connected.append(item.split()[0])
        return connected

    def encoder_availability(self) -> list[str]:
        result = run_command(["ffmpeg", "-hide_banner", "-encoders"], timeout=6.0)
        encoders = []
        for raw in result.stdout.splitlines():
            lower = raw.lower()
            if any(keyword in lower for keyword in ENCODER_KEYWORDS):
                encoders.append(" ".join(raw.split()))
        if encoders:
            return encoders[:8]
        if result.missing:
            return ["ffmpeg not found."]
        return ["No known hardware encoders detected in ffmpeg output."]

    @staticmethod
    def encoder_summary(encoders: Sequence[str]) -> str:
        if not encoders:
            return "none detected"
        if len(encoders) == 1 and (
            encoders[0].endswith("not found.") or encoders[0].startswith("No known hardware encoders")
        ):
            return encoders[0]
        families = []
        for needle, label in (
            ("nvenc", "NVENC"),
            ("qsv", "QSV"),
            ("amf", "AMF"),
            ("vaapi", "VAAPI"),
            ("v4l2m2m", "V4L2-M2M"),
            ("rkmpp", "RKMPP"),
        ):
            if any(needle in item.lower() for item in encoders):
                families.append(label)
        if families:
            return ", ".join(families)
        return shorten(", ".join(encoders[:3]), 120)

    @staticmethod
    def capture_clients(nodes: Sequence[str]) -> dict[str, list[str]]:
        active_nodes = [node for node in nodes if Path(node).exists()]
        if not active_nodes:
            return {}
        owners: dict[str, set[str]] = {node: set() for node in active_nodes}
        target_nodes = set(active_nodes)
        proc_root = Path("/proc")
        for pid_dir in proc_root.iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            if not fd_dir.is_dir():
                continue
            comm = read_text(pid_dir / "comm").strip() or pid_dir.name
            matched: set[str] = set()
            try:
                for fd_path in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd_path)
                    except OSError:
                        continue
                    if target in target_nodes:
                        matched.add(target)
            except OSError:
                continue
            for node in matched:
                owners[node].add(f"{pid_dir.name} {comm}")
        return {node: sorted(values) for node, values in owners.items() if values}

    def collect(self) -> list[str]:
        lines = ["Capture pipeline:"]
        cards = self.backend.cached("capture_cards", 60.0, self.capture_cards)
        modules = self.backend.cached("capture_modules", 30.0, self.capture_modules)
        driver_params = self.backend.cached("capture_driver_params", 60.0, self.capture_driver_params)
        v4l2_inventory = self.backend.cached("v4l2_inventory", 30.0, self.v4l2_inventory)
        encoders = self.backend.cached("encoder_availability", 600.0, self.encoder_availability)
        connectors = self.drm_connectors()
        log_hints = self.capture_log_hints()
        avmatrix_cards = [card for card in cards if "avmatrix" in card.lower()]
        capture_slots = self.capture_slots(avmatrix_cards)
        sysfs_nodes = v4l2_inventory.get("sysfs_nodes", []) if isinstance(v4l2_inventory, dict) else []
        capture_sysfs_nodes = [
            entry for entry in sysfs_nodes if isinstance(entry, dict) and str(entry.get("slot", "")) in capture_slots
        ]
        capture_video_nodes = [
            str(entry.get("devname")) for entry in capture_sysfs_nodes if entry.get("present") and entry.get("devname")
        ]
        media_nodes = v4l2_inventory.get("media_nodes", []) if isinstance(v4l2_inventory, dict) else []
        userspace_lines = v4l2_inventory.get("userspace_lines", []) if isinstance(v4l2_inventory, dict) else []
        capture_clients = (
            self.backend.cached(
                "capture_clients:" + ",".join(capture_video_nodes),
                30.0,
                lambda: self.capture_clients(capture_video_nodes),
            )
            if capture_video_nodes
            else {}
        )
        driver_overrides = self.capture_driver_overrides(driver_params)
        connected_links = self.connected_drm_connectors(connectors)
        capture_log_issues = self.capture_log_issues(log_hints)

        health = "not detected"
        if avmatrix_cards:
            if not capture_sysfs_nodes:
                health = "broken"
            elif not capture_video_nodes:
                health = "degraded"
            elif len(capture_video_nodes) < len(capture_sysfs_nodes):
                health = "degraded"
            else:
                health = "ready"

        if health == "broken":
            lines.append("! AVMatrix readiness: broken")
        elif health == "degraded":
            lines.append("! AVMatrix readiness: degraded")
        elif health == "ready":
            lines.append("AVMatrix readiness: ready")
        else:
            lines.append("AVMatrix readiness: not detected")

        if avmatrix_cards:
            lines.append(f"  Card: {self.capture_card_brief(avmatrix_cards[0])}")
        lines.append(
            "  Stages: "
            + f"card {len(avmatrix_cards)} | kernel {len(capture_sysfs_nodes)}"
            + f" | /dev/video {len(capture_video_nodes)} | /dev/media {len(media_nodes)}"
        )
        lines.append("  Modules: " + (", ".join(modules[:6]) if modules else "none loaded"))

        if avmatrix_cards and not capture_sysfs_nodes:
            lines.append("! Breakpoint: AVMatrix is on PCI, but no kernel video channels were registered")
        elif avmatrix_cards and capture_sysfs_nodes and not capture_video_nodes:
            lines.append("! Breakpoint: kernel channels exist, but /dev/video nodes were not created")
            lines.append("? Likely udev/device-node issue; userspace cannot open the capture card")
        elif avmatrix_cards and len(capture_video_nodes) < len(capture_sysfs_nodes):
            lines.append(f"? Breakpoint: only {len(capture_video_nodes)}/{len(capture_sysfs_nodes)} capture nodes reached userspace")
        elif modules and not capture_sysfs_nodes:
            lines.append("? Breakpoint: capture modules are loaded, but the card is not exposing video channels")

        if driver_overrides:
            lines.append("  Driver overrides: " + ", ".join(driver_overrides[:4]))

        if capture_sysfs_nodes and health != "ready":
            lines.append("  Channels:")
            for entry in capture_sysfs_nodes[:8]:
                lines.append(f"    {self.format_sysfs_v4l2_node(entry)}")
        elif capture_sysfs_nodes:
            channel_names = [str(entry.get("label", entry.get("sysfs_name", "video"))) for entry in capture_sysfs_nodes]
            lines.append("  Channels: " + ", ".join(channel_names[:6]))

        if capture_video_nodes:
            rw_access = sum(1 for node in capture_video_nodes if os.access(node, os.R_OK | os.W_OK))
            lines.append(f"  Node access: {rw_access}/{len(capture_video_nodes)} read-write")
            if isinstance(capture_clients, dict) and capture_clients:
                client_parts = []
                for node, owners in list(capture_clients.items())[:4]:
                    client_parts.append(f"{Path(node).name} -> {', '.join(owners[:2])}")
                lines.append("  Capture clients: " + "; ".join(client_parts))
            else:
                lines.append("  Capture clients: none")
        elif userspace_lines and health == "not detected":
            lines.append("  V4L2 view: " + shorten(userspace_lines[0], 140))

        lines.append("Display / encode:")
        if connected_links:
            lines.append(f"  Connected links: {', '.join(connected_links[:4])}")
        else:
            lines.append("  Connected links: none")
        lines.append("  Encoders: " + self.encoder_summary(encoders))

        lines.append("Capture log issues:")
        if capture_log_issues:
            for item in capture_log_issues[:3]:
                lines.append(f"  {item}")
        elif log_hints:
            lines.append("  No AVMatrix warnings in current boot journal.")
        else:
            lines.append("  No AVMatrix journal entries found this boot.")
        return lines
