from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Sequence

from monitor.shared.command import run_command
from monitor.shared.formatting import format_bytes, summarize_list
from monitor.shared.text import line_list, parse_float, shorten


DOCKER_CPU_HOG_PCT = 80.0
DOCKER_MEMORY_HOG_BYTES = 2 * 1024**3
DOCKER_IMAGE_STALE_30_SECONDS = 30 * 86400
DOCKER_IMAGE_STALE_90_SECONDS = 90 * 86400
DOCKER_FLOATING_TAGS = frozenset({"latest"})
DOCKER_ROOT_DIR = Path("/var/lib/docker")


class ContainersCollector:
    def __init__(self, backend: object) -> None:
        self.backend = backend

    def detect_enabled(self) -> bool:
        if shutil.which("docker") is not None:
            return True
        if DOCKER_ROOT_DIR.exists():
            return True
        return self.backend._privileged_section("containers") is not None

    @staticmethod
    def json_command(args: Sequence[str], timeout: float = 6.0) -> tuple[dict[str, object] | None, str | None]:
        result = run_command(args, timeout=timeout)
        if not result.stdout:
            if result.ok:
                return {}, None
            if result.missing:
                return None, f"{args[0]} not found"
            if result.timed_out:
                return None, f"{args[0]} timed out"
            if result.stderr:
                return None, shorten(" ".join(result.stderr.split()), 120)
            return None, f"{args[0]} returned no data"
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None, f"{args[0]} returned invalid JSON"
        if result.stderr:
            return None, shorten(" ".join(result.stderr.split()), 120)
        if isinstance(payload, dict):
            return payload, None
        return None, f"{args[0]} returned unexpected JSON"

    @staticmethod
    def json_lines_command(args: Sequence[str], timeout: float = 6.0) -> tuple[list[dict[str, object]], str | None]:
        result = run_command(args, timeout=timeout)
        if not result.stdout:
            if result.ok:
                return [], None
            if result.missing:
                return [], f"{args[0]} not found"
            if result.timed_out:
                return [], f"{args[0]} timed out"
            if result.stderr:
                return [], shorten(" ".join(result.stderr.split()), 120)
            return [], f"{args[0]} returned no data"
        rows: list[dict[str, object]] = []
        for raw in result.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                return [], f"{args[0]} returned invalid JSON"
            if isinstance(payload, dict):
                rows.append(payload)
        return rows, None

    @staticmethod
    def count_command_lines(args: Sequence[str], timeout: float = 5.0) -> tuple[int | None, str | None]:
        result = run_command(args, timeout=timeout)
        if result.stdout or result.ok:
            return len(line_list(result.stdout)), None
        if result.missing:
            return None, f"{args[0]} not found"
        if result.timed_out:
            return None, f"{args[0]} timed out"
        if result.stderr:
            return None, shorten(" ".join(result.stderr.split()), 120)
        return 0, None

    @staticmethod
    def parse_size_bytes(text: str) -> int | None:
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
            "KB": 1000,
            "MB": 1000**2,
            "GB": 1000**3,
            "TB": 1000**4,
            "PB": 1000**5,
        }
        factor = factors.get(unit)
        if factor is None:
            return None
        return int(amount * factor)

    @staticmethod
    def parse_age_seconds(text: str) -> int | None:
        lowered = text.strip().lower()
        if not lowered:
            return None
        if lowered.startswith("less than"):
            return 0
        match = re.search(r"(\d+)\s+([a-z]+)", lowered)
        if not match:
            return None
        value = int(match.group(1))
        unit = match.group(2)
        multipliers = {
            "second": 1,
            "seconds": 1,
            "minute": 60,
            "minutes": 60,
            "hour": 3600,
            "hours": 3600,
            "day": 86400,
            "days": 86400,
            "week": 7 * 86400,
            "weeks": 7 * 86400,
            "month": 30 * 86400,
            "months": 30 * 86400,
            "year": 365 * 86400,
            "years": 365 * 86400,
        }
        multiplier = multipliers.get(unit)
        if multiplier is None:
            return None
        return value * multiplier

    @staticmethod
    def image_ref(repository: str, tag: str) -> str:
        repo = repository.strip()
        tag_value = tag.strip()
        if not repo or repo == "<none>":
            return "<dangling>"
        if not tag_value or tag_value == "<none>":
            return repo
        return f"{repo}:{tag_value}"

    @staticmethod
    def row_name(row: dict[str, object]) -> str:
        for key in ("Name", "Names", "Container", "ID"):
            value = str(row.get(key, "")).strip()
            if value:
                return value
        return "unknown"

    @staticmethod
    def age_label(age_seconds: int | None) -> str:
        if age_seconds is None:
            return "age?"
        if age_seconds < 3600:
            return f"{max(age_seconds // 60, 0)}m"
        if age_seconds < 86400:
            return f"{age_seconds // 3600}h"
        return f"{age_seconds // 86400}d"

    def docker_service_state(self) -> str | None:
        result = run_command(["systemctl", "is-active", "docker.service"], timeout=3.0)
        if result.stdout:
            return result.stdout.splitlines()[0].strip()
        if result.missing:
            return None
        if result.stderr:
            if "Failed to connect to system scope bus" in result.stderr:
                return None
            return shorten(" ".join(result.stderr.split()), 80)
        return "unknown"

    def docker_info_live(self) -> tuple[dict[str, object] | None, str | None]:
        return self.json_command(["docker", "info", "--format", "{{json .}}"], timeout=8.0)

    def docker_ps_rows_live(self) -> tuple[list[dict[str, object]], str | None]:
        return self.json_lines_command(
            ["docker", "ps", "-a", "--size", "--no-trunc", "--format", "{{json .}}"],
            timeout=8.0,
        )

    def docker_stats_rows_live(self) -> tuple[list[dict[str, object]], str | None]:
        return self.json_lines_command(
            ["docker", "stats", "--no-stream", "--no-trunc", "--format", "{{json .}}"],
            timeout=8.0,
        )

    def docker_image_rows_live(self) -> tuple[list[dict[str, object]], str | None]:
        return self.json_lines_command(
            ["docker", "image", "ls", "--no-trunc", "--format", "{{json .}}"],
            timeout=10.0,
        )

    def docker_df_rows_live(self) -> tuple[list[dict[str, object]], str | None]:
        return self.json_lines_command(
            ["docker", "system", "df", "--format", "{{json .}}"],
            timeout=10.0,
        )

    def docker_state_live(self) -> dict[str, object]:
        service_state = self.backend.cached("docker_service_state", 60.0, self.docker_service_state)
        docker_info, docker_info_error = self.backend.cached("docker_info_live", 30.0, self.docker_info_live)

        root_dir = DOCKER_ROOT_DIR
        if isinstance(docker_info, dict):
            docker_root_raw = str(docker_info.get("DockerRootDir", "")).strip()
            if docker_root_raw:
                root_dir = Path(docker_root_raw)

        state: dict[str, object] = {
            "source": "live",
            "detected": bool(shutil.which("docker") or root_dir.exists()),
            "available": docker_info_error is None,
            "access_error": docker_info_error,
            "docker_service": service_state,
            "docker_root_dir": str(root_dir) if root_dir else "",
            "docker_data_bytes": None,
            "reclaimable_bytes": None,
            "running": 0,
            "exited": 0,
            "restarting": 0,
            "dead": 0,
            "paused": 0,
            "unhealthy": 0,
            "healthy": 0,
            "health_starting": 0,
            "missing_healthchecks": None,
            "dangling_images": None,
            "dangling_volumes": None,
            "stale_images_30d": None,
            "stale_images_90d": None,
            "floating_latest_tags": None,
            "cpu_hogs": 0,
            "memory_hogs": 0,
            "top_cpu": [],
            "top_memory": [],
            "top_writable": [],
            "largest_images": [],
            "restarting_names": [],
            "unhealthy_names": [],
            "notes": [],
            "total_images": None,
            "total_containers": None,
        }

        if root_dir.exists():
            state["docker_data_bytes"] = self.backend.cached(
                f"docker_root_dir_size:{root_dir}",
                300.0,
                lambda: self.backend._path_size(root_dir, timeout=10.0),
            )

        if docker_info_error is not None:
            return state

        ps_rows, ps_error = self.backend.cached("docker_ps_rows_live", 30.0, self.docker_ps_rows_live)
        stats_rows, stats_error = self.backend.cached("docker_stats_rows_live", 15.0, self.docker_stats_rows_live)
        image_rows, image_error = self.backend.cached("docker_image_rows_live", 600.0, self.docker_image_rows_live)
        df_rows, df_error = self.backend.cached("docker_df_rows_live", 300.0, self.docker_df_rows_live)
        dangling_images, dangling_images_error = self.backend.cached(
            "docker_dangling_images",
            300.0,
            lambda: self.count_command_lines(["docker", "images", "-q", "--filter", "dangling=true"], timeout=6.0),
        )
        dangling_volumes, dangling_volumes_error = self.backend.cached(
            "docker_dangling_volumes",
            300.0,
            lambda: self.count_command_lines(["docker", "volume", "ls", "-q", "--filter", "dangling=true"], timeout=6.0),
        )

        notes = [item for item in (ps_error, stats_error, image_error) if item]
        if df_error and "--format" not in df_error:
            notes.append(df_error)
        if dangling_images_error:
            notes.append(dangling_images_error)
        if dangling_volumes_error:
            notes.append(dangling_volumes_error)
        state["notes"] = list(dict.fromkeys(notes))

        state["dangling_images"] = dangling_images
        state["dangling_volumes"] = dangling_volumes
        state["total_containers"] = len(ps_rows)

        health_known = 0
        writable_rows: list[dict[str, object]] = []
        restarting_names: list[str] = []
        unhealthy_names: list[str] = []
        for row in ps_rows:
            name = self.row_name(row)
            status = str(row.get("Status", "")).strip()
            lowered_status = status.lower()
            container_state = str(row.get("State", "")).strip().lower()
            if container_state == "running":
                state["running"] = int(state["running"]) + 1
            elif container_state == "exited":
                state["exited"] = int(state["exited"]) + 1
            elif container_state == "restarting":
                state["restarting"] = int(state["restarting"]) + 1
                restarting_names.append(name)
            elif container_state == "dead":
                state["dead"] = int(state["dead"]) + 1
            elif container_state == "paused":
                state["paused"] = int(state["paused"]) + 1

            if "unhealthy" in lowered_status:
                state["unhealthy"] = int(state["unhealthy"]) + 1
                health_known += 1
                unhealthy_names.append(name)
            elif "health: starting" in lowered_status:
                state["health_starting"] = int(state["health_starting"]) + 1
                health_known += 1
            elif "healthy" in lowered_status:
                state["healthy"] = int(state["healthy"]) + 1
                health_known += 1

            size_bytes = self.parse_size_bytes(str(row.get("Size", "")))
            if size_bytes is not None and size_bytes > 0:
                writable_rows.append(
                    {
                        "name": name,
                        "size_bytes": size_bytes,
                        "image": str(row.get("Image", "")).strip(),
                        "status": status,
                    }
                )

        state["restarting_names"] = restarting_names[:4]
        state["unhealthy_names"] = unhealthy_names[:4]
        running = int(state["running"])
        state["missing_healthchecks"] = max(running - health_known, 0) if running >= 0 else None
        writable_rows.sort(key=lambda item: int(item["size_bytes"]), reverse=True)
        state["top_writable"] = writable_rows[:3]

        cpu_rows: list[dict[str, object]] = []
        memory_rows: list[dict[str, object]] = []
        for row in stats_rows:
            name = self.row_name(row)
            cpu_pct = parse_float(str(row.get("CPUPerc", "")))
            mem_bytes = self.parse_size_bytes(str(row.get("MemUsage", "")))
            mem_pct = parse_float(str(row.get("MemPerc", "")))
            if cpu_pct is not None:
                cpu_rows.append(
                    {
                        "name": name,
                        "cpu_pct": cpu_pct,
                        "mem_bytes": mem_bytes,
                        "mem_pct": mem_pct,
                    }
                )
            if mem_bytes is not None:
                memory_rows.append(
                    {
                        "name": name,
                        "mem_bytes": mem_bytes,
                        "mem_pct": mem_pct,
                        "cpu_pct": cpu_pct,
                    }
                )
        cpu_rows.sort(key=lambda item: float(item.get("cpu_pct", 0.0)), reverse=True)
        memory_rows.sort(key=lambda item: int(item.get("mem_bytes", 0)), reverse=True)
        state["top_cpu"] = [item for item in cpu_rows if float(item.get("cpu_pct", 0.0)) > 0.0][:3]
        state["top_memory"] = [item for item in memory_rows if int(item.get("mem_bytes", 0)) > 0][:3]
        state["cpu_hogs"] = sum(1 for item in cpu_rows if float(item.get("cpu_pct", 0.0)) >= DOCKER_CPU_HOG_PCT)
        state["memory_hogs"] = sum(
            1
            for item in memory_rows
            if int(item.get("mem_bytes", 0)) >= DOCKER_MEMORY_HOG_BYTES
        )

        images_by_id: dict[str, dict[str, object]] = {}
        for row in image_rows:
            image_id = str(row.get("ID", "")).strip() or str(len(images_by_id))
            repository = str(row.get("Repository", "")).strip()
            tag = str(row.get("Tag", "")).strip()
            entry = images_by_id.setdefault(
                image_id,
                {
                    "name": self.image_ref(repository, tag),
                    "size_bytes": None,
                    "age_seconds": None,
                    "floating_latest": False,
                },
            )
            name = self.image_ref(repository, tag)
            if entry["name"] == "<dangling>" and name != "<dangling>":
                entry["name"] = name
            size_bytes = self.parse_size_bytes(str(row.get("Size", "")))
            if isinstance(size_bytes, int):
                entry["size_bytes"] = size_bytes
            age_seconds = self.parse_age_seconds(str(row.get("CreatedSince", "")))
            if isinstance(age_seconds, int):
                entry["age_seconds"] = age_seconds
            if tag.lower() in DOCKER_FLOATING_TAGS:
                entry["floating_latest"] = True

        unique_images = list(images_by_id.values())
        unique_images.sort(key=lambda item: int(item.get("size_bytes") or 0), reverse=True)
        state["total_images"] = len(unique_images)
        state["largest_images"] = unique_images[:3]
        state["stale_images_30d"] = sum(
            1
            for item in unique_images
            if isinstance(item.get("age_seconds"), int)
            and int(item["age_seconds"]) >= DOCKER_IMAGE_STALE_30_SECONDS
            and str(item.get("name", "")) != "<dangling>"
        )
        state["stale_images_90d"] = sum(
            1
            for item in unique_images
            if isinstance(item.get("age_seconds"), int)
            and int(item["age_seconds"]) >= DOCKER_IMAGE_STALE_90_SECONDS
            and str(item.get("name", "")) != "<dangling>"
        )
        state["floating_latest_tags"] = sum(1 for item in unique_images if bool(item.get("floating_latest")))

        reclaimable_bytes = 0
        reclaimable_found = False
        for row in df_rows:
            reclaimable = self.parse_size_bytes(str(row.get("Reclaimable", "")))
            if reclaimable is None:
                continue
            reclaimable_found = True
            reclaimable_bytes += reclaimable
        if reclaimable_found:
            state["reclaimable_bytes"] = reclaimable_bytes

        return state

    def state(self) -> dict[str, object]:
        return self.backend.cached("docker_state", 15.0, self._state_uncached)

    def _state_uncached(self) -> dict[str, object]:
        live = self.docker_state_live()
        if bool(live.get("available")):
            return live
        privileged = self.backend._privileged_section("containers")
        if isinstance(privileged, dict):
            snapshot = dict(privileged)
            snapshot["source"] = "snapshot"
            if live.get("access_error") and not snapshot.get("access_error"):
                snapshot["access_error"] = live.get("access_error")
            return snapshot
        return live

    def digest(self) -> dict[str, object]:
        state = self.state()
        top_cpu = state.get("top_cpu", [])
        top_memory = state.get("top_memory", [])
        top_writable = state.get("top_writable", [])
        digest: dict[str, object] = {
            "detected": bool(state.get("detected")),
            "source": str(state.get("source", "live")),
            "available": bool(state.get("available")),
            "access_error": state.get("access_error"),
            "docker_service": state.get("docker_service"),
            "running": state.get("running"),
            "restarting": state.get("restarting"),
            "dead": state.get("dead"),
            "unhealthy": state.get("unhealthy"),
            "missing_healthchecks": state.get("missing_healthchecks"),
            "docker_data_bytes": state.get("docker_data_bytes"),
            "reclaimable_bytes": state.get("reclaimable_bytes"),
            "dangling_images": state.get("dangling_images"),
            "dangling_volumes": state.get("dangling_volumes"),
            "stale_images_90d": state.get("stale_images_90d"),
            "floating_latest_tags": state.get("floating_latest_tags"),
            "cpu_hogs": state.get("cpu_hogs"),
            "memory_hogs": state.get("memory_hogs"),
        }
        if isinstance(top_cpu, list) and top_cpu:
            digest["top_cpu_name"] = str(top_cpu[0].get("name", ""))
            digest["top_cpu_pct"] = top_cpu[0].get("cpu_pct")
        if isinstance(top_memory, list) and top_memory:
            digest["top_memory_name"] = str(top_memory[0].get("name", ""))
            digest["top_memory_bytes"] = top_memory[0].get("mem_bytes")
        if isinstance(top_writable, list) and top_writable:
            digest["top_writable_name"] = str(top_writable[0].get("name", ""))
            digest["top_writable_bytes"] = top_writable[0].get("size_bytes")
        return digest

    def collect(self) -> list[str]:
        state = self.state()
        lines: list[str] = []

        if state.get("source") == "snapshot":
            snapshot_line = self.backend._privileged_snapshot_line()
            if snapshot_line:
                lines.append(snapshot_line)

        if not state.get("detected") and not state.get("available"):
            lines.append("Docker: not detected on this system.")
            return lines

        access_line = "Docker access: "
        access_error = str(state.get("access_error", "")).strip()
        service_value = state.get("docker_service")
        service_state = service_value.strip() if isinstance(service_value, str) else ""
        if state.get("source") == "snapshot":
            access_line += "using privileged snapshot"
            if access_error:
                access_line += f" ({shorten(access_error, 100)})"
        elif state.get("available"):
            access_line += "daemon reachable"
        elif access_error:
            access_line += shorten(access_error, 120)
        else:
            access_line += "unavailable"
        if service_state:
            access_line += f" | docker.service {service_state}"
        lines.append(access_line)

        if not state.get("available") and state.get("docker_data_bytes") is None:
            notes = state.get("notes", [])
            if isinstance(notes, list) and notes:
                lines.append("Notes: " + summarize_list([shorten(str(item), 80) for item in notes], limit=2))
            return lines

        running = int(state.get("running", 0) or 0)
        exited = int(state.get("exited", 0) or 0)
        restarting = int(state.get("restarting", 0) or 0)
        dead = int(state.get("dead", 0) or 0)
        paused = int(state.get("paused", 0) or 0)
        counts_line = f"Containers: {running} running | {exited} exited | {restarting} restarting | {dead} dead"
        if paused > 0:
            counts_line += f" | {paused} paused"
        lines.append(counts_line)

        unhealthy = int(state.get("unhealthy", 0) or 0)
        healthy = int(state.get("healthy", 0) or 0)
        health_starting = int(state.get("health_starting", 0) or 0)
        missing_healthchecks = state.get("missing_healthchecks")
        health_line = f"Health: {unhealthy} unhealthy | {healthy} healthy"
        if health_starting > 0:
            health_line += f" | {health_starting} starting"
        if isinstance(missing_healthchecks, int):
            health_line += f" | {missing_healthchecks} without healthchecks"
        lines.append(health_line)

        unhealthy_names = state.get("unhealthy_names", [])
        if isinstance(unhealthy_names, list) and unhealthy_names:
            lines.append("Unhealthy: " + summarize_list([str(item) for item in unhealthy_names], limit=3))
        restarting_names = state.get("restarting_names", [])
        if isinstance(restarting_names, list) and restarting_names:
            lines.append("Restarting: " + summarize_list([str(item) for item in restarting_names], limit=3))

        top_cpu = state.get("top_cpu", [])
        if isinstance(top_cpu, list) and top_cpu:
            lines.append(
                "CPU hotspots: "
                + ", ".join(
                    f"{shorten(str(item.get('name', '')), 24)} {float(item.get('cpu_pct', 0.0)):.0f}%"
                    for item in top_cpu[:3]
                )
            )

        top_memory = state.get("top_memory", [])
        if isinstance(top_memory, list) and top_memory:
            lines.append(
                "Memory hotspots: "
                + ", ".join(
                    f"{shorten(str(item.get('name', '')), 24)} {format_bytes(int(item.get('mem_bytes', 0) or 0))}"
                    for item in top_memory[:3]
                )
            )

        top_writable = state.get("top_writable", [])
        if isinstance(top_writable, list) and top_writable:
            lines.append(
                "Writable layers: "
                + ", ".join(
                    f"{shorten(str(item.get('name', '')), 24)} {format_bytes(int(item.get('size_bytes', 0) or 0))}"
                    for item in top_writable[:3]
                )
            )

        storage_parts: list[str] = []
        docker_data_bytes = state.get("docker_data_bytes")
        if isinstance(docker_data_bytes, int) and docker_data_bytes >= 0:
            storage_parts.append(f"docker data {format_bytes(docker_data_bytes)}")
        reclaimable_bytes = state.get("reclaimable_bytes")
        if isinstance(reclaimable_bytes, int) and reclaimable_bytes > 0:
            storage_parts.append(f"reclaimable {format_bytes(reclaimable_bytes)}")
        dangling_images = state.get("dangling_images")
        if isinstance(dangling_images, int) and dangling_images > 0:
            storage_parts.append(f"{dangling_images} dangling images")
        dangling_volumes = state.get("dangling_volumes")
        if isinstance(dangling_volumes, int) and dangling_volumes > 0:
            storage_parts.append(f"{dangling_volumes} dangling volumes")
        lines.append("Storage: " + (" | ".join(storage_parts) if storage_parts else "unavailable"))

        largest_images = state.get("largest_images", [])
        if isinstance(largest_images, list) and largest_images:
            lines.append(
                "Largest images: "
                + ", ".join(
                    f"{shorten(str(item.get('name', '')), 34)} {format_bytes(int(item.get('size_bytes', 0) or 0))} {self.age_label(item.get('age_seconds') if isinstance(item, dict) else None)}"
                    for item in largest_images[:3]
                    if isinstance(item, dict)
                )
            )

        stale_30 = state.get("stale_images_30d")
        stale_90 = state.get("stale_images_90d")
        floating = state.get("floating_latest_tags")
        freshness_parts: list[str] = []
        if isinstance(stale_30, int):
            freshness_parts.append(f"{stale_30} older than 30d")
        if isinstance(stale_90, int):
            freshness_parts.append(f"{stale_90} older than 90d")
        if isinstance(floating, int):
            freshness_parts.append(f"{floating} :latest tag(s)")
        if freshness_parts:
            lines.append("Image freshness: " + " | ".join(freshness_parts))

        notes = state.get("notes", [])
        if isinstance(notes, list) and notes:
            lines.append("Notes: " + summarize_list([shorten(str(item), 80) for item in notes], limit=2))
        return lines
