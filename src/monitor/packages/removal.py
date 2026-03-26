from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from monitor.packages.common import (
    CandidatePreview,
    PackageInfo,
    RemovalPlan,
    TREE_MAX_DEPTH,
    built_in_protected,
    format_bytes,
    format_name_list,
    run_command,
    single_line,
)


def removal_preview(roots: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(roots, str):
        root_names = [roots]
    else:
        root_names = [name for name in roots if name]
    root_names = list(dict.fromkeys(root_names))
    command = ["pacman", "-Rsu", "--print", "--print-format", "%n", *root_names]
    result = run_command(command, timeout=30.0)
    if result.missing:
        raise RuntimeError("pacman not found.")
    if not result.ok:
        message = single_line(result.stderr) or "pacman removal preview failed."
        raise RuntimeError(message)
    removal_names = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    if not removal_names:
        raise RuntimeError(f"No packages would be removed for {format_name_list(root_names)}.")
    return removal_names


def validate_removal_plan(
    roots: Iterable[str],
    removal_names: Iterable[str],
    packages: dict[str, PackageInfo],
    protected: set[str],
    official_only: bool = True,
) -> RemovalPlan | None:
    root_names = tuple(dict.fromkeys(root for root in roots if root))
    removed = tuple(dict.fromkeys(name for name in removal_names if name))
    if not root_names or not removed:
        return None
    if any(root not in packages for root in root_names):
        return None
    if any(name not in packages for name in removed):
        return None
    if any(root not in removed for root in root_names):
        return None
    if any(root in protected or built_in_protected(root) for root in root_names):
        return None
    if any(name in protected or built_in_protected(name) for name in removed):
        return None
    if official_only and any(not packages[name].official for name in removed):
        return None
    reclaimable_size = sum(packages[name].installed_size for name in removed)
    return RemovalPlan(
        roots=root_names,
        removal_names=removed,
        reclaimable_size=reclaimable_size,
    )


def removal_plan_error(
    roots: Iterable[str],
    removal_names: Iterable[str],
    packages: dict[str, PackageInfo],
    protected: set[str],
    official_only: bool = True,
) -> str | None:
    root_names = tuple(dict.fromkeys(root for root in roots if root))
    removed = tuple(dict.fromkeys(name for name in removal_names if name))
    if not root_names:
        return "No root packages selected."
    missing_roots = [root for root in root_names if root not in packages]
    if missing_roots:
        return f"Packages are no longer installed: {format_name_list(missing_roots)}."
    missing_removed = [name for name in removed if name not in packages]
    if missing_removed:
        return f"Removal set is stale; missing packages: {format_name_list(missing_removed)}."
    protected_hits = [name for name in removed if name in protected or built_in_protected(name)]
    if protected_hits:
        return f"Selection would remove protected packages: {format_name_list(protected_hits)}."
    if official_only:
        foreign_hits = [name for name in removed if not packages[name].official]
        if foreign_hits:
            return f"Selection would remove non-official packages: {format_name_list(foreign_hits)}."
    return None


def validate_preview(
    root: str,
    removal_names: Iterable[str],
    packages: dict[str, PackageInfo],
    protected: set[str],
) -> CandidatePreview | None:
    plan = validate_removal_plan((root,), removal_names, packages, protected, official_only=True)
    if plan is None:
        return None
    return CandidatePreview(
        root=root,
        removal_names=plan.removal_names,
        reclaimable_size=plan.reclaimable_size,
    )


def preview_tree_lines(preview: CandidatePreview, packages: dict[str, PackageInfo], width: int) -> list[str]:
    removal_set = set(preview.removal_names)
    children_map: dict[str, list[str]] = {name: [] for name in removal_set}
    for name in removal_set:
        pkg = packages.get(name)
        if pkg is None:
            continue
        for dep_name in pkg.resolved_dep_names:
            if dep_name in removal_set:
                children_map[name].append(dep_name)
    for name in children_map:
        children_map[name] = sorted(dict.fromkeys(children_map[name]))

    lines: list[str] = []

    def walk(name: str, depth: int, prefix: str, is_last: bool, active_path: set[str]) -> None:
        connector = "`- " if is_last else "|- "
        if depth == 0:
            connector = ""
        label = name
        pkg = packages.get(name)
        if pkg is not None and pkg.installed_size:
            label = f"{label} ({format_bytes(pkg.installed_size)})"
        lines.append((prefix + connector + label)[:width])
        if depth >= TREE_MAX_DEPTH - 1:
            remaining = [child for child in children_map.get(name, []) if child not in active_path]
            if remaining:
                lines.append((prefix + ("   " if is_last else "|  ") + "...")[:width])
            return
        children = [child for child in children_map.get(name, []) if child not in active_path]
        next_prefix = prefix + ("   " if is_last else "|  ")
        for index, child in enumerate(children):
            walk(
                child,
                depth + 1,
                next_prefix,
                index == len(children) - 1,
                active_path | {child},
            )

    walk(preview.root, 0, "", True, {preview.root})
    return lines or [preview.root[:width]]


def shell_command_for_removal(roots: str | Iterable[str]) -> list[str]:
    if isinstance(roots, str):
        root_names = [roots]
    else:
        root_names = [name for name in roots if name]
    root_names = list(dict.fromkeys(root_names))
    if os.geteuid() == 0:
        return ["pacman", "-Rsu", "--confirm", *root_names]
    return ["sudo", "pacman", "-Rsu", "--confirm", *root_names]

