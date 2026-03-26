from __future__ import annotations

import hashlib
from typing import Iterable

from monitor.packages.common import (
    PackageInfo,
    parse_size_bytes,
    run_command,
    single_line,
    split_field_values,
    strip_dep_version,
)


def parse_pacman_qi_block(block: str) -> PackageInfo | None:
    fields: dict[str, list[str]] = {}
    current_key: str | None = None
    for raw in block.splitlines():
        if not raw.strip():
            continue
        if ":" in raw and not raw.startswith(" "):
            key, value = raw.split(":", 1)
            current_key = key.strip()
            fields[current_key] = [value.strip()]
        elif current_key is not None:
            fields[current_key].append(raw.strip())
    if not fields:
        return None

    name = single_line(" ".join(fields.get("Name", [])))
    version = single_line(" ".join(fields.get("Version", [])))
    description = single_line(" ".join(fields.get("Description", [])))
    installed_size = parse_size_bytes(" ".join(fields.get("Installed Size", [])))
    install_reason = single_line(" ".join(fields.get("Install Reason", []))).lower()
    required_by = split_field_values(fields.get("Required By", []))
    depends = split_field_values(fields.get("Depends On", []))
    provides = split_field_values(fields.get("Provides", []))
    groups = split_field_values(fields.get("Groups", []))
    repository = single_line(" ".join(fields.get("Repository", [])))
    if not name:
        return None
    return PackageInfo(
        name=name,
        version=version,
        description=description,
        installed_size=installed_size,
        install_reason="explicit" if "explicitly" in install_reason else "dependency",
        required_by=required_by,
        depends=depends,
        provides=provides,
        groups=groups,
        official=repository.lower() != "local",
    )


def resolve_dependency_names(packages: dict[str, PackageInfo]) -> None:
    provides: dict[str, set[str]] = {}
    for pkg in packages.values():
        for item in pkg.provides:
            token = strip_dep_version(item)
            if token:
                provides.setdefault(token, set()).add(pkg.name)
    for pkg in packages.values():
        resolved: list[str] = []
        for dep in pkg.depends:
            token = strip_dep_version(dep)
            if not token:
                continue
            if token in packages:
                resolved.append(token)
                continue
            providers = provides.get(token, set())
            if providers:
                resolved.extend(sorted(providers))
        pkg.resolved_dep_names = list(dict.fromkeys(resolved))


def inventory_fingerprint(packages: dict[str, PackageInfo]) -> str:
    digest = hashlib.sha256()
    for name in sorted(packages):
        pkg = packages[name]
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(pkg.version.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def load_package_inventory() -> tuple[dict[str, PackageInfo], str]:
    info_result = run_command(["pacman", "-Qi"], timeout=60.0)
    if info_result.missing:
        raise RuntimeError("pacman not found.")
    if not info_result.ok and not info_result.stdout:
        raise RuntimeError(single_line(info_result.stderr) or "Failed to read pacman metadata.")

    foreign_result = run_command(["pacman", "-Qqm"], timeout=20.0)
    foreign_names: set[str] = set()
    if foreign_result.ok or foreign_result.stdout:
        foreign_names = {line.strip() for line in foreign_result.stdout.splitlines() if line.strip()}

    packages: dict[str, PackageInfo] = {}
    for block in info_result.stdout.split("\n\n"):
        pkg = parse_pacman_qi_block(block)
        if pkg is None:
            continue
        if pkg.name in foreign_names:
            pkg.official = False
        packages[pkg.name] = pkg
    resolve_dependency_names(packages)
    return packages, inventory_fingerprint(packages)

