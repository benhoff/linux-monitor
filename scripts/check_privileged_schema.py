#!/usr/bin/env python3

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"


@dataclass
class DictShape:
    paths: set[str]


@dataclass
class ListShape:
    item_paths: set[str]


@dataclass
class MapShape:
    value_paths: set[str]


Shape = DictShape | ListShape | MapShape | None


@dataclass
class ContractResult:
    name: str
    missing: set[str]
    producer_paths: set[str]
    consumer_paths: set[str]


def repo_module_path(module_name: str) -> Path | None:
    if not module_name.startswith("monitor."):
        return None
    relative = Path(*module_name.split("."))
    candidate = SRC_ROOT / f"{relative}.py"
    if candidate.exists():
        return candidate
    package_init = SRC_ROOT / relative / "__init__.py"
    if package_init.exists():
        return package_init
    return None


def join_path(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else key


def with_key(key: str, shape: Shape) -> set[str]:
    paths = {key}
    if isinstance(shape, DictShape):
        paths.update(f"{key}.{path}" for path in shape.paths)
    elif isinstance(shape, ListShape):
        paths.update(f"{key}[].{path}" for path in shape.item_paths)
    return paths


def top_level_paths(paths: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for path in paths:
        head = path.split(".", 1)[0]
        head = head.split("[].", 1)[0]
        result.add(head.split("[]", 1)[0])
    return result


class ModuleStore:
    def __init__(self) -> None:
        self.modules: dict[Path, ast.Module] = {}
        self.imports: dict[Path, dict[str, tuple[Path, str]]] = {}
        self.function_cache: dict[tuple[Path, str], Shape] = {}

    def load(self, path: Path) -> ast.Module:
        module = self.modules.get(path)
        if module is None:
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            self.modules[path] = module
            self.imports[path] = self._collect_imports(module)
        return module

    def _collect_imports(self, module: ast.Module) -> dict[str, tuple[Path, str]]:
        resolved: dict[str, tuple[Path, str]] = {}
        for node in module.body:
            if not isinstance(node, ast.ImportFrom) or node.level != 0 or node.module is None:
                continue
            path = repo_module_path(node.module)
            if path is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                resolved[alias.asname or alias.name] = (path, alias.name)
        return resolved

    def find_function(self, path: Path, qualname: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
        module = self.load(path)
        current: ast.AST = module
        for part in qualname.split("."):
            body = getattr(current, "body", [])
            match = next(
                (
                    node
                    for node in body
                    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == part
                ),
                None,
            )
            if match is None:
                raise ValueError(f"Could not find {qualname} in {path}")
            current = match
        if not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            raise ValueError(f"{qualname} in {path} is not a function")
        return current

    def resolve_name(self, path: Path, local_name: str) -> tuple[Path, str] | None:
        module_imports = self.imports.get(path)
        if module_imports is None:
            self.load(path)
            module_imports = self.imports[path]
        return module_imports.get(local_name)

    def function_shape(self, path: Path, qualname: str) -> Shape:
        cache_key = (path, qualname)
        cached = self.function_cache.get(cache_key)
        if cached is not None:
            return cached
        function = self.find_function(path, qualname)
        analyzer = FunctionShapeAnalyzer(self, path)
        shape = analyzer.analyze(function)
        self.function_cache[cache_key] = shape
        return shape


class FunctionShapeAnalyzer:
    def __init__(self, store: ModuleStore, path: Path) -> None:
        self.store = store
        self.path = path
        self.env: dict[str, Shape] = {}
        self.return_shape: Shape = None

    def analyze(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> Shape:
        self._walk(function.body)
        return self.return_shape

    def _walk(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            if isinstance(statement, ast.Assign):
                self._handle_assign(statement.targets, statement.value)
            elif isinstance(statement, ast.AnnAssign):
                self._handle_assign([statement.target], statement.value)
            elif isinstance(statement, ast.Expr):
                self._handle_expr(statement.value)
            elif isinstance(statement, ast.Return):
                self._merge_return(self._eval_expr(statement.value))
            elif isinstance(statement, ast.For):
                self._walk(statement.body)
                self._walk(statement.orelse)
            elif isinstance(statement, ast.If):
                self._walk(statement.body)
                self._walk(statement.orelse)
            elif isinstance(statement, ast.With):
                self._walk(statement.body)
            elif isinstance(statement, ast.Try):
                self._walk(statement.body)
                for handler in statement.handlers:
                    self._walk(handler.body)
                self._walk(statement.orelse)
                self._walk(statement.finalbody)

    def _merge_return(self, shape: Shape) -> None:
        self.return_shape = merge_shapes(self.return_shape, shape)

    def _handle_assign(self, targets: list[ast.expr], value: ast.expr | None) -> None:
        if value is None:
            return
        shape = self._eval_expr(value)
        for target in targets:
            if isinstance(target, ast.Name):
                if shape is None:
                    self.env.pop(target.id, None)
                else:
                    self.env[target.id] = copy_shape(shape)
            else:
                key_target = self._subscript_target(target)
                if key_target is None:
                    continue
                base_name, key = key_target
                base_shape = self.env.get(base_name)
                if not isinstance(base_shape, DictShape):
                    base_shape = DictShape(set())
                    self.env[base_name] = base_shape
                base_shape.paths.update(with_key(key, shape))

    def _handle_expr(self, expr: ast.expr) -> None:
        if not isinstance(expr, ast.Call):
            return
        if isinstance(expr.func, ast.Attribute):
            action = expr.func.attr
            if isinstance(expr.func.value, ast.Name):
                base_name = expr.func.value.id
                if action == "update":
                    base_shape = self.env.get(base_name)
                    update_shape = self._eval_expr(expr.args[0]) if expr.args else None
                    if isinstance(base_shape, DictShape) and isinstance(update_shape, DictShape):
                        base_shape.paths.update(update_shape.paths)
                elif action == "append":
                    item_shape = self._eval_expr(expr.args[0]) if expr.args else None
                    base_shape = self.env.get(base_name)
                    if not isinstance(base_shape, ListShape):
                        base_shape = ListShape(set())
                        self.env[base_name] = base_shape
                    if isinstance(item_shape, DictShape):
                        base_shape.item_paths.update(item_shape.paths)
            else:
                nested_target = self._subscript_target(expr.func.value)
                if nested_target is None or action != "append":
                    return
                base_name, key = nested_target
                item_shape = self._eval_expr(expr.args[0]) if expr.args else None
                base_shape = self.env.get(base_name)
                if isinstance(base_shape, DictShape) and isinstance(item_shape, DictShape):
                    base_shape.paths.update(with_key(key, ListShape(item_shape.paths)))

    def _eval_expr(self, expr: ast.expr | None) -> Shape:
        if expr is None:
            return None
        if isinstance(expr, ast.Dict):
            paths: set[str] = set()
            for key_node, value_node in zip(expr.keys, expr.values):
                if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
                    continue
                key = key_node.value
                paths.update(with_key(key, self._eval_expr(value_node)))
            return DictShape(paths)
        if isinstance(expr, ast.List):
            item_paths: set[str] = set()
            for item in expr.elts:
                item_shape = self._eval_expr(item)
                if isinstance(item_shape, DictShape):
                    item_paths.update(item_shape.paths)
            return ListShape(item_paths)
        if isinstance(expr, ast.Name):
            shape = self.env.get(expr.id)
            return copy_shape(shape)
        if isinstance(expr, ast.Subscript):
            value_shape = self._eval_expr(expr.value)
            if isinstance(value_shape, ListShape):
                return ListShape(set(value_shape.item_paths))
            if isinstance(value_shape, DictShape):
                key = literal_str(expr.slice)
                if key is None:
                    return None
                nested = {path[len(key) + 1 :] for path in value_shape.paths if path.startswith(f"{key}.")}
                if key in value_shape.paths or nested:
                    return DictShape(nested)
            return None
        if isinstance(expr, ast.Call):
            return self._eval_call(expr)
        if isinstance(expr, ast.ListComp):
            if len(expr.generators) != 1:
                return None
            generator = expr.generators[0]
            if not isinstance(generator.target, ast.Name):
                return None
            iter_shape = self._eval_expr(generator.iter)
            if isinstance(iter_shape, ListShape) and isinstance(expr.elt, ast.Name) and expr.elt.id == generator.target.id:
                return ListShape(set(iter_shape.item_paths))
        return None

    def _eval_call(self, expr: ast.Call) -> Shape:
        if isinstance(expr.func, ast.Name):
            if expr.func.id == "list" and expr.args:
                return self._eval_expr(expr.args[0])
            resolved = self.store.resolve_name(self.path, expr.func.id)
            if resolved is not None:
                return copy_shape(self.store.function_shape(*resolved))
            local = self._local_function(expr.func.id)
            if local is not None:
                return copy_shape(self.store.function_shape(self.path, local))
        if isinstance(expr.func, ast.Attribute) and isinstance(expr.func.value, ast.Name):
            base_name = expr.func.value.id
            base_shape = self.env.get(base_name)
            if expr.func.attr == "values" and isinstance(base_shape, MapShape):
                return ListShape(set(base_shape.value_paths))
            if expr.func.attr == "setdefault" and len(expr.args) >= 2:
                default_shape = self._eval_expr(expr.args[1])
                if isinstance(default_shape, DictShape):
                    existing = self.env.get(base_name)
                    if not isinstance(existing, MapShape):
                        existing = MapShape(set())
                        self.env[base_name] = existing
                    existing.value_paths.update(default_shape.paths)
                    return DictShape(set(default_shape.paths))
        return None

    def _local_function(self, name: str) -> str | None:
        module = self.store.load(self.path)
        for node in module.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return name
        return None

    @staticmethod
    def _subscript_target(target: ast.expr) -> tuple[str, str] | None:
        if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
            return None
        key = literal_str(target.slice)
        if key is None:
            return None
        return (target.value.id, key)


def merge_shapes(left: Shape, right: Shape) -> Shape:
    if left is None:
        return copy_shape(right)
    if right is None:
        return copy_shape(left)
    if isinstance(left, DictShape) and isinstance(right, DictShape):
        return DictShape(set(left.paths) | set(right.paths))
    if isinstance(left, ListShape) and isinstance(right, ListShape):
        return ListShape(set(left.item_paths) | set(right.item_paths))
    if isinstance(left, MapShape) and isinstance(right, MapShape):
        return MapShape(set(left.value_paths) | set(right.value_paths))
    return copy_shape(left)


def copy_shape(shape: Shape) -> Shape:
    if isinstance(shape, DictShape):
        return DictShape(set(shape.paths))
    if isinstance(shape, ListShape):
        return ListShape(set(shape.item_paths))
    if isinstance(shape, MapShape):
        return MapShape(set(shape.value_paths))
    return None


def literal_str(expr: ast.expr) -> str | None:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    return None


def extract_reader_paths(path: Path, qualname: str, section_name: str) -> set[str]:
    store = ModuleStore()
    function = store.find_function(path, qualname)
    aliases: dict[str, str] = {}
    required: set[str] = set()

    def walk_expr(expr: ast.expr) -> None:
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and isinstance(expr.func.value, ast.Name):
            base_name = expr.func.value.id
            if expr.func.attr == "get" and base_name in aliases and expr.args:
                key = literal_str(expr.args[0])
                if key is not None:
                    required.add(join_path(aliases[base_name], key))
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                walk_expr(child)

    def walk_statements(statements: list[ast.stmt]) -> None:
        for statement in statements:
            if isinstance(statement, ast.Assign):
                value = statement.value
                alias_path = alias_value(value)
                for target in statement.targets:
                    if isinstance(target, ast.Name) and alias_path is not None:
                        aliases[target.id] = alias_path
                walk_expr(statement.value)
            elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                alias_path = alias_value(statement.value)
                if isinstance(statement.target, ast.Name) and alias_path is not None:
                    aliases[statement.target.id] = alias_path
                walk_expr(statement.value)
            elif isinstance(statement, ast.Expr):
                walk_expr(statement.value)
            elif isinstance(statement, ast.For):
                walk_expr(statement.iter)
                walk_statements(statement.body)
                walk_statements(statement.orelse)
            elif isinstance(statement, ast.If):
                walk_expr(statement.test)
                walk_statements(statement.body)
                walk_statements(statement.orelse)
            elif isinstance(statement, ast.With):
                walk_statements(statement.body)
            elif isinstance(statement, ast.Try):
                walk_statements(statement.body)
                for handler in statement.handlers:
                    walk_statements(handler.body)
                walk_statements(statement.orelse)
                walk_statements(statement.finalbody)
            elif isinstance(statement, ast.Return) and statement.value is not None:
                walk_expr(statement.value)

    def alias_value(expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if (
                expr.func.attr == "_privileged_section"
                and isinstance(expr.func.value, ast.Attribute)
                and expr.func.value.attr == "backend"
                and isinstance(expr.func.value.value, ast.Name)
                and expr.func.value.value.id == "self"
                and expr.args
                and literal_str(expr.args[0]) == section_name
            ):
                return ""
            if isinstance(expr.func.value, ast.Name) and expr.func.attr == "get" and expr.args:
                key = literal_str(expr.args[0])
                if key is not None and expr.func.value.id in aliases:
                    required.add(join_path(aliases[expr.func.value.id], key))
                    return join_path(aliases[expr.func.value.id], key)
        return None

    walk_statements(function.body)
    return required


def extract_privileged_section_names(path: Path) -> set[str]:
    store = ModuleStore()
    module = store.load(path)
    names: set[str] = set()
    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "_privileged_section":
            continue
        if not node.args:
            continue
        value = literal_str(node.args[0])
        if value:
            names.add(value)
    return names


def section_paths(shape: Shape, section_name: str) -> set[str]:
    if not isinstance(shape, DictShape):
        return set()
    prefix = f"{section_name}."
    result: set[str] = set()
    for path in shape.paths:
        if path == section_name:
            continue
        if path.startswith(prefix):
            result.add(path[len(prefix) :])
    return result


def compare_paths(name: str, producer_paths: set[str], consumer_paths: set[str]) -> ContractResult:
    return ContractResult(
        name=name,
        missing=consumer_paths - producer_paths,
        producer_paths=producer_paths,
        consumer_paths=consumer_paths,
    )


def report_contract(result: ContractResult) -> int:
    if not result.missing:
        print(f"OK  {result.name}")
        return 0
    print(f"ERR {result.name}")
    for path in sorted(result.missing):
        print(f"  missing: {path}")
    return 1


def main() -> int:
    writer_path = SRC_ROOT / "monitor/app/privileged_snapshot.py"
    constants_path = SRC_ROOT / "monitor/shared/constants.py"
    collectors_path = SRC_ROOT / "monitor/collectors"

    store = ModuleStore()
    snapshot_shape = store.function_shape(writer_path, "snapshot_payload")
    ethernet_writer_shape = store.function_shape(writer_path, "ethernet_snapshot")
    wifi_writer_shape = store.function_shape(writer_path, "wifi_snapshot")
    docker_writer_shape = store.function_shape(writer_path, "docker_snapshot")
    ethernet_live_shape = store.function_shape(collectors_path / "networking.py", "EthernetCollector.live_state")
    wifi_live_shape = store.function_shape(collectors_path / "networking.py", "WifiCollector.live_state")
    docker_live_shape = store.function_shape(collectors_path / "containers.py", "ContainersCollector.docker_state_live")

    failures = 0

    reader_sections = set()
    for file_path in collectors_path.glob("*.py"):
        reader_sections.update(extract_privileged_section_names(file_path))
    written_sections = top_level_paths(snapshot_shape.paths) if isinstance(snapshot_shape, DictShape) else set()
    missing_sections = reader_sections - written_sections
    if missing_sections:
        print("ERR privileged section coverage")
        for section in sorted(missing_sections):
            print(f"  missing section: {section}")
        failures += 1
    else:
        print("OK  privileged section coverage")

    direct_contracts = [
        (
            "logs section",
            "logs",
            collectors_path / "logs.py",
            "LogsCollector.collect",
        ),
        (
            "systemd section",
            "systemd",
            collectors_path / "systemd_health.py",
            "SystemdHealthCollector.collect",
        ),
        (
            "hardware section",
            "hardware",
            collectors_path / "resources.py",
            "HardwareCollector.collect",
        ),
        (
            "network section",
            "network",
            collectors_path / "networking.py",
            "NetworkCollector.collect",
        ),
        (
            "fs_integrity section",
            "fs_integrity",
            collectors_path / "resources.py",
            "FilesystemIntegrityCollector.collect",
        ),
        (
            "security section",
            "security",
            collectors_path / "security.py",
            "SecurityCollector.collect",
        ),
    ]

    for name, section_name, reader_path, qualname in direct_contracts:
        producer_paths = section_paths(snapshot_shape, section_name)
        consumer_paths = extract_reader_paths(reader_path, qualname, section_name)
        failures += report_contract(compare_paths(name, producer_paths, consumer_paths))

    wifi_result = compare_paths(
        "wifi state parity",
        wifi_writer_shape.paths if isinstance(wifi_writer_shape, DictShape) else set(),
        wifi_live_shape.paths if isinstance(wifi_live_shape, DictShape) else set(),
    )
    failures += report_contract(wifi_result)

    ethernet_result = compare_paths(
        "ethernet state parity",
        ethernet_writer_shape.paths if isinstance(ethernet_writer_shape, DictShape) else set(),
        ethernet_live_shape.paths if isinstance(ethernet_live_shape, DictShape) else set(),
    )
    failures += report_contract(ethernet_result)

    docker_result = compare_paths(
        "container state parity (top-level)",
        top_level_paths(docker_writer_shape.paths) if isinstance(docker_writer_shape, DictShape) else set(),
        (
            top_level_paths(docker_live_shape.paths) - {"source"}
            if isinstance(docker_live_shape, DictShape)
            else set()
        ),
    )
    failures += report_contract(docker_result)

    version_text = constants_path.read_text(encoding="utf-8")
    if "PRIVILEGED_SNAPSHOT_VERSION" not in version_text:
        print("ERR snapshot version constant")
        print("  missing: PRIVILEGED_SNAPSHOT_VERSION")
        failures += 1
    else:
        print("OK  snapshot version constant")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
