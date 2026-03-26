from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_legacy_module(script_name: str) -> ModuleType:
    script_path = _repo_root() / script_name
    module_name = f"_monitor_legacy_{script_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load legacy script: {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def call_legacy_main(script_name: str) -> int:
    module = load_legacy_module(script_name)
    main = getattr(module, "main", None)
    if not callable(main):
        raise RuntimeError(f"Legacy script does not expose main(): {script_name}")
    return int(main())
