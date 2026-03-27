#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path


def add_repo_src_to_path() -> None:
    script_dir = Path(__file__).resolve().parent
    for base_dir in (script_dir, *script_dir.parents):
        src_dir = base_dir / "src"
        if not (src_dir / "monitor" / "__init__.py").is_file():
            continue
        src_path = str(src_dir)
        if src_path not in sys.path:
            sys.path.insert(0, src_path)
        return


add_repo_src_to_path()

from monitor.app.privileged_snapshot import main


if __name__ == "__main__":
    raise SystemExit(main())
