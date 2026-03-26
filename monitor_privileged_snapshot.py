#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent / "src"
if SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from monitor.app.privileged_snapshot import main


if __name__ == "__main__":
    raise SystemExit(main())
