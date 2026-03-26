from __future__ import annotations

import argparse

from monitor.packages.model import PackageCleanupModel
from monitor.tui.package_cleanup import PackageCleanupUI


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Conservative Arch package cleanup TUI for installed official packages."
    )
    return parser.parse_args()


def main() -> int:
    parse_args()
    model = PackageCleanupModel()
    model.start()
    try:
        PackageCleanupUI(model).run()
    finally:
        model.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
