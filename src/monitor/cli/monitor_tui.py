from __future__ import annotations

from monitor._legacy import call_legacy_main


def main() -> int:
    return call_legacy_main("monitor_tui.py")


if __name__ == "__main__":
    raise SystemExit(main())
