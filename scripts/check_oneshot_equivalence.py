#!/usr/bin/env python3

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


NOISY_LINE_PREFIXES = (
    "Active devices: ",
    "Background refresh: last refresh ",
    "Compared with ",
    "Disk IO: ",
    "Last refresh: ",
    "Uptime: ",
)

NOISY_LINE_EXACT = {
    "No prior diff snapshot yet. A baseline will be written automatically.",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare monitor_tui.py --once output between two revisions.",
    )
    parser.add_argument("left", help="Left revision to compare, or WORKTREE")
    parser.add_argument("right", help="Right revision to compare, or WORKTREE")
    parser.add_argument(
        "--tab",
        choices=("tier1", "tier2", "tier3", "packages", "aur", "all"),
        default="tier1",
        help="Tab to compare in --once mode.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable or "python3",
        help="Python interpreter to use for both revisions.",
    )
    parser.add_argument(
        "--no-normalize",
        action="store_true",
        help="Compare raw output instead of normalizing volatile lines.",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep exported temporary trees for inspection.",
    )
    parser.add_argument(
        "--ignore-prefix",
        action="append",
        default=[],
        help="Additional stripped line prefix to ignore during normalized comparison.",
    )
    return parser.parse_args()


def export_revision(ref: str, dest: Path) -> Path:
    if ref.upper() == "WORKTREE":
        return repo_root()
    dest.mkdir(parents=True, exist_ok=True)
    archive_path = dest / "tree.tar"
    subprocess.run(
        ["git", "archive", "--format=tar", "-o", str(archive_path), ref],
        cwd=repo_root(),
        check=True,
    )
    tree_dir = dest / "tree"
    tree_dir.mkdir()
    with tarfile.open(archive_path) as tar:
        tar.extractall(tree_dir)
    archive_path.unlink()
    return tree_dir


def run_oneshot(tree: Path, tab: str, python_exe: str, state_root: Path) -> str:
    env = os.environ.copy()
    if state_root.exists():
        shutil.rmtree(state_root)
    state_root.mkdir(parents=True, exist_ok=True)
    env["MONITOR_DIFF_SNAPSHOT"] = str(state_root / "diff_snapshot.json")
    env["XDG_STATE_HOME"] = str(state_root / "xdg-state")
    command = [python_exe, "monitor_tui.py", "--once", "--tab", tab]
    result = subprocess.run(
        command,
        cwd=tree,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{tree}: {' '.join(command)} failed with exit code {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout


def normalize_output(text: str, extra_ignored_prefixes: list[str]) -> str:
    ignored_prefixes = (*NOISY_LINE_PREFIXES, *extra_ignored_prefixes)
    lines: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped in NOISY_LINE_EXACT:
            continue
        if any(stripped.startswith(prefix) for prefix in ignored_prefixes):
            continue
        normalized = raw
        normalized = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:[+-]\d{2}:\d{2})?\b", "<datetime>", normalized)
        normalized = re.sub(r"\b\d{2}:\d{2}:\d{2}\b", "<time>", normalized)
        normalized = re.sub(r"\|\s+\d+[smhd](?:\s+\d+[hm])*\s+old\b", "| <age> old", normalized)
        normalized = re.sub(r"\|\s+oldest\s+\d+[smhd](?:\s+\d+[hm])*\b", "| oldest <age>", normalized)
        lines.append(normalized.rstrip())
    return "\n".join(lines).strip() + "\n"


def compare_outputs(left_name: str, left_output: str, right_name: str, right_output: str) -> int:
    if left_output == right_output:
        print(f"Equivalent: {left_name} == {right_name}")
        return 0
    diff = difflib.unified_diff(
        left_output.splitlines(),
        right_output.splitlines(),
        fromfile=left_name,
        tofile=right_name,
        lineterm="",
    )
    print("\n".join(diff))
    return 1


def main() -> int:
    args = parse_args()
    with tempfile.TemporaryDirectory(prefix="monitor-oneshot-") as temp_root_text:
        temp_root = Path(temp_root_text)
        left_dir = export_revision(args.left, temp_root / "left")
        right_dir = export_revision(args.right, temp_root / "right")

        left_output = run_oneshot(left_dir, args.tab, args.python, temp_root / "state-left")
        right_output = run_oneshot(right_dir, args.tab, args.python, temp_root / "state-right")

        if args.keep_temp:
            kept_root = repo_root() / ".tmp-oneshot-equivalence"
            if kept_root.exists():
                shutil.rmtree(kept_root)
            shutil.copytree(temp_root, kept_root)
            print(f"Kept exported trees under {kept_root}")

        if not args.no_normalize:
            left_output = normalize_output(left_output, args.ignore_prefix)
            right_output = normalize_output(right_output, args.ignore_prefix)

        return compare_outputs(args.left, left_output, args.right, right_output)


if __name__ == "__main__":
    raise SystemExit(main())
