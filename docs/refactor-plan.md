# Refactor Plan

This document tracks the recommended refactor order for moving the repository
from a flat script-first layout to a more standard Python project structure.

## Principles

- Keep the application runnable after every step.
- Separate structural moves from behavioral changes.
- Prefer additive wrappers first, then internal moves, then cleanup.
- Commit after every completed step.

## Target Shape

```text
monitor/
  pyproject.toml
  README.md
  src/
    monitor/
      __init__.py
      cli/
        monitor_tui.py
        package_cleanup.py
        privileged_snapshot.py
      tui/
        dashboard.py
        package_cleanup.py
      model/
        dashboard.py
      collectors/
        packages.py
        storage.py
        systemd.py
        memory.py
        cpu.py
        thermal.py
        hardware.py
        network.py
        wifi.py
        bluetooth.py
        security.py
        hygiene.py
        boot.py
      packages/
        inventory.py
        removal.py
        state.py
      snapshot/
        schema.py
        writer.py
      shared/
        commands.py
        formatting.py
        parsing.py
        paths.py
  scripts/
    install_monitor_privileged.sh
    refresh_monitor_privileged.sh
  packaging/
    systemd/
      monitor-privileged-snapshot.service
      monitor-privileged-snapshot.timer
  tests/
    unit/
    integration/
```

## Refactor Order

### Step 1: Project scaffolding

- Add `pyproject.toml`.
- Add `src/monitor/` package skeleton.
- Add thin package CLI entrypoints.
- Keep current top-level scripts as the source of truth.
- Avoid behavior changes.
- Commit when complete.

### Step 2: Shared utilities extraction

- Move duplicated helpers and constants into `shared/` and `snapshot/`.
- Start with command execution, text/file helpers, parsing helpers, shared regexes,
  and snapshot version/path logic.
- Update callers with minimal behavior change.
- Commit when complete.

### Step 3: Main monitor split

- Extract the curses UI into `tui/dashboard.py`.
- Extract `DashboardModel` into `model/dashboard.py`.
- Split `MonitorBackend` into focused modules under `collectors/`.
- Keep CLI behavior stable while the internal layout changes.
- Commit when complete.

### Step 4: Package cleanup split

- Move cleanup CLI entrypoint under `cli/`.
- Separate UI, package inventory loading, removal planning, and state handling
  into `tui/` and `packages/`.
- Keep current key behavior and command flow unchanged.
- Commit when complete.

### Step 5: Operational asset cleanup

- Move shell scripts into `scripts/`.
- Move systemd units into `packaging/systemd/` or `deploy/systemd/`.
- Update installer paths after the move.
- Commit when complete.

### Step 6: Runtime state normalization

- Standardize runtime state on XDG locations.
- Remove repo-local `.monitor_state/` fallback once a supported migration path is in place.
- Commit when complete.

### Step 7: Test scaffolding and coverage

- Add `tests/unit/` for parsers, formatters, snapshot validation, and command adapters.
- Add `tests/integration/` for CLI and command-mocking flows where practical.
- Commit when complete.

### Step 8: Legacy root script retirement

- Replace old root scripts with tiny compatibility wrappers or remove them.
- Update docs and install instructions to use packaged entrypoints.
- Commit when complete.

## Notes For This Repo

- The working tree already had local edits in `README.md` and `monitor_tui.py`
  when this plan was added, so step 1 should avoid rewriting those files.
- The initial package CLI entrypoints can wrap the current root scripts until the
  implementation is moved into `src/monitor/`.
