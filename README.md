# monitor

`monitor-tui` is a no-dependency Python TUI for Linux system health checks.

`monitor-package-cleanup` is a separate no-dependency Python TUI for conservative package cleanup on Arch.
It shows only installed official-repo packages that validate as removable candidates, hides built-in protected packages, and can mark additional packages as protected from inside the UI.

On systems with a supported package manager (`pacman` or `apt`) it groups the dashboard into three core tabs plus package tabs:

- `Tier 1`: kernel/firmware/NVIDIA package tracking, storage, systemd health, journal errors
- `Tier 2`: memory pressure, CPU/load, thermal state, hardware health, filesystem integrity, device-specific signals
- `Tier 3`: network state, Wi-Fi intelligence, Bluetooth, exposure surface, Docker/container hygiene, system hygiene, boot regressions
- `Packages`: official repo update backlog with size totals, ETA, and per-package rows
- `AUR`: AUR update backlog with size totals, ETA, and per-package rows on Arch systems with `yay`

On Debian and Ubuntu, the core health tabs still work and the repo package tab uses `apt`.
On systems without a supported package backend, the core health tabs still work and package tabs are hidden.
Hardware-specific NVIDIA and AVMatrix sections are only shown when their monitoring stack is detected.

## Run

```bash
monitor-tui
monitor-package-cleanup
```

If you are running directly from the repo without installing entrypoints, use the repo-root
`monitor_tui.py` and `package_cleanup_tui.py` wrappers, or run
`bin/monitor_privileged_snapshot.py` for the privileged snapshot helper.

## Keys

- `Left` / `Right`: switch tabs
- `Up` / `Down`: scroll
- `PageUp` / `PageDown`: faster scroll
- `r`: force refresh
- `s`: toggle package sorting by size/name in the `Packages` tab
- `q`: quit

## Package Cleanup TUI

Main view:

- shows only removable official packages
- supports marking multiple roots for bulk removal
- keeps the main list to package name and description
- validates candidates in the background using pacman removal previews

Keys:

- `Up` / `Down`: move through the candidate list
- `Space`: mark or unmark the current package
- `Enter`: inspect the selected package
- `x`: remove all marked packages, or the current package when nothing is marked
- `c`: clear all current marks
- `o`: open the orphan package view
- `m`: protect and hide the selected package
- `p`: open the user-protected package list
- `s`: cycle sort by reclaimable size, installed size, or name
- `r`: refresh package metadata and candidate validation
- `q`: quit or go back from subviews

Detail view:

- shows a bounded removal tree for the selected package
- shows reclaimable installed size and the full removal impact
- `Space` marks or unmarks the current package without leaving detail view
- `x` runs `pacman -Rsu --confirm <package>` through the TUI after a final prompt

Orphan view:

- lists dependency-installed packages with no reverse dependencies
- auto-selects all visible orphan packages by default
- `Space` toggles the current orphan on or off
- `a` reselects all current orphans
- `c` clears the current orphan selection
- `x` runs a bulk uninstall for the currently selected orphan set
- `m` protects and hides the current orphan package

Protected view:

- lists packages you hid manually
- `u` removes the selected package from the user-protected list

State:

- user-protected packages and removal preview cache are stored in `~/.local/state/monitor/package_cleanup_state.json` unless `XDG_STATE_HOME` is set
- successful removals update the cached package inventory incrementally and only revalidate impacted/new roots instead of forcing a full catalog reload
- monitor diff snapshots are stored in `~/.local/state/monitor/diff_snapshot.json` unless `XDG_STATE_HOME` or `MONITOR_DIFF_SNAPSHOT` is set
- if an old repo-local `.monitor_state/diff_snapshot.json` exists in the current working directory, the monitor will migrate it forward automatically

## Colors

- Green: healthy / empty / zero-count states
- Yellow: watch items, missing permissions, or degraded visibility
- Red: likely problems or sections that need attention now

## One-shot mode

```bash
monitor-tui --once --tab tier1
monitor-tui --once --tab tier2
monitor-tui --once --tab packages
monitor-tui --once --tab aur
monitor-tui --once --tab all
```

## Notes

- The app uses standard Linux interfaces first (`/proc`, `/sys`) and falls back to commands like `pacman`, `yay`, `journalctl`, `systemctl`, `smartctl`, `nvidia-smi`, `ip`, `ss`, and `ffmpeg` when available.
- Some sections will show partial data if tools are missing or if the current user cannot read privileged system state.
- The package panel tracks kernel, firmware, and NVIDIA versions for supported package backends and is hidden on unsupported package managers.
- In TUI mode, package update metadata is refreshed in the background and `r` also triggers a package refresh request.
- Tier 1 includes a `Privileged Snapshot` panel that checks snapshot schema drift and staleness before the TUI trusts privileged data.
- Tier 3 includes a `Wi-Fi Intelligence` panel that surfaces link quality, RF state, PHY rates, retries, beacon loss, and recent Wi-Fi journal hints when those signals are available.
- DNS probe targets and package-cache labels are distro-aware, so Debian-family systems use Debian/Ubuntu package and mirror conventions instead of Arch-specific ones.
- Debian and Ubuntu package hygiene uses `apt`/`apt-mark` where available, while AUR-specific features stay Arch-only.
- Tier 3 includes a `Bluetooth` panel that tracks service state, adapter/rfkill visibility, controller power/discoverability, connected and paired devices, and recent Bluetooth journal hints when those signals are available.
- Tier 3 includes a `Containers / Docker` panel that surfaces unhealthy/restarting containers, CPU and memory hotspots, writable-layer and Docker-root storage growth, dangling leftovers, and local image-age hygiene signals.
- Tier 3 `System Hygiene` now surfaces package-cache age/count, large watched directories, config drift under `/etc`, scheduled task hygiene, and container/VM leftovers.
- Tier 3 `Security / Exposure Surface` now calls out services listening on non-loopback addresses before listing all sockets.

## Privileged Snapshot

The safe privilege model is:

- run the TUI as your normal user
- run `monitor-privileged-snapshot` as root on a timer
- let the TUI read `/run/monitor/privileged_snapshot.json`

Write a snapshot manually:

```bash
sudo monitor-privileged-snapshot --output /run/monitor/privileged_snapshot.json
```

Install the privileged snapshot service and timer:

```bash
./scripts/install_monitor_privileged.sh
```

Refresh the installed privileged snapshot writer and force a new snapshot:

```bash
./scripts/refresh_monitor_privileged.sh
```

Debug a missing, stale, unreadable, or mismatched privileged snapshot:

```bash
./scripts/debug_monitor_privileged.sh
```

The debug script checks the snapshot file, systemd service/timer state, unit `ExecStart`,
path mismatches, freshness, permissions, and recent service logs, then prints concrete fix steps.
`monitor-privileged-snapshot.service` is a `Type=oneshot` unit, so `inactive (dead)` after a
successful run is normal; the timer should be enabled and active.

If you installed the helper into `/usr/local/bin`, you can also run:

```bash
monitor-privileged-refresh
```

If the debug helper was installed into `/usr/local/bin`, you can also run:

```bash
monitor-privileged-debug
```

Use a different snapshot path:

```bash
MONITOR_PRIVILEGED_SNAPSHOT=/path/to/privileged_snapshot.json monitor-tui
```

Example systemd unit templates are in:

- `packaging/systemd/monitor-privileged-snapshot.service`
- `packaging/systemd/monitor-privileged-snapshot.timer`

The installer writes concrete unit files into `/etc/systemd/system` and prompts for `sudo` automatically.
It also installs `monitor-privileged-refresh` and `monitor-privileged-debug` into `/usr/local/bin`
when their scripts are present in the repo.
The repo-root `install_monitor_privileged.sh`, `refresh_monitor_privileged.sh`, and
`debug_monitor_privileged.sh` remain as compatibility wrappers.
