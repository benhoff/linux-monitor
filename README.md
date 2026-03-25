# monitor

`monitor_tui.py` is a no-dependency Python TUI for Arch/Linux system health checks.

It groups the dashboard into three tabs:

- `Tier 1`: kernel/firmware/NVIDIA package tracking, storage, systemd health, journal errors
- `Tier 2`: memory pressure, CPU/load, thermal state, hardware health, filesystem integrity, device-specific signals
- `Tier 3`: network state, exposure surface, hygiene, boot regressions
- `Packages`: official repo update backlog with size totals, ETA, and per-package rows
- `AUR`: AUR update backlog with size totals, ETA, and per-package rows

## Run

```bash
python3 monitor_tui.py
```

## Keys

- `Left` / `Right`: switch tabs
- `Up` / `Down`: scroll
- `PageUp` / `PageDown`: faster scroll
- `r`: force refresh
- `s`: toggle package sorting by size/name in the `Packages` tab
- `q`: quit

## Colors

- Green: healthy / empty / zero-count states
- Yellow: watch items, missing permissions, or degraded visibility
- Red: likely problems or sections that need attention now

## One-shot mode

```bash
python3 monitor_tui.py --once --tab tier1
python3 monitor_tui.py --once --tab tier2
python3 monitor_tui.py --once --tab packages
python3 monitor_tui.py --once --tab aur
python3 monitor_tui.py --once --tab all
```

## Notes

- The app uses standard Linux interfaces first (`/proc`, `/sys`) and falls back to commands like `pacman`, `yay`, `journalctl`, `systemctl`, `smartctl`, `nvidia-smi`, `ip`, `ss`, and `ffmpeg` when available.
- Some sections will show partial data if tools are missing or if the current user cannot read privileged system state.
- The package panel tracks only kernel, firmware, and NVIDIA versions.
- In TUI mode, package update metadata is refreshed in the background and `r` also triggers a package refresh request.
- Tier 1 includes a `Privileged Snapshot` panel that checks snapshot schema drift and staleness before the TUI trusts privileged data.

## Privileged Snapshot

The safe privilege model is:

- run the TUI as your normal user
- run `monitor_privileged_snapshot.py` as root on a timer
- let the TUI read `/run/monitor/privileged_snapshot.json`

Write a snapshot manually:

```bash
sudo python3 monitor_privileged_snapshot.py --output /run/monitor/privileged_snapshot.json
```

Install the privileged snapshot service and timer:

```bash
./install_monitor_privileged.sh
```

Refresh the installed privileged snapshot writer and force a new snapshot:

```bash
./refresh_monitor_privileged.sh
```

If you installed the helper into `/usr/local/bin`, you can also run:

```bash
monitor-privileged-refresh
```

Use a different snapshot path:

```bash
MONITOR_PRIVILEGED_SNAPSHOT=/path/to/privileged_snapshot.json python3 monitor_tui.py
```

Example systemd unit templates are in:

- `contrib/systemd/monitor-privileged-snapshot.service`
- `contrib/systemd/monitor-privileged-snapshot.timer`

The installer writes concrete unit files into `/etc/systemd/system` and prompts for `sudo` automatically.
It also installs `monitor-privileged-refresh` into `/usr/local/bin` when `refresh_monitor_privileged.sh` is present in the repo.
