#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="monitor-privileged-snapshot.service"
TIMER_NAME="monitor-privileged-snapshot.timer"
INSTALL_DIR="/usr/local/lib/monitor"
SYSTEMD_DIR="/etc/systemd/system"
SNAPSHOT_OUTPUT="/run/monitor/privileged_snapshot.json"
REFRESH_INTERVAL="${MONITOR_SNAPSHOT_INTERVAL:-2min}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_SCRIPT="${SCRIPT_DIR}/monitor_privileged_snapshot.py"
INSTALLED_SCRIPT="${INSTALL_DIR}/monitor_privileged_snapshot.py"
SERVICE_PATH="${SYSTEMD_DIR}/${SERVICE_NAME}"
TIMER_PATH="${SYSTEMD_DIR}/${TIMER_NAME}"

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "${command_name}" >&2
    exit 1
  fi
}

write_service() {
  cat >"${SERVICE_PATH}" <<EOF
[Unit]
Description=Write privileged monitor snapshot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${INSTALLED_SCRIPT} --output ${SNAPSHOT_OUTPUT}

[Install]
WantedBy=multi-user.target
EOF
}

write_timer() {
  cat >"${TIMER_PATH}" <<EOF
[Unit]
Description=Refresh privileged monitor snapshot every ${REFRESH_INTERVAL}

[Timer]
OnBootSec=30s
OnUnitActiveSec=${REFRESH_INTERVAL}
AccuracySec=15s
Unit=${SERVICE_NAME}

[Install]
WantedBy=timers.target
EOF
}

main() {
  require_command python3
  require_command systemctl
  require_command install

  if [[ ! -f "${SOURCE_SCRIPT}" ]]; then
    printf 'Could not find %s\n' "${SOURCE_SCRIPT}" >&2
    exit 1
  fi

  if [[ "${EUID}" -ne 0 ]]; then
    require_command sudo
    printf 'This installer will set up the privileged monitor snapshot service.\n'
    printf 'It needs sudo to write into %s and %s.\n' "${INSTALL_DIR}" "${SYSTEMD_DIR}"
    export MONITOR_SNAPSHOT_INTERVAL="${REFRESH_INTERVAL}"
    sudo -v
    exec sudo --preserve-env=MONITOR_SNAPSHOT_INTERVAL bash "${SCRIPT_DIR}/install_monitor_privileged.sh" "$@"
  fi

  install -d -m 0755 "${INSTALL_DIR}"
  install -m 0755 "${SOURCE_SCRIPT}" "${INSTALLED_SCRIPT}"

  write_service
  write_timer

  systemctl daemon-reload
  systemctl enable --now "${TIMER_NAME}"
  systemctl start "${SERVICE_NAME}"

  printf 'Installed %s\n' "${INSTALLED_SCRIPT}"
  printf 'Installed %s\n' "${SERVICE_PATH}"
  printf 'Installed %s\n' "${TIMER_PATH}"
  printf 'Enabled and started %s\n' "${TIMER_NAME}"
  printf 'Ran %s once to write %s\n' "${SERVICE_NAME}" "${SNAPSHOT_OUTPUT}"
}

main "$@"
