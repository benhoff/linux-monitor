#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="monitor-privileged-snapshot.service"
TIMER_NAME="monitor-privileged-snapshot.timer"
INSTALL_DIR="/usr/local/lib/monitor"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
SNAPSHOT_OUTPUT="/run/monitor/privileged_snapshot.json"
REFRESH_INTERVAL="${MONITOR_SNAPSHOT_INTERVAL:-2min}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SOURCE_SCRIPT="${REPO_ROOT}/monitor_privileged_snapshot.py"
SOURCE_REFRESH="${SCRIPT_DIR}/refresh_monitor_privileged.sh"
SOURCE_PACKAGE_ROOT="${REPO_ROOT}/src/monitor"
SOURCE_APP_INIT="${SOURCE_PACKAGE_ROOT}/app/__init__.py"
SOURCE_APP_PRIVILEGED="${SOURCE_PACKAGE_ROOT}/app/privileged_snapshot.py"
SOURCE_SHARED_INIT="${SOURCE_PACKAGE_ROOT}/shared/__init__.py"
SOURCE_SHARED_CONSTANTS="${SOURCE_PACKAGE_ROOT}/shared/constants.py"
SOURCE_SHARED_TEXT="${SOURCE_PACKAGE_ROOT}/shared/text.py"
INSTALLED_SCRIPT="${INSTALL_DIR}/monitor_privileged_snapshot.py"
INSTALLED_PACKAGE_ROOT="${INSTALL_DIR}/src/monitor"
INSTALLED_APP_DIR="${INSTALLED_PACKAGE_ROOT}/app"
INSTALLED_APP_INIT="${INSTALLED_APP_DIR}/__init__.py"
INSTALLED_APP_PRIVILEGED="${INSTALLED_APP_DIR}/privileged_snapshot.py"
INSTALLED_SHARED_DIR="${INSTALLED_PACKAGE_ROOT}/shared"
INSTALLED_PACKAGE_INIT="${INSTALLED_PACKAGE_ROOT}/__init__.py"
INSTALLED_SHARED_INIT="${INSTALLED_SHARED_DIR}/__init__.py"
INSTALLED_SHARED_CONSTANTS="${INSTALLED_SHARED_DIR}/constants.py"
INSTALLED_SHARED_TEXT="${INSTALLED_SHARED_DIR}/text.py"
INSTALLED_REFRESH="${BIN_DIR}/monitor-privileged-refresh"
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
  if [[ ! -f "${SOURCE_APP_INIT}" || ! -f "${SOURCE_APP_PRIVILEGED}" || ! -f "${SOURCE_SHARED_INIT}" || ! -f "${SOURCE_SHARED_CONSTANTS}" || ! -f "${SOURCE_SHARED_TEXT}" ]]; then
    printf 'Could not find required package files under %s\n' "${SOURCE_PACKAGE_ROOT}" >&2
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
  install -d -m 0755 "${INSTALLED_APP_DIR}"
  install -d -m 0755 "${INSTALLED_SHARED_DIR}"
  install -m 0755 "${SOURCE_SCRIPT}" "${INSTALLED_SCRIPT}"
  install -m 0644 "${SOURCE_PACKAGE_ROOT}/__init__.py" "${INSTALLED_PACKAGE_INIT}"
  install -m 0644 "${SOURCE_APP_INIT}" "${INSTALLED_APP_INIT}"
  install -m 0644 "${SOURCE_APP_PRIVILEGED}" "${INSTALLED_APP_PRIVILEGED}"
  install -m 0644 "${SOURCE_SHARED_INIT}" "${INSTALLED_SHARED_INIT}"
  install -m 0644 "${SOURCE_SHARED_CONSTANTS}" "${INSTALLED_SHARED_CONSTANTS}"
  install -m 0644 "${SOURCE_SHARED_TEXT}" "${INSTALLED_SHARED_TEXT}"
  if [[ -f "${SOURCE_REFRESH}" ]]; then
    install -m 0755 "${SOURCE_REFRESH}" "${INSTALLED_REFRESH}"
  fi

  write_service
  write_timer

  systemctl daemon-reload
  systemctl enable --now "${TIMER_NAME}"
  systemctl start "${SERVICE_NAME}"

  printf 'Installed %s\n' "${INSTALLED_SCRIPT}"
  printf 'Installed shared package under %s\n' "${INSTALLED_PACKAGE_ROOT}"
  if [[ -f "${SOURCE_REFRESH}" ]]; then
    printf 'Installed %s\n' "${INSTALLED_REFRESH}"
  fi
  printf 'Installed %s\n' "${SERVICE_PATH}"
  printf 'Installed %s\n' "${TIMER_PATH}"
  printf 'Enabled and started %s\n' "${TIMER_NAME}"
  printf 'Ran %s once to write %s\n' "${SERVICE_NAME}" "${SNAPSHOT_OUTPUT}"
}

main "$@"
