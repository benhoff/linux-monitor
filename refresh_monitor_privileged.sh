#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="monitor-privileged-snapshot.service"
INSTALL_DIR="/usr/local/lib/monitor"
SNAPSHOT_OUTPUT="${MONITOR_SNAPSHOT_OUTPUT:-/run/monitor/privileged_snapshot.json}"

SELF_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${SELF_PATH}")" && pwd)"
SOURCE_SCRIPT="${SCRIPT_DIR}/monitor_privileged_snapshot.py"
SOURCE_PACKAGE_ROOT="${SCRIPT_DIR}/src/monitor"
SOURCE_SHARED_INIT="${SOURCE_PACKAGE_ROOT}/shared/__init__.py"
SOURCE_SHARED_CONSTANTS="${SOURCE_PACKAGE_ROOT}/shared/constants.py"
SOURCE_SHARED_TEXT="${SOURCE_PACKAGE_ROOT}/shared/text.py"
INSTALLED_SCRIPT="${INSTALL_DIR}/monitor_privileged_snapshot.py"
INSTALLED_PACKAGE_ROOT="${INSTALL_DIR}/src/monitor"
INSTALLED_SHARED_DIR="${INSTALLED_PACKAGE_ROOT}/shared"
INSTALLED_PACKAGE_INIT="${INSTALLED_PACKAGE_ROOT}/__init__.py"
INSTALLED_SHARED_INIT="${INSTALLED_SHARED_DIR}/__init__.py"
INSTALLED_SHARED_CONSTANTS="${INSTALLED_SHARED_DIR}/constants.py"
INSTALLED_SHARED_TEXT="${INSTALLED_SHARED_DIR}/text.py"

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "${command_name}" >&2
    exit 1
  fi
}

main() {
  require_command python3

  if [[ "${EUID}" -ne 0 ]]; then
    require_command sudo
    printf 'This will refresh the privileged monitor snapshot.\n'
    printf 'It uses sudo because the snapshot is written to %s.\n' "${SNAPSHOT_OUTPUT}"
    export MONITOR_SNAPSHOT_OUTPUT="${SNAPSHOT_OUTPUT}"
    sudo -v
    exec sudo --preserve-env=MONITOR_SNAPSHOT_OUTPUT bash "${SELF_PATH}" "$@"
  fi

  if [[ -f "${SOURCE_SCRIPT}" ]]; then
    require_command install
    install -d -m 0755 "${INSTALL_DIR}"
    install -d -m 0755 "${INSTALLED_SHARED_DIR}"
    install -m 0755 "${SOURCE_SCRIPT}" "${INSTALLED_SCRIPT}"
    install -m 0644 "${SOURCE_PACKAGE_ROOT}/__init__.py" "${INSTALLED_PACKAGE_INIT}"
    install -m 0644 "${SOURCE_SHARED_INIT}" "${INSTALLED_SHARED_INIT}"
    install -m 0644 "${SOURCE_SHARED_CONSTANTS}" "${INSTALLED_SHARED_CONSTANTS}"
    install -m 0644 "${SOURCE_SHARED_TEXT}" "${INSTALLED_SHARED_TEXT}"
    printf 'Updated %s from the current repo copy.\n' "${INSTALLED_SCRIPT}"
    printf 'Updated shared package under %s.\n' "${INSTALLED_PACKAGE_ROOT}"
  elif [[ ! -f "${INSTALLED_SCRIPT}" ]]; then
    printf 'Could not find %s or %s\n' "${SOURCE_SCRIPT}" "${INSTALLED_SCRIPT}" >&2
    exit 1
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files "${SERVICE_NAME}" --no-legend >/dev/null 2>&1; then
    if systemctl start "${SERVICE_NAME}"; then
      printf 'Triggered %s to rewrite %s\n' "${SERVICE_NAME}" "${SNAPSHOT_OUTPUT}"
      exit 0
    fi
  fi

  python3 "${INSTALLED_SCRIPT}" --output "${SNAPSHOT_OUTPUT}"
  printf 'Wrote %s\n' "${SNAPSHOT_OUTPUT}"
}

main "$@"
