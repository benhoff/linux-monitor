#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="monitor-privileged-snapshot.service"
TIMER_NAME="monitor-privileged-snapshot.timer"
DEFAULT_SNAPSHOT_PATH="/run/monitor/privileged_snapshot.json"
EXPECTED_VERSION=3
DEFAULT_MAX_AGE=900
INSTALLED_SCRIPT="/usr/local/lib/monitor/monitor_privileged_snapshot.py"

SELF_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${SELF_PATH}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SNAPSHOT_PATH="${MONITOR_PRIVILEGED_SNAPSHOT:-${DEFAULT_SNAPSHOT_PATH}}"
SNAPSHOT_PATH_SOURCE="default"
if [[ -n "${MONITOR_PRIVILEGED_SNAPSHOT:-}" ]]; then
  SNAPSHOT_PATH_SOURCE="MONITOR_PRIVILEGED_SNAPSHOT"
fi

MAX_AGE="${MONITOR_PRIVILEGED_SNAPSHOT_MAX_AGE:-${DEFAULT_MAX_AGE}}"
if ! [[ "${MAX_AGE}" =~ ^[0-9]+$ ]] || (( MAX_AGE <= 0 )); then
  MAX_AGE="${DEFAULT_MAX_AGE}"
fi

declare -a ISSUES=()
declare -a RECOMMENDATIONS=()
declare -a NOTES=()

SYSTEMD_READY=0
SNAPSHOT_STATUS="unknown"
SNAPSHOT_REASON=""
SNAPSHOT_VERSION=""
SNAPSHOT_AGE=""
SNAPSHOT_WRITER=""

SERVICE_LOAD_STATE=""
SERVICE_UNIT_FILE_STATE=""
SERVICE_ACTIVE_STATE=""
SERVICE_SUB_STATE=""
SERVICE_RESULT=""
SERVICE_FRAGMENT_PATH=""
SERVICE_OUTPUT_PATH=""
SERVICE_SCRIPT_PATH=""

TIMER_LOAD_STATE=""
TIMER_UNIT_FILE_STATE=""
TIMER_ACTIVE_STATE=""
TIMER_SUB_STATE=""
TIMER_RESULT=""
TIMER_SCHEDULE=""

JOURNAL_EXCERPT=""

usage() {
  printf 'Usage: %s [--snapshot PATH]\n' "${0##*/}"
  printf '\n'
  printf 'Debug why monitor-tui is reporting a missing or unhealthy privileged snapshot.\n'
  printf 'It checks the snapshot file, service/timer state, unit ExecStart, and recent logs.\n'
}

have_command() {
  command -v "$1" >/dev/null 2>&1
}

add_issue() {
  ISSUES+=("$1")
}

add_recommendation() {
  RECOMMENDATIONS+=("$1")
}

add_note() {
  NOTES+=("$1")
}

print_section() {
  printf '\n== %s ==\n' "$1"
}

print_unique_list() {
  local item
  declare -A seen=()
  for item in "$@"; do
    [[ -n "${item}" ]] || continue
    if [[ -n "${seen["${item}"]:-}" ]]; then
      continue
    fi
    seen["${item}"]=1
    printf -- '- %s\n' "${item}"
  done
}

install_hint() {
  if [[ -x "${REPO_ROOT}/scripts/install_monitor_privileged.sh" ]]; then
    printf '%s' "${REPO_ROOT}/scripts/install_monitor_privileged.sh"
    return
  fi
  if [[ -x "${REPO_ROOT}/install_monitor_privileged.sh" ]]; then
    printf '%s' "${REPO_ROOT}/install_monitor_privileged.sh"
    return
  fi
  printf './scripts/install_monitor_privileged.sh'
}

refresh_hint() {
  local output_path="${SERVICE_OUTPUT_PATH:-${SNAPSHOT_PATH}}"
  if have_command monitor-privileged-refresh; then
    printf 'monitor-privileged-refresh'
    return
  fi
  if [[ -x "${REPO_ROOT}/scripts/refresh_monitor_privileged.sh" ]]; then
    printf '%s' "${REPO_ROOT}/scripts/refresh_monitor_privileged.sh"
    return
  fi
  if [[ -x "${REPO_ROOT}/refresh_monitor_privileged.sh" ]]; then
    printf '%s' "${REPO_ROOT}/refresh_monitor_privileged.sh"
    return
  fi
  printf 'sudo monitor-privileged-snapshot --output %s' "${output_path}"
}

journal_hint() {
  printf 'sudo journalctl -u %s -n 50 --no-pager' "${SERVICE_NAME}"
}

enable_timer_hint() {
  printf 'sudo systemctl enable --now %s' "${TIMER_NAME}"
}

unit_property() {
  local unit_name="$1"
  local property_name="$2"
  local line

  if ! line="$(systemctl show "${unit_name}" --property="${property_name}" 2>/dev/null)"; then
    return 1
  fi
  printf '%s' "${line#*=}"
}

parse_service_unit() {
  local unit_text
  local execstart_line
  local previous=""
  local token

  if ! unit_text="$(systemctl cat "${SERVICE_NAME}" 2>/dev/null)"; then
    return
  fi

  execstart_line="$(printf '%s\n' "${unit_text}" | sed -n 's/^ExecStart=//p' | head -n 1)"
  [[ -n "${execstart_line}" ]] || return

  for token in ${execstart_line}; do
    if [[ "${previous}" == "--output" ]]; then
      SERVICE_OUTPUT_PATH="${token}"
    fi
    case "${token}" in
      */monitor_privileged_snapshot.py)
        SERVICE_SCRIPT_PATH="${token}"
        ;;
    esac
    previous="${token}"
  done
}

check_snapshot_file() {
  local stat_output
  local report

  print_section "Snapshot File"
  printf 'Path: %s (%s)\n' "${SNAPSHOT_PATH}" "${SNAPSHOT_PATH_SOURCE}"

  if [[ ! -e "${SNAPSHOT_PATH}" ]]; then
    SNAPSHOT_STATUS="missing"
    printf 'Status: missing\n'
    add_issue "snapshot file is missing at ${SNAPSHOT_PATH}"
    add_recommendation "Write a fresh snapshot with $(refresh_hint)."
    return
  fi

  if stat_output="$(stat -Lc '%a %U:%G %s bytes' -- "${SNAPSHOT_PATH}" 2>/dev/null)"; then
    printf 'File: %s\n' "${stat_output}"
  fi

  if [[ ! -r "${SNAPSHOT_PATH}" ]]; then
    SNAPSHOT_STATUS="unreadable"
    printf 'Status: unreadable by %s\n' "$(id -un)"
    add_issue "snapshot exists but $(id -un) cannot read ${SNAPSHOT_PATH}"
    add_recommendation "Rewrite the snapshot as root with $(refresh_hint); the writer recreates it with mode 0644."
    return
  fi

  if ! have_command python3; then
    SNAPSHOT_STATUS="unknown"
    printf 'Status: could not inspect JSON because python3 is missing\n'
    add_issue "python3 is not installed, so the snapshot contents could not be validated"
    add_recommendation "Install python3, then rerun this debugger."
    return
  fi

  report="$(
    SNAPSHOT_PATH="${SNAPSHOT_PATH}" \
    EXPECTED_VERSION="${EXPECTED_VERSION}" \
    MAX_AGE="${MAX_AGE}" \
    python3 - <<'PY'
import json
import os
import time
from pathlib import Path

path = Path(os.environ["SNAPSHOT_PATH"])
expected = int(os.environ["EXPECTED_VERSION"])
max_age = int(os.environ["MAX_AGE"])

try:
    raw = path.read_text(encoding="utf-8")
except PermissionError as exc:
    print("status=unreadable")
    print(f"reason={exc}")
    raise SystemExit(0)
except OSError as exc:
    print("status=unreadable")
    print(f"reason={exc}")
    raise SystemExit(0)

try:
    data = json.loads(raw)
except json.JSONDecodeError as exc:
    print("status=invalid")
    print(f"reason=invalid JSON: {exc.msg}")
    raise SystemExit(0)

if not isinstance(data, dict):
    print("status=invalid")
    print("reason=snapshot root is not a JSON object")
    raise SystemExit(0)

version = data.get("snapshot_version")
writer = data.get("snapshot_writer")
generated = data.get("generated_at")

if isinstance(version, int):
    print(f"version={version}")
if isinstance(writer, str) and writer:
    print(f"writer={writer}")

if isinstance(generated, (int, float)):
    age = max(int(time.time() - float(generated)), 0)
    print(f"age={age}")
else:
    age = None

if not isinstance(version, int):
    print("status=version_drift")
    print(f"reason=snapshot schema missing, expected v{expected}")
elif version != expected:
    print("status=version_drift")
    print(f"reason=snapshot schema v{version}, expected v{expected}")
elif not isinstance(generated, (int, float)):
    print("status=invalid")
    print("reason=generated_at missing from snapshot")
elif age is not None and age > max_age:
    print("status=stale")
    print(f"reason=snapshot older than {max_age} seconds")
else:
    print("status=healthy")
PY
  )"

  while IFS='=' read -r key value; do
    case "${key}" in
      status)
        SNAPSHOT_STATUS="${value}"
        ;;
      reason)
        SNAPSHOT_REASON="${value}"
        ;;
      version)
        SNAPSHOT_VERSION="${value}"
        ;;
      age)
        SNAPSHOT_AGE="${value}"
        ;;
      writer)
        SNAPSHOT_WRITER="${value}"
        ;;
    esac
  done <<< "${report}"

  printf 'Status: %s\n' "${SNAPSHOT_STATUS}"
  if [[ -n "${SNAPSHOT_VERSION}" ]]; then
    printf 'Schema: v%s (expected v%s)\n' "${SNAPSHOT_VERSION}" "${EXPECTED_VERSION}"
  else
    printf 'Schema: missing (expected v%s)\n' "${EXPECTED_VERSION}"
  fi
  if [[ -n "${SNAPSHOT_AGE}" ]]; then
    printf 'Age: %ss (max %ss)\n' "${SNAPSHOT_AGE}" "${MAX_AGE}"
  fi
  if [[ -n "${SNAPSHOT_WRITER}" ]]; then
    printf 'Writer: %s\n' "${SNAPSHOT_WRITER}"
  fi
  if [[ -n "${SNAPSHOT_REASON}" ]]; then
    printf 'Reason: %s\n' "${SNAPSHOT_REASON}"
  fi

  case "${SNAPSHOT_STATUS}" in
    healthy)
      ;;
    stale)
      add_issue "snapshot is stale at ${SNAPSHOT_PATH}"
      add_recommendation "Refresh it with $(refresh_hint), then confirm ${TIMER_NAME} is enabled and active."
      ;;
    invalid)
      add_issue "snapshot JSON at ${SNAPSHOT_PATH} is invalid"
      add_recommendation "Rewrite it with $(refresh_hint), then inspect logs with $(journal_hint) if the file becomes invalid again."
      ;;
    version_drift)
      add_issue "snapshot schema does not match the TUI expectation"
      add_recommendation "Refresh from the current repo copy with $(refresh_hint), or reinstall with $(install_hint) if the installed helper is older."
      ;;
    unreadable)
      add_issue "snapshot exists but could not be read"
      add_recommendation "Rewrite the snapshot as root with $(refresh_hint); the writer recreates it with mode 0644."
      ;;
    *)
      add_issue "snapshot health is ${SNAPSHOT_STATUS}"
      add_recommendation "Inspect the snapshot file and rewrite it with $(refresh_hint)."
      ;;
  esac
}

check_systemd_units() {
  print_section "Systemd Units"

  if ! have_command systemctl; then
    printf 'systemctl: not installed\n'
    add_issue "systemctl is not available on this machine"
    add_recommendation "Write the snapshot manually with sudo monitor-privileged-snapshot --output ${SNAPSHOT_PATH}, or run the helper on the host system."
    return
  fi

  if ! systemctl list-unit-files --no-pager >/dev/null 2>&1; then
    printf 'systemctl: installed but the system bus is not reachable here\n'
    add_issue "systemctl is present but this environment cannot inspect systemd"
    add_recommendation "Run this debugger on the actual host where monitor-tui is running."
    return
  fi

  SYSTEMD_READY=1

  SERVICE_LOAD_STATE="$(unit_property "${SERVICE_NAME}" "LoadState" || true)"
  SERVICE_UNIT_FILE_STATE="$(unit_property "${SERVICE_NAME}" "UnitFileState" || true)"
  SERVICE_ACTIVE_STATE="$(unit_property "${SERVICE_NAME}" "ActiveState" || true)"
  SERVICE_SUB_STATE="$(unit_property "${SERVICE_NAME}" "SubState" || true)"
  SERVICE_RESULT="$(unit_property "${SERVICE_NAME}" "Result" || true)"
  SERVICE_FRAGMENT_PATH="$(unit_property "${SERVICE_NAME}" "FragmentPath" || true)"

  TIMER_LOAD_STATE="$(unit_property "${TIMER_NAME}" "LoadState" || true)"
  TIMER_UNIT_FILE_STATE="$(unit_property "${TIMER_NAME}" "UnitFileState" || true)"
  TIMER_ACTIVE_STATE="$(unit_property "${TIMER_NAME}" "ActiveState" || true)"
  TIMER_SUB_STATE="$(unit_property "${TIMER_NAME}" "SubState" || true)"
  TIMER_RESULT="$(unit_property "${TIMER_NAME}" "Result" || true)"
  TIMER_SCHEDULE="$(systemctl list-timers "${TIMER_NAME}" --all --no-legend --no-pager 2>/dev/null | head -n 1 || true)"

  parse_service_unit

  printf 'Service: load=%s | enabled=%s | active=%s/%s | result=%s\n' \
    "${SERVICE_LOAD_STATE:-unknown}" \
    "${SERVICE_UNIT_FILE_STATE:-unknown}" \
    "${SERVICE_ACTIVE_STATE:-unknown}" \
    "${SERVICE_SUB_STATE:-unknown}" \
    "${SERVICE_RESULT:-unknown}"
  if [[ -n "${SERVICE_FRAGMENT_PATH}" ]]; then
    printf 'Service unit: %s\n' "${SERVICE_FRAGMENT_PATH}"
  fi
  if [[ -n "${SERVICE_SCRIPT_PATH}" ]]; then
    printf 'Service script: %s\n' "${SERVICE_SCRIPT_PATH}"
  fi
  if [[ -n "${SERVICE_OUTPUT_PATH}" ]]; then
    printf 'Service output: %s\n' "${SERVICE_OUTPUT_PATH}"
  fi

  printf 'Timer: load=%s | enabled=%s | active=%s/%s | result=%s\n' \
    "${TIMER_LOAD_STATE:-unknown}" \
    "${TIMER_UNIT_FILE_STATE:-unknown}" \
    "${TIMER_ACTIVE_STATE:-unknown}" \
    "${TIMER_SUB_STATE:-unknown}" \
    "${TIMER_RESULT:-unknown}"
  if [[ -n "${TIMER_SCHEDULE}" ]]; then
    printf 'Timer schedule: %s\n' "${TIMER_SCHEDULE}"
  fi

  if [[ "${SERVICE_LOAD_STATE}" != "loaded" ]]; then
    add_issue "${SERVICE_NAME} is not installed"
    add_recommendation "Install the helper with $(install_hint)."
  fi

  if [[ "${TIMER_LOAD_STATE}" != "loaded" ]]; then
    add_issue "${TIMER_NAME} is not installed"
    add_recommendation "Install the helper with $(install_hint)."
  fi

  if [[ "${TIMER_LOAD_STATE}" == "loaded" && "${TIMER_UNIT_FILE_STATE}" != "enabled" ]]; then
    add_issue "${TIMER_NAME} is not enabled"
    add_recommendation "Enable the timer with $(enable_timer_hint)."
  fi

  if [[ "${TIMER_LOAD_STATE}" == "loaded" && "${TIMER_ACTIVE_STATE}" != "active" ]]; then
    add_issue "${TIMER_NAME} is not active"
    add_recommendation "Start the timer with $(enable_timer_hint)."
  fi

  if [[ "${SERVICE_ACTIVE_STATE}" == "failed" || "${SERVICE_RESULT}" == "failed" || "${SERVICE_RESULT}" == "exit-code" ]]; then
    add_issue "${SERVICE_NAME} last run failed"
    add_recommendation "Inspect the service logs with $(journal_hint)."
  fi

  if [[ "${SERVICE_ACTIVE_STATE}" == "inactive" && "${SERVICE_RESULT}" == "success" ]]; then
    add_note "${SERVICE_NAME} is a oneshot unit, so inactive (${SERVICE_SUB_STATE}) after a successful run is normal."
  fi

  if [[ -n "${SERVICE_SCRIPT_PATH}" && ! -f "${SERVICE_SCRIPT_PATH}" ]]; then
    add_issue "${SERVICE_NAME} points to a missing script at ${SERVICE_SCRIPT_PATH}"
    add_recommendation "Reinstall the helper with $(install_hint), or update ExecStart in ${SERVICE_FRAGMENT_PATH:-the service unit}."
  fi
}

check_installed_helper() {
  print_section "Installed Helper"

  if [[ -f "${INSTALLED_SCRIPT}" ]]; then
    printf 'Installed script: %s\n' "${INSTALLED_SCRIPT}"
    if have_command python3 && python3 "${INSTALLED_SCRIPT}" --help >/dev/null 2>&1; then
      printf 'Smoke test: ok\n'
    else
      printf 'Smoke test: failed\n'
      add_issue "${INSTALLED_SCRIPT} does not pass a simple python3 --help smoke test"
      add_recommendation "Reinstall the helper with $(install_hint)."
    fi
  else
    printf 'Installed script: missing (%s)\n' "${INSTALLED_SCRIPT}"
    if [[ "${SERVICE_LOAD_STATE}" == "loaded" || "${TIMER_LOAD_STATE}" == "loaded" ]]; then
      add_issue "installed helper script is missing at ${INSTALLED_SCRIPT}"
      add_recommendation "Reinstall the helper with $(install_hint)."
    fi
  fi

  if have_command monitor-privileged-refresh; then
    printf 'Refresh helper: %s\n' "$(command -v monitor-privileged-refresh)"
  elif [[ -x "${REPO_ROOT}/scripts/refresh_monitor_privileged.sh" ]]; then
    printf 'Refresh helper: %s\n' "${REPO_ROOT}/scripts/refresh_monitor_privileged.sh"
  else
    printf 'Refresh helper: not found in PATH\n'
  fi
}

check_path_mismatch() {
  if [[ -z "${SERVICE_OUTPUT_PATH}" || "${SERVICE_OUTPUT_PATH}" == "${SNAPSHOT_PATH}" ]]; then
    return
  fi

  add_note "The service writes ${SERVICE_OUTPUT_PATH}, but this debug run is checking ${SNAPSHOT_PATH}."
  if [[ "${SNAPSHOT_STATUS}" != "healthy" ]]; then
    add_issue "the TUI snapshot path and the service output path do not match"
    add_recommendation "Unset MONITOR_PRIVILEGED_SNAPSHOT or point it at ${SERVICE_OUTPUT_PATH}, or update ${SERVICE_NAME} to write ${SNAPSHOT_PATH}."
  fi
}

check_recent_logs() {
  local output

  print_section "Recent Service Logs"

  if (( SYSTEMD_READY == 0 )); then
    printf 'Skipped because systemd is not inspectable here.\n'
    return
  fi

  if ! have_command journalctl; then
    printf 'journalctl: not installed\n'
    return
  fi

  if output="$(journalctl -u "${SERVICE_NAME}" -n 10 --no-pager 2>/dev/null)"; then
    :
  elif have_command sudo && sudo -n true >/dev/null 2>&1 && output="$(sudo -n journalctl -u "${SERVICE_NAME}" -n 10 --no-pager 2>/dev/null)"; then
    :
  else
    printf 'Could not read service logs without more privileges.\n'
    printf 'Try: %s\n' "$(journal_hint)"
    return
  fi

  JOURNAL_EXCERPT="${output}"
  if [[ -z "${JOURNAL_EXCERPT}" ]]; then
    printf 'No recent logs found for %s\n' "${SERVICE_NAME}"
    return
  fi

  printf '%s\n' "${JOURNAL_EXCERPT}" | tail -n 8

  case "${JOURNAL_EXCERPT}" in
    *ModuleNotFoundError*|*"No module named "*)
      add_issue "recent service logs show missing Python modules"
      add_recommendation "Reinstall the helper with $(install_hint) so the Python package is copied again."
      ;;
  esac

  case "${JOURNAL_EXCERPT}" in
    *"No such file or directory"*)
      add_issue "recent service logs mention a missing file"
      add_recommendation "Reinstall the helper with $(install_hint), or update ExecStart in ${SERVICE_FRAGMENT_PATH:-the service unit}."
      ;;
  esac

  case "${JOURNAL_EXCERPT}" in
    *"Permission denied"*)
      add_issue "recent service logs show a permission error"
      add_recommendation "Check ownership and mode on $(dirname -- "${SERVICE_OUTPUT_PATH:-${SNAPSHOT_PATH}}"), then rerun $(refresh_hint) as root."
      ;;
  esac

  case "${JOURNAL_EXCERPT}" in
    *"Read-only file system"*)
      add_issue "recent service logs show the snapshot path is on a read-only filesystem"
      add_recommendation "Fix the underlying filesystem state or pick a writable output path before rerunning $(refresh_hint)."
      ;;
  esac
}

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      --snapshot)
        if (( $# < 2 )); then
          printf '--snapshot requires a path\n' >&2
          exit 2
        fi
        SNAPSHOT_PATH="$2"
        SNAPSHOT_PATH_SOURCE="--snapshot"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        printf 'Unknown argument: %s\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done
}

print_summary() {
  print_section "Summary"

  if (( ${#ISSUES[@]} == 0 )); then
    printf 'No obvious problems were detected.\n'
  else
    printf 'Findings:\n'
    print_unique_list "${ISSUES[@]}"
  fi

  if (( ${#RECOMMENDATIONS[@]} > 0 )); then
    printf '\nRecommendations:\n'
    print_unique_list "${RECOMMENDATIONS[@]}"
  fi

  if (( ${#NOTES[@]} > 0 )); then
    printf '\nNotes:\n'
    print_unique_list "${NOTES[@]}"
  fi
}

main() {
  parse_args "$@"

  print_section "Context"
  printf 'User: %s\n' "$(id -un)"
  printf 'Snapshot max age: %ss\n' "${MAX_AGE}"

  check_systemd_units
  check_snapshot_file
  check_installed_helper
  check_path_mismatch
  check_recent_logs
  print_summary

  if (( ${#ISSUES[@]} > 0 )); then
    exit 1
  fi
}

main "$@"
