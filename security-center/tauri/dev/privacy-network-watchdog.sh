#!/usr/bin/env bash
set -euo pipefail

# Development-only recovery guard for UI tests that intentionally mutate the
# active NetworkManager/firewalld privacy profile. It never belongs in the
# installed product or production image.
state_dir="${XDG_RUNTIME_DIR:-/tmp}/greyward-security-center"
marker="$state_dir/privacy-network-watchdog.active"
pid_file="$state_dir/privacy-network-watchdog.pid"
log_file="$state_dir/privacy-network-watchdog.log"
timeout_seconds="${GREYWARD_PRIVACY_WATCHDOG_TIMEOUT_SECONDS:-120}"

mkdir -p "$state_dir"
chmod 700 "$state_dir"

case "${1:-}" in
  arm)
    baseline="${2:-STANDARD}"
    case "$baseline" in
      STANDARD|PRIVATE|TRAVEL) ;;
      *) echo "unsupported baseline profile" >&2; exit 64 ;;
    esac
    if [[ -f "$pid_file" ]]; then
      kill "$(cat "$pid_file")" 2>/dev/null || true
    fi
    printf '%s\n' "$baseline" > "$marker"
    nohup bash -c '
      set -euo pipefail
      sleep "$1"
      marker="$2"
      baseline="$3"
      if [[ -f "$marker" ]]; then
        /usr/libexec/greyward-security-profile --set "$baseline" >"${marker}.log" 2>&1 || true
        rm -f "$marker"
      fi
    ' _ "$timeout_seconds" "$marker" "$baseline" >"$log_file" 2>&1 < /dev/null &
    printf '%s\n' "$!" > "$pid_file"
    ;;
  cancel)
    rm -f "$marker"
    if [[ -f "$pid_file" ]]; then
      kill "$(cat "$pid_file")" 2>/dev/null || true
      rm -f "$pid_file"
    fi
    ;;
  status)
    if [[ -f "$marker" ]]; then
      printf 'ARMED %s\n' "$(cat "$marker")"
    else
      printf 'DISARMED\n'
    fi
    ;;
  *)
    echo "usage: privacy-network-watchdog.sh arm STANDARD|PRIVATE|TRAVEL|cancel|status" >&2
    exit 64
    ;;
esac
