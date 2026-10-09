#!/bin/bash
# Labwc startup hook for the fixed, isolated development probe account.
set -euo pipefail
test "$(id -un)" = greyward-guard-probe
test "$HOME" = /home/greyward-guard-probe
test "${WLR_BACKENDS:-}" = headless
test "$(getenforce)" = Enforcing
export XDG_RUNTIME_DIR=/run/user/"$(id -u)"
export DBUS_SESSION_BUS_ADDRESS=unix:path="$XDG_RUNTIME_DIR/bus"
# Exercise the account's real user bus and graphical target so portal activation
# uses the same boundary as the shell. Only this separate UID's units are used.
systemctl --user set-property --runtime greyward-dms.service CPUQuota=25% MemoryMax=512M
trap 'uwsm stop' EXIT
uwsm finalize WAYLAND_DISPLAY XDG_CURRENT_DESKTOP QT_QUICK_BACKEND
python3 /usr/local/libexec/greyward-application-security-portal-probe.py > "$HOME/portal-probe-result.json"
ready=0
for attempt in {1..12}; do
    if timeout 15s /usr/local/libexec/greyward-dms-runtime-check > "$HOME/session-shell-result.json"; then
        ready=1
        break
    fi
    sleep 1
done
test "$ready" = 1
sleep 5
