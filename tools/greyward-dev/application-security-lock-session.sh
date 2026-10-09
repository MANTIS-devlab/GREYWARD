#!/bin/bash
# Fixed UID-1002 private display. Never uses the active user's bus or compositor.
set -euo pipefail
test "$(id -u)" = 1002
test "$(getenforce)" = Enforcing
test "$(cut -d: -f3 /proc/self/attr/current | tr -d '\000')" = greyward_guard_t
base=/run/greyward-application-security-lock
export HOME=$base/home XDG_RUNTIME_DIR=$base/runtime
export XDG_CONFIG_HOME=$base/config XDG_STATE_HOME=$base/state XDG_CACHE_HOME=$base/cache
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
export WAYLAND_DISPLAY=wayland-0
# Backend creates its own PID-named socket; coordinator binds its actual peer.
unset DMS_SOCKET
export WLR_BACKENDS=headless WLR_HEADLESS_OUTPUTS=1 WLR_RENDERER=pixman
export QT_QUICK_BACKEND=software LIBGL_ALWAYS_SOFTWARE=1 XDG_CURRENT_DESKTOP=GREYWARD:labwc
export USER=greyward-guard-probe LOGNAME=greyward-guard-probe
unset XDG_SESSION_ID DISPLAY
/usr/bin/dbus-daemon --nofork --config-file="$base/session-bus.conf" > "$base/bus.log" 2>&1 &
for attempt in {1..40}; do test -S "$XDG_RUNTIME_DIR/bus" && break; sleep 0.1; done
test -S "$XDG_RUNTIME_DIR/bus"
/usr/bin/labwc -C "$base/config/labwc" > "$base/compositor.log" 2>&1 &
compositor=$!
for attempt in {1..40}; do test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" && break; sleep 0.1; done
test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"
/usr/local/bin/greyward-dms run > "$base/shell.log" 2>&1 &
backend=$!
printf '%s %s\n' "$compositor" "$backend" > "$base/processes"
# The bounded system unit owns cleanup of all children. The root coordinator
# terminates it even after failed authentication; no IPC unlock/forceReset.
for attempt in {1..600}; do sleep 0.1; done
exit 1
