#!/bin/bash
# Fixed private compositor for the security-context protocol probe only.
set -euo pipefail
test "$(id -u)" = 1002
test "$(getenforce)" = Enforcing
base=/run/greyward-application-security-wayland
export HOME=$base/home XDG_RUNTIME_DIR=$base/runtime XDG_CONFIG_HOME=$base/config
export XDG_STATE_HOME=$base/state XDG_CACHE_HOME=$base/cache
export WAYLAND_DISPLAY=wayland-0 WLR_BACKENDS=headless WLR_HEADLESS_OUTPUTS=1 WLR_RENDERER=pixman
unset DISPLAY WAYLAND_SOCKET DBUS_SESSION_BUS_ADDRESS
/usr/bin/labwc -C "$base/config/labwc" > "$base/compositor.log" 2>&1 &
for attempt in {1..40}; do test -S "$XDG_RUNTIME_DIR/wayland-0" && break; sleep 0.1; done
test -S "$XDG_RUNTIME_DIR/wayland-0"
/usr/local/libexec/greyward-application-security-wayland-probe
# The bounded system unit owns the compositor and its whole-cgroup cleanup.
