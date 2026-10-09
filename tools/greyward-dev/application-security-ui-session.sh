#!/bin/bash
# Called only by the fixed private UID-1002 system unit, never the active session.
set -euo pipefail
trap 'printf "Private UI fixture stopped at line %s\n" "$LINENO" >&2' ERR
test "$(id -u)" = 1002
actual_domain=$(cut -d: -f3 /proc/self/attr/current | tr -d '\000')
test "$actual_domain" = "$GREYWARD_UI_EXPECTED_DOMAIN"
state=/run/greyward-application-security-ui
export XDG_RUNTIME_DIR=$state/runtime
export XDG_CONFIG_HOME=$state/config
export XDG_STATE_HOME=$state/state
export XDG_CACHE_HOME=$state/cache
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
export WLR_BACKENDS=headless WLR_HEADLESS_OUTPUTS=1 WLR_RENDERER=pixman
export LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=wayland
# The fixed root unit owns lifetime/whole-cgroup cleanup. Do not kill numerical
# helper PIDs that might have exited/reused before cleanup.
/usr/bin/dbus-daemon --nofork --config-file="$state/session-bus.conf" > "$state/bus.log" 2>&1 &
for attempt in {1..40}; do test -S "$XDG_RUNTIME_DIR/bus" && break; sleep 0.1; done
test -S "$XDG_RUNTIME_DIR/bus"
# Source application reads and presentation-only private history; no policy
# mutation or installed provider activation.
export PYTHONPATH=/usr/local/lib/greyward-application-security-ui-context-source
/usr/local/libexec/greyward-application-security-ui-context-python -B /usr/local/libexec/greyward-application-security-ui-context.py > "$state/context.log" 2>&1 &
for attempt in {1..40}; do
    if /usr/bin/gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner systems.mantis.greyward.SecurityContext1 2>/dev/null | /usr/bin/rg -q true; then break; fi
    sleep 0.1
done
/usr/bin/gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.NameHasOwner systems.mantis.greyward.SecurityContext1 | /usr/bin/rg -q true
/usr/bin/labwc -d -C "$state/config/labwc" > "$state/compositor.log" 2>&1 &
for attempt in {1..40}; do test -S "$XDG_RUNTIME_DIR/wayland-0" && break; sleep 0.1; done
test -S "$XDG_RUNTIME_DIR/wayland-0"
export WAYLAND_DISPLAY=wayland-0
/usr/local/libexec/greyward-application-security-ui-driver --native-driver /usr/bin/WebKitWebDriver --port 49940 --native-port 49941 > "$state/driver.log" 2>&1 &
/usr/bin/node /usr/local/libexec/greyward-application-security-ui-probe.mjs > "$state/probe.log" 2>&1
