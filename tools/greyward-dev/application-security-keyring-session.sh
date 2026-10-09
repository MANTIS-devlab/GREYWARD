#!/bin/bash
# Fixed private Secret Service fixture; never a product launch/policy API.
set -euo pipefail
test "$(id -u)" = 1002
test "$HOME" = /run/greyward-application-security-keyring/home
case "${1:-}" in seed|deny) ;; *) exit 2;; esac
state=/run/greyward-application-security-keyring
export XDG_RUNTIME_DIR=$state/$1-runtime XDG_DATA_HOME=$HOME/.local/share
export XDG_CONFIG_HOME=$HOME/.config XDG_CACHE_HOME=$HOME/.cache
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
unset DISPLAY WAYLAND_DISPLAY SSH_AUTH_SOCK
/usr/bin/dbus-daemon --nofork --config-file="$state/$1-session-bus.conf" > "$state/$1-bus.log" 2>&1 &
for attempt in {1..40}; do test -S "$XDG_RUNTIME_DIR/bus" && break; sleep 0.1; done
test -S "$XDG_RUNTIME_DIR/bus"
# Only this synthetic collection exists in the private HOME. The fixed root
# unit owns all children/lifetime. No numerical PID kill or host PAM change.
printf 'greyward-synthetic-keyring-pass\n' | /usr/bin/gnome-keyring-daemon \
    --foreground --unlock --components=secrets --control-directory="$XDG_RUNTIME_DIR/keyring" &
ready=false
for attempt in {1..40}; do
    if /usr/bin/gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner org.freedesktop.secrets 2>/dev/null | /usr/bin/rg -q true; then
        ready=true; break
    fi
    sleep 0.1
done
if test "$1" = seed; then
    test "$ready" = true
    printf 'greyward-synthetic-keyring-value' | timeout 8s /usr/bin/secret-tool store \
        --label='GREYWARD synthetic deputy fixture' greyward-probe keyring
    test "$(timeout 8s /usr/bin/secret-tool lookup greyward-probe keyring)" = greyward-synthetic-keyring-value
    test -s "$XDG_DATA_HOME/keyrings/login.keyring"
    printf 'SYNTHETIC_SECRET_SERVICE_POSITIVE_CONTROL_PASS\n'
else
    test "$(cut -d: -f3 /proc/self/attr/current | tr -d '\000')" = greyward_guard_t
    # This is an actual deputy probe, not an absent-provider failure test.
    test "$ready" = true
    if test "$ready" = true; then
        /usr/bin/python3 -I - <<'PY'
import dbus
bus = dbus.SessionBus()
daemon = dbus.Interface(bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus'), 'org.freedesktop.DBus')
peer = daemon.GetConnectionCredentials(daemon.GetNameOwner('org.freedesktop.secrets'))
assert int(peer['UnixUserID']) == 1002
context = bytes(peer['LinuxSecurityLabel']).rstrip(b'\0').decode()
assert context.split(':')[2] == 'greyward_guard_gkeyringd_t', context
print('CONFINED_SECRET_SERVICE_IDENTITY_PASS')
PY
    fi
    # The service exists, but loading its protected collection can fail. Never
    # turn that into an empty successful protection/permission projection.
    set +e
    result=$(timeout 8s /usr/bin/secret-tool lookup greyward-probe keyring 2> "$state/lookup.log")
    outcome=$?
    set -e
    test "$outcome" != 0
    test -z "$result"
    if timeout 2s /usr/bin/head -c1 "$XDG_DATA_HOME/keyrings/login.keyring" > /dev/null 2>&1; then
        echo 'Synthetic protected keyring read unexpectedly succeeded' >&2; exit 1
    fi
    printf 'SYNTHETIC_SECRET_SERVICE_NO_DISCLOSURE_PASS available=%s lookup_status=%s\n' "$ready" "$outcome"
fi
