#!/bin/bash
# Actual system-bus source test with synthetic in-memory records only.
# No package installation, production database, enrollment or desktop control.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
test "$(id -G greyward-guard-probe)" = 1002
if pgrep -u 1002 >/dev/null; then echo 'Probe account is busy' >&2; exit 1; fi
source=/var/tmp/greyward-application-security-build/security-center
policy=/etc/dbus-1/system.d/greyward-application-security-transport-probe.conf
target=/usr/local/libexec/greyward-application-security-broker-test
test "$(busctl --timeout=6 call org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus NameHasOwner s systems.mantis.greyward.ApplicationSecurity1)" = 'b false'
sudo -n test ! -e "$policy"
sudo -n test ! -L "$policy"
sudo -n test ! -e /var/lib/greyward/application-security/policy.sqlite3
sudo -n test "$(sudo -n cat /var/lib/greyward-development/application-security/account.uid)" = 1002
test "$(getent passwd greyward-guard-probe | cut -d: -f6)" = /home/greyward-guard-probe
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
installed=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-application-security-read-transport.service >/dev/null 2>&1
    if $installed; then
        sudo -n rm -f -- "$policy" || result=1
        sudo -n busctl --timeout=6 call org.freedesktop.DBus /org/freedesktop/DBus \
            org.freedesktop.DBus ReloadConfig >/dev/null || result=1
    fi
    test "$(getenforce)" = Enforcing || result=1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    sudo -n test ! -e /var/lib/greyward/application-security/policy.sqlite3 || result=1
    exit "$result"
}
trap cleanup EXIT
# Cargo identifies its exact current artifact; no wildcard/stale target choice.
build_log=$(mktemp /var/tmp/greyward-application-security-build/transport-build.XXXXXXXX)
systemd-run --user --quiet --wait --pipe --collect --unit=greyward-appsec-transport-build \
    -p RuntimeMaxSec=180 -p MemoryMax=1G -p CPUQuota=100% -p "WorkingDirectory=$source" \
    -E PATH=/usr/bin:/bin -E CARGO=/usr/bin/cargo -E RUSTC=/usr/bin/rustc \
    -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
    /usr/bin/cargo test -p greyward-application-security --test system_bus_broker \
        --no-run --message-format=json --offline --locked > "$build_log"
binary=$(/usr/bin/python3 -I - "$source" "$build_log" <<'PY'
import json, pathlib, sys
base = pathlib.Path(sys.argv[1]) / 'target/debug/deps'
results = []
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    value = json.loads(line)
    if value.get('reason') == 'compiler-artifact' and value.get('target', {}).get('name') == 'system_bus_broker' and value.get('executable'):
        executable = pathlib.Path(value['executable'])
        if executable.parent != base or not executable.name.startswith('system_bus_broker-'):
            raise SystemExit('Unexpected compiled test path')
        results.append(str(executable))
if len(results) != 1:
    raise SystemExit('Exactly one matching source test artifact is required')
print(results[0])
PY
)
test -f "$binary" && test ! -L "$binary"
sha256sum "$binary"
sudo -n test ! -L "$target"
sudo -n install -m0755 "$binary" "$target"
sudo -n restorecon "$target"
installed=true
sudo -n install -m0644 "$source/packaging/application-security/systems.mantis.greyward.ApplicationSecurity1.conf" "$policy"
sudo -n busctl --timeout=6 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-read-transport \
    -p RuntimeMaxSec=30 -p TimeoutStopSec=3 -p MemoryMax=128M -p CPUQuota=100% \
    -p SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0 \
    "$target" --ignored --exact root_read_transport_enforces_scope_without_enforcement_claims --nocapture
printf 'REAL_SOURCE_READ_TRANSPORT_PASS\n'
