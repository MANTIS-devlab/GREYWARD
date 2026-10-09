#!/bin/bash
# Fixed runtime-core integration probe; no generic application launch API.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
stage=/var/tmp/greyward-application-security-probe
state=/var/lib/greyward-development/application-security
fixture=$state/native-private
root=$fixture/root
source=/var/tmp/greyward-application-security-build/security-center
build_log=$(mktemp /var/tmp/greyward-application-security-build/native-artifact.XXXXXXXX)
if pgrep -u 1002 >/dev/null; then rm -f -- "$build_log"; echo 'Probe account is busy' >&2; exit 1; fi
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
test "$(systemctl --user is-active greyward-dms.service)" = active
guard_setup=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    local failed=0
    sudo -n systemctl stop greyward-application-security-native-probe.service >/dev/null 2>&1
    rm -f -- "$build_log" || failed=1
    if $guard_setup; then sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || failed=1; fi
    if sudo -n test -d "$fixture"; then sudo -n restorecon -R "$fixture" || failed=1; fi
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || failed=1
    test "$(getenforce)" = Enforcing || failed=1
    if test "$failed" = 1; then echo 'Native probe cleanup requires recovery' >&2; result=1; fi
    exit "$result"
}
trap cleanup EXIT

systemd-run --user --quiet --wait --pipe --collect --unit=greyward-appsec-native-build \
    -p RuntimeMaxSec=180 -p MemoryMax=1G -p CPUQuota=100% -p "WorkingDirectory=$source" \
    -E PATH=/usr/bin:/bin -E CARGO=/usr/bin/cargo -E RUSTC=/usr/bin/rustc \
    -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
    /usr/bin/cargo build -p greyward-application-security --example native-restriction-check \
        --message-format=json --offline --locked > "$build_log"
binary=$(/usr/bin/python3 -I - "$source" "$build_log" <<'PY'
import json, pathlib, sys
base = pathlib.Path(sys.argv[1]) / 'target/debug/examples'
matches = []
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    item = json.loads(line)
    if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'native-restriction-check' and item.get('executable'):
        candidate = pathlib.Path(item['executable'])
        if candidate.parent != base or candidate.name != 'native-restriction-check':
            raise SystemExit('Unexpected current worker test artifact')
        matches.append(str(candidate))
if len(matches) != 1:
    raise SystemExit('Exactly one matching runtime-core test artifact required')
print(matches[0])
PY
)
sha256sum -- "$binary"
guard_setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
test "$(id -u greyward-guard-probe)" = 1002
sudo -n test ! -L "$fixture"
if sudo -n test -e "$fixture"; then
    test "$(sudo -n stat -c '%u %a' "$fixture")" = '0 700'
fi
sudo -n install -d -m0700 "$fixture"
for directory in "$root" "$root/usr" "$root/proc" "$root/dev" "$root/etc" "$root/work" "$root/run" "$root/tmp"; do
    sudo -n test ! -L "$directory"
    if sudo -n test -e "$directory"; then test "$(sudo -n stat -c %u "$directory")" = 0; fi
    sudo -n install -d -m0755 "$directory"
done
for link in lib lib64; do
    if sudo -n test -e "$root/$link" || sudo -n test -L "$root/$link"; then
        test "$(sudo -n readlink "$root/$link")" = "usr/$link"
    else
        sudo -n ln -s "usr/$link" "$root/$link"
    fi
done
for file in "$fixture/selected-document" "$fixture/ordinary-outside"; do
    sudo -n test ! -L "$file"
    if sudo -n test -e "$file"; then test "$(sudo -n stat -c '%u %h' "$file")" = '0 1'; fi
done
printf 'synthetic selected document\n' | sudo -n tee "$fixture/selected-document" >/dev/null
printf 'synthetic ordinary file\n' | sudo -n tee "$fixture/ordinary-outside" >/dev/null
sudo -n chmod 0444 "$fixture/selected-document" "$fixture/ordinary-outside"
sudo -n chcon -t user_home_t "$fixture/selected-document" "$fixture/ordinary-outside"
sudo -n test ! -L "$fixture/work"
sudo -n install -d -m0700 -o greyward-guard-probe -g greyward-guard-probe "$fixture/work"
sudo -n chcon -R -h -t user_home_t "$fixture/work"
sudo -n install -m0755 "$binary" \
    /usr/local/libexec/greyward-application-security-native-probe
sudo -n restorecon /usr/local/libexec/greyward-application-security-native-probe
host_namespaces=()
for namespace in mnt pid net user; do
    namespace_id=$(sudo -n readlink "/proc/1/ns/$namespace")
    [[ "$namespace_id" =~ ^${namespace}:\[[0-9]+\]$ ]]
    host_namespaces+=("GREYWARD_HOST_NS_${namespace^^}=$namespace_id")
done
sudo -n rm -f -- "$fixture/work/application-started"
run_worker() {
    local bind_inputs="/usr $fixture/ordinary-outside:/ordinary-outside /home/greyward-guard-probe/protected/credential:/protected-test"
    if test "$1" = complete; then bind_inputs+=" $fixture/selected-document:/selected-document"; fi
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-native-probe \
    -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=32 \
    -p User=greyward-guard-probe -p Group=greyward-guard-probe \
    -p SELinuxContext=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0 \
    -p "RootDirectory=$root" -p PrivateUsers=yes -p PrivatePIDs=yes \
    -p PrivateNetwork=yes -p PrivateMounts=yes -p PrivateDevices=yes \
    -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p ProtectSystem=strict \
    -p "Environment=${host_namespaces[*]}" \
    -p "BindReadOnlyPaths=$bind_inputs" \
    -p "BindPaths=$fixture/work:/work" \
    /usr/local/libexec/greyward-application-security-native-probe --fixed-probe
}
# A missing required rule input must refuse execution before any child launch.
if run_worker missing-input; then
    echo 'Missing required input incorrectly permitted a launch' >&2
    exit 1
fi
sudo -n test ! -e "$fixture/work/application-started"
run_worker complete
sudo -n test -f "$fixture/work/application-started"
