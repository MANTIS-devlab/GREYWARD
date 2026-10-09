#!/bin/bash
# Fixed root-owned ancestry/mount probe; no package enrollment or launch API.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
parent=/var/lib/greyward-development/application-security
fixture=$parent/installed-object-probe
executable=/usr/local/libexec/greyward-application-security-installed-test
test "$(sudo -n stat -c '%u %a %h' "$executable")" = '0 755 1'
sudo -n test ! -L "$executable"
test "$(sudo -n stat -c '%u %a' "$parent")" = '0 700'
for path in "$fixture" "$fixture/usr" "$fixture/usr/bin" "$fixture/usr/alias" "$fixture/usr/bin/sample"; do
    sudo -n test ! -L "$path"
    if sudo -n test -e "$path"; then test "$(sudo -n stat -c %u "$path")" = 0; fi
done
sudo -n install -d -m0700 "$fixture"
sudo -n install -d -m0755 "$fixture/usr" "$fixture/usr/bin" "$fixture/usr/alias"
sudo -n install -m0755 /usr/bin/cat "$fixture/usr/bin/sample"
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-application-security-installed-probe.service >/dev/null 2>&1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    test "$(getenforce)" = Enforcing || result=1
    exit "$result"
}
trap cleanup EXIT
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-installed-probe \
    -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=16 \
    -p NoNewPrivileges=yes -p PrivateMounts=yes -p ProtectSystem=strict \
    -p "ReadWritePaths=$parent" \
    "$executable" --ignored installed_content::tests::root_installed_ --nocapture
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-installed-probe \
    -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=16 \
    -p NoNewPrivileges=yes -p PrivateMounts=yes -p ProtectSystem=strict \
    -p "BindReadOnlyPaths=$fixture/usr/bin:$fixture/usr/alias" \
    "$executable" --ignored --exact installed_content::tests::root_bind_alias_cannot_gain_installed_membership --nocapture
echo INSTALLED_ANCESTRY_REPLACEMENT_AND_BIND_REFUSAL_PASS
