#!/bin/bash
# Fixed root/private-mount metadata probe; no enrollment or resource-policy API.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
fixture=/var/lib/greyward-development/application-security/resource-selection-probe
executable=/usr/local/libexec/greyward-application-security-resource-test
test "$(sudo -n stat -c '%u %a %h' "$executable")" = '0 755 1'
sudo -n test ! -L "$executable"
test "$(sudo -n stat -c '%u %a' /var/lib/greyward-development/application-security)" = '0 700'
for path in "$fixture" "$fixture/selected" "$fixture/alias"; do
    sudo -n test ! -L "$path"
done
sudo -n install -d -m0700 "$fixture" "$fixture/alias"
sudo -n install -d -m0700 -o greyward-guard-probe -g greyward-guard-probe "$fixture/selected"
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-application-security-resource-probe.service >/dev/null 2>&1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    test "$(getenforce)" = Enforcing || result=1
    exit "$result"
}
trap cleanup EXIT
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-resource-probe \
    -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=16 \
    -p NoNewPrivileges=yes -p PrivateMounts=yes -p ProtectSystem=strict \
    -p "BindReadOnlyPaths=$fixture/selected:$fixture/alias" \
    "$executable" --ignored --exact root_bind_alias_cannot_be_selected_as_a_descendant_mount --nocapture
