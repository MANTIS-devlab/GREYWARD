#!/bin/bash
# Disjoint synthetic label grants, no public grant API or production enrollment.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
stage=/var/tmp/greyward-application-security-probe
state=/var/lib/greyward-development/application-security
home=/home/greyward-guard-probe
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
build=$(mktemp -d /var/tmp/greyward-application-security-build/grant-policy.XXXXXX)
cp "$stage/greyward_resource_grant_probe.te" "$build/"
systemd-run --user --wait --pipe --collect --unit=greyward-appsec-grant-policy-build \
    -p "WorkingDirectory=$build" -p RuntimeMaxSec=120 -p MemoryMax=512M -p CPUQuota=100% \
    /usr/bin/make -f /usr/share/selinux/devel/Makefile greyward_resource_grant_probe.pp
guard_setup=false
module_added=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    local failed=0
    for unit in ordinary raw tool browser lifetime; do sudo -n systemctl stop "greyward-application-security-grant-$unit.service" >/dev/null 2>&1; done
    if $guard_setup; then
        sudo -n loginctl terminate-user greyward-guard-probe >/dev/null 2>&1
        if sudo -n test -d "$home/resource-grants"; then sudo -n restorecon -R "$home/resource-grants" || failed=1; fi
    fi
    if $module_added; then sudo -n semodule -r greyward_resource_grant_probe || failed=1; fi
    if $guard_setup; then sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || failed=1; fi
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || failed=1
    test "$(getenforce)" = Enforcing || failed=1
    if test "$failed" = 1; then echo 'Grant probe cleanup requires recovery' >&2; result=1; fi
    exit "$result"
}
trap cleanup EXIT
guard_setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
sudo -n semodule -i "$build/greyward_resource_grant_probe.pp"
module_added=true
sudo -n test ! -L "$home/resource-grants"
if sudo -n test -e "$home/resource-grants"; then test "$(sudo -n stat -c %u "$home/resource-grants")" = 0; fi
sudo -n install -d -m0755 "$home/resource-grants"
sudo -n chcon -t user_home_t "$home/resource-grants"
for category in ssh browser other; do
    directory=$home/resource-grants/$category
    sudo -n test ! -L "$directory"
    sudo -n test ! -L "$directory/synthetic"
    if sudo -n test -e "$directory"; then test "$(sudo -n stat -c %u "$directory")" = 0; fi
    if sudo -n test -e "$directory/synthetic"; then test "$(sudo -n stat -c '%u %h' "$directory/synthetic")" = '0 1'; fi
    sudo -n install -d -m0755 "$directory"
    printf 'synthetic grant-scope fixture\n' | sudo -n tee "$directory/synthetic" >/dev/null
    sudo -n chmod 0444 "$directory/synthetic"
    case "$category" in
        ssh) resource_type=greyward_probe_ssh_t;;
        browser) resource_type=greyward_probe_browser_data_t;;
        other) resource_type=greyward_probe_other_data_t;;
    esac
    sudo -n chcon -t "$resource_type" "$directory" "$directory/synthetic"
done

# PID 1 owns the timeout and cgroup after the launcher exits. The fixed child
# intentionally keeps its raw descriptor and ignores SIGTERM. No production
# this-run grant or broker-crash integration is claimed by this fixture.
sudo -n install -m0755 "$stage/application-security-grant-lifetime.py" /usr/local/libexec/greyward-application-security-grant-lifetime.py
sudo -n restorecon /usr/local/libexec/greyward-application-security-grant-lifetime.py
sudo -n systemd-run --unit=greyward-application-security-grant-lifetime \
    -p RuntimeMaxSec=8 -p TimeoutStopSec=1 -p KillMode=control-group \
    -p SendSIGKILL=yes -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=8 \
    -p User=greyward-guard-probe -p Group=greyward-guard-probe \
    -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p ProtectControlGroups=yes \
    -p SELinuxContext=greyward_guard_u:greyward_guard_owner_r:greyward_probe_tool_t:s0 \
    /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-grant-lifetime.py --fixed-workload
sudo -n /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-grant-lifetime.py --fixed-observer
test "$(sudo -n systemctl show greyward-application-security-grant-lifetime.service -p Result --value)" = timeout
sudo -n systemctl reset-failed greyward-application-security-grant-lifetime.service
sudo -n install -m0755 "$stage/application-security-grant-probe.py" /usr/local/libexec/greyward-application-security-grant-probe.py
sudo -n restorecon /usr/local/libexec/greyward-application-security-grant-probe.py
for profile in ordinary raw tool browser; do
    nnp=yes
    case "$profile" in
        ordinary) context=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0;;
        raw) context=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0; nnp=no;;
        tool) context=greyward_guard_u:greyward_guard_owner_r:greyward_probe_tool_t:s0;;
        browser) context=greyward_guard_u:greyward_guard_owner_r:greyward_probe_browser_t:s0;;
    esac
    sudo -n systemd-run --wait --pipe --collect --unit="greyward-application-security-grant-$profile" \
        -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=16 \
        -p User=greyward-guard-probe -p Group=greyward-guard-probe -p "NoNewPrivileges=$nnp" \
        -p CapabilityBoundingSet= -p "SELinuxContext=$context" \
        /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-grant-probe.py
done
