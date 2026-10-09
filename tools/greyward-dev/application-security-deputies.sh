#!/bin/bash
# Development-only fixed export/deputy probe. Never changes the active account.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
stage=/var/tmp/greyward-application-security-probe
test "$(id -u greyward-guard-probe)" = 1002
test "$(id -G greyward-guard-probe)" = 1002
test "$(systemctl --user is-active greyward-dms.service)" = active
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
host_namespace_limit=$(cat /proc/sys/user/max_user_namespaces)
setup=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-application-security-deputy-probe.service >/dev/null 2>&1 || true
    if $setup; then sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || result=1; fi
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    test "$(getenforce)" = Enforcing || result=1
    test "$(cat /proc/sys/user/max_user_namespaces)" = "$host_namespace_limit" || result=1
    exit "$result"
}
trap cleanup EXIT
setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
# Re-run ordinary subject/deputy/ptrace and private bind-alias gates with the
# exact module used by Flatpak, not a weaker earlier policy checkpoint.
sudo -n bash "$stage/application-security-feasibility.sh" run "$stage"
sudo -n bash "$stage/application-security-feasibility.sh" namespace "$stage"
sudo -n bash "$stage/application-security-feasibility.sh" aliases "$stage"
sudo -n install -m0755 "$stage/application-security-deputy-probe.py" /usr/local/libexec/greyward-application-security-deputy-probe.py
sudo -n install -m0755 "$stage/application-security-task-probe.py" /usr/local/libexec/greyward-application-security-task-probe.py
sudo -n install -m0755 "$stage/application-security-pip-launch.py" /usr/local/libexec/greyward-application-security-pip-launch.py
sudo -n install -m0644 "$stage/application-security-pip-backend.py" /usr/local/libexec/greyward-application-security-pip-backend.py
sudo -n restorecon /usr/local/libexec/greyward-application-security-deputy-probe.py
sudo -n restorecon /usr/local/libexec/greyward-application-security-task-probe.py
sudo -n restorecon /usr/local/libexec/greyward-application-security-pip-launch.py /usr/local/libexec/greyward-application-security-pip-backend.py
probe_since=$(date --iso-8601=seconds)
protected_inode=$(sudo -n stat -c '%i' /home/greyward-guard-probe/protected/credential)
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-deputy-probe \
    -p User=greyward-guard-probe -p Group=greyward-guard-probe \
    -p SELinuxContext=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0 \
    -p RuntimeMaxSec=45 -p TimeoutStopSec=2 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=32 \
    -p PrivateNetwork=yes -p PrivateTmp=yes \
    /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-deputy-probe.py
# Bound the audit read to this run; no EXECVE/proctitle or environment records.
# Match the precise synthetic resource label/inode, confined subject and fixed
# runtime reader. This is probe evidence, not a production app attribution API.
sudo -n journalctl --since="$probe_since" _TRANSPORT=audit --no-pager -o cat \
    | awk -v inode="$protected_inode" '$0 ~ /^AVC / && $0 ~ /comm="head"/ && $0 ~ /denied.*read/ && $0 ~ /scontext=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0/ && $0 ~ /tcontext=greyward_guard_u:object_r:greyward_guard_secret_t:s0/ && $0 ~ ("ino=" inode " ") { found=1 } END { exit !found }'
printf 'FLATPAK_SYNTHETIC_KERNEL_DENIAL_PASS\n'
