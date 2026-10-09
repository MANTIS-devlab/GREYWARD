#!/bin/bash
# Separate-account real Secret Service probe, no active-user/desktop changes.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
test "$(id -G greyward-guard-probe)" = 1002
if pgrep -u 1002 >/dev/null; then echo 'Probe account is busy' >&2; exit 1; fi
stage=/var/tmp/greyward-application-security-probe
parent=/var/lib/greyward-development/application-security
sudo -n test ! -L "$parent"
test "$(sudo -n stat -c '%u %a' "$parent")" = '0 700'
fixture=$(sudo -n mktemp -d "$parent/keyring-probe.XXXXXXXX")
case "$fixture" in "$parent"/keyring-probe.*) ;; *) exit 2;; esac
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
setup=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-application-security-keyring-probe.service >/dev/null 2>&1
    if $setup; then
        sudo -n restorecon -R "$fixture" || result=1
        sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || result=1
    fi
    test "$(getenforce)" = Enforcing || result=1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    exit "$result"
}
trap cleanup EXIT
sudo -n test ! -L "$fixture"
# A unique root-created fixture cannot adopt any existing credential collection.
test "$(sudo -n stat -c '%u %a' "$fixture")" = '0 700'
sudo -n install -d -m0700 -o 1002 -g 1002 "$fixture"
for directory in seed-runtime seed-runtime/keyring deny-runtime deny-runtime/keyring home home/.local home/.local/share home/.local/share/keyrings home/.config home/.cache; do
    sudo -n install -d -m0700 -o 1002 -g 1002 "$fixture/$directory"
done
sudo -n install -m0755 "$stage/application-security-keyring-session.sh" /usr/local/libexec/greyward-application-security-keyring-session.sh
sudo -n restorecon /usr/local/libexec/greyward-application-security-keyring-session.sh
for mode in seed deny; do
    printf '%s\n' "<busconfig><type>session</type><listen>unix:path=/run/greyward-application-security-keyring/$mode-runtime/bus</listen><auth>EXTERNAL</auth><policy context=\"default\"><allow user=\"1002\"/><allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>" > "$stage/keyring-session-bus.conf"
    sudo -n install -m0444 "$stage/keyring-session-bus.conf" "$fixture/$mode-session-bus.conf"
done
printf '%s\n' "$fixture" > "$stage/keyring-probe.path"
run_fixture() {
    local context=$1 mode=$2
    sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-keyring-probe \
        -p User=greyward-guard-probe -p Group=greyward-guard-probe \
        -p RuntimeMaxSec=30 -p TimeoutStopSec=3 -p MemoryMax=256M -p CPUQuota=100% -p TasksMax=64 \
        -p PrivateNetwork=yes -p PrivateTmp=yes -p ProtectHome=yes -p ProtectSystem=strict \
        -p "BindPaths=$fixture:/run/greyward-application-security-keyring" \
        -p ReadWritePaths=/run/greyward-application-security-keyring \
        -p "SELinuxContext=$context" -E PATH=/usr/bin:/bin \
        -E HOME=/run/greyward-application-security-keyring/home \
        /bin/bash /usr/local/libexec/greyward-application-security-keyring-session.sh "$mode"
}
run_fixture unconfined_u:unconfined_r:unconfined_t:s0 seed
setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
sudo -n chcon -R -t user_home_t "$fixture"
sudo -n chcon -t user_home_dir_t "$fixture" "$fixture/home"
sudo -n chcon -R -t user_tmp_t "$fixture/seed-runtime" "$fixture/deny-runtime"
# Use Fedora's existing keyring runtime label for the private socket directory,
# rather than widening its domain's access to ordinary user temporary files.
sudo -n chcon -R -t gkeyringd_tmp_t "$fixture/deny-runtime/keyring"
sudo -n chcon -R -t greyward_guard_secret_t "$fixture/home/.local/share/keyrings"
# Match the enrolled user's SELinux identity as well as DAC UID. Bootstrap
# objects came from the explicitly unconfined positive-control context.
sudo -n chcon -R -u greyward_guard_u "$fixture"
run_fixture greyward_guard_u:greyward_guard_r:greyward_guard_t:s0 deny
