#!/bin/bash
# Separate-account protocol feasibility. No production broker/display mutation.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
test "$(id -G greyward-guard-probe)" = 1002
if pgrep -u 1002 >/dev/null; then echo 'Probe account is busy' >&2; exit 1; fi
stage=/var/tmp/greyward-application-security-probe
input=/var/tmp/greyward-application-security-build/wayland-probe-input
test "$(stat -c '%u %a' /var/tmp/greyward-application-security-build)" = "$(id -u) 700"
test ! -L "$input"
test "$(sha256sum "$input/security-context-v1.xml" | cut -d' ' -f1)" = f4f8ba15ebd2df62db611b1de32e992f660a4aeeea83250cb88fa468da42ffcb
build=$(mktemp -d /var/tmp/greyward-application-security-build/wayland-build.XXXXXXXX)
cp "$input/security-context-v1.xml" "$input/probe.c" "$build/"
systemd-run --user --wait --pipe --collect --unit=greyward-appsec-wayland-build \
    -p RuntimeMaxSec=30 -p MemoryMax=256M -p CPUQuota=100% -p "WorkingDirectory=$build" \
    -E PATH=/usr/bin:/bin /bin/bash -c \
    '/usr/bin/wayland-scanner client-header security-context-v1.xml security-context-client.h && /usr/bin/wayland-scanner private-code security-context-v1.xml security-context-protocol.c && /usr/bin/gcc -std=c11 -Wall -Wextra -Werror probe.c security-context-protocol.c -lwayland-client -o probe'
sha256sum "$build/probe"
parent=/var/lib/greyward-development/application-security
sudo -n test ! -L "$parent"
test "$(sudo -n stat -c '%u %a' "$parent")" = '0 700'
fixture=$(sudo -n mktemp -d "$parent/wayland-probe.XXXXXXXX")
case "$fixture" in "$parent"/wayland-probe.*) ;; *) exit 2;; esac
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
setup=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-application-security-wayland-probe.service >/dev/null 2>&1
    if $setup; then
        sudo -n restorecon -R "$fixture" || result=1
        sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || result=1
    fi
    test "$(getenforce)" = Enforcing || result=1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    exit "$result"
}
trap cleanup EXIT
sudo -n install -m0755 "$build/probe" /usr/local/libexec/greyward-application-security-wayland-probe
sudo -n install -m0755 "$stage/application-security-wayland-session.sh" /usr/local/libexec/greyward-application-security-wayland-session.sh
sudo -n restorecon /usr/local/libexec/greyward-application-security-wayland-probe /usr/local/libexec/greyward-application-security-wayland-session.sh
setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
sudo -n install -d -o 1002 -g 1002 -m0700 "$fixture"
for directory in home runtime config config/labwc state cache; do
    sudo -n install -d -o 1002 -g 1002 -m0700 "$fixture/$directory"
done
printf '<labwc_config><core><decoration>server</decoration></core></labwc_config>\n' > "$stage/wayland-rc.xml"
printf '#!/bin/sh\n' > "$stage/wayland-autostart"
sudo -n install -m0444 "$stage/wayland-rc.xml" "$fixture/config/labwc/rc.xml"
sudo -n install -m0555 "$stage/wayland-autostart" "$fixture/config/labwc/autostart"
sudo -n chcon -R -u greyward_guard_u -t user_home_t "$fixture"
sudo -n chcon -t user_home_dir_t "$fixture" "$fixture/home"
sudo -n chcon -R -t user_tmp_t "$fixture/runtime"
printf '%s\n' "$fixture" > "$stage/wayland-probe.path"
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-wayland-probe \
    -p User=greyward-guard-probe -p Group=greyward-guard-probe \
    -p RuntimeMaxSec=20 -p TimeoutStopSec=3 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=32 \
    -p PrivateNetwork=yes -p PrivateTmp=yes -p ProtectHome=yes -p ProtectSystem=strict \
    -p "BindPaths=$fixture:/run/greyward-application-security-wayland" \
    -p ReadWritePaths=/run/greyward-application-security-wayland \
    -p SELinuxContext=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0 \
    -E PATH=/usr/bin:/bin /bin/bash /usr/local/libexec/greyward-application-security-wayland-session.sh
