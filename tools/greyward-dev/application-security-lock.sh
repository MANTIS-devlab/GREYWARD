#!/bin/bash
# Enroll only the owned probe account; native DMS PAM on a private headless seat.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
test "$(id -G greyward-guard-probe)" = 1002
if pgrep -u 1002 >/dev/null; then echo 'Probe account is busy' >&2; exit 1; fi
stage=/var/tmp/greyward-application-security-probe
parent=/var/lib/greyward-development/application-security
test "$(sudo -n stat -c '%u %a' "$parent")" = '0 700'
sudo -n test ! -L "$parent"
fixture=$(sudo -n mktemp -d "$parent/lock-probe.XXXXXXXX")
case "$fixture" in "$parent"/lock-probe.*) ;; *) exit 2;; esac
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
setup=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-application-security-lock-coordinator.service greyward-application-security-lock-probe.service >/dev/null 2>&1
    sudo -n python3 -I /usr/local/libexec/greyward-application-security-authorization.py --restore || result=1
    if $setup; then
        sudo -n restorecon -R "$fixture" || result=1
        sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || result=1
    fi
    test "$(getenforce)" = Enforcing || result=1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    exit "$result"
}
trap cleanup EXIT
for name in lock.py lock-session.sh; do
    sudo -n install -m0755 "$stage/application-security-$name" "/usr/local/libexec/greyward-application-security-$name"
    sudo -n restorecon "/usr/local/libexec/greyward-application-security-$name"
done
setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
sudo -n install -d -o 1002 -g 1002 -m0700 "$fixture"
for directory in home runtime config config/labwc config/DankMaterialShell state cache; do
    sudo -n install -d -o 1002 -g 1002 -m0700 "$fixture/$directory"
done
# Fixed source settings copy and candidate-only overrides. Existing per-user
# preferences and Fedora PAM/authselect are never changed.
sudo -n python3 -I - "$fixture" <<'PY'
import json, pathlib, sys
base = pathlib.Path(sys.argv[1])
settings = json.loads(pathlib.Path('/home/greyward-guard-probe/.config/DankMaterialShell/settings.json').read_text())
settings.update({'customPowerActionLock': '', 'loginctlLockIntegration': False,
    'lockAtStartup': False, 'lockBeforeSuspend': False, 'fadeToLockEnabled': False,
    'fadeToDpmsEnabled': False, 'lockScreenPowerOffMonitorsOnLock': False,
    'lockScreenVideoEnabled': False, 'lockPamExternallyManaged': True,
    'lockPamPath': '/etc/pam.d/greyward-dms-lock', 'enableFprint': False, 'enableU2f': False})
for key in ('acMonitorTimeout', 'acLockTimeout', 'acPostLockMonitorTimeout',
            'batteryMonitorTimeout', 'batteryLockTimeout', 'batteryPostLockMonitorTimeout',
            'acSuspendTimeout', 'batterySuspendTimeout'):
    settings[key] = 0
(base / 'config/DankMaterialShell/settings.json').write_text(json.dumps(settings))
(base / 'session-bus.conf').write_text('<busconfig><type>session</type><listen>unix:path=/run/greyward-application-security-lock/runtime/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="1002"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
(base / 'config/labwc/rc.xml').write_text('<labwc_config><core><decoration>server</decoration></core></labwc_config>')
(base / 'config/labwc/autostart').write_text('#!/bin/sh\n')
PY
sudo -n chown -R 1002:1002 "$fixture"
sudo -n chcon -R -u greyward_guard_u -t user_home_t "$fixture"
sudo -n chcon -t user_home_dir_t "$fixture" "$fixture/home"
sudo -n chcon -R -t user_tmp_t "$fixture/runtime"
printf '%s\n' "$fixture" > "$stage/lock-probe.path"
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-lock-coordinator \
    -p RuntimeMaxSec=80 -p TimeoutStopSec=3 -p MemoryMax=128M -p CPUQuota=50% \
    -p SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0 \
    /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-lock.py "$fixture"
