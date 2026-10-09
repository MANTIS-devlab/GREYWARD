#!/bin/bash
# Minimum startup regression in the separate account; no portal/lock matrix.
set -euo pipefail
test "$(id -u)" = 1002
test "${WLR_BACKENDS:-}" = headless
export XDG_RUNTIME_DIR=/run/user/1002
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
systemctl --user set-property --runtime greyward-dms.service CPUQuota=25% MemoryMax=512M
trap 'uwsm stop' EXIT
uwsm finalize WAYLAND_DISPLAY XDG_CURRENT_DESKTOP QT_QUICK_BACKEND
for attempt in {1..12}; do
    if timeout 5s /usr/local/libexec/greyward-dms-runtime-check > "$HOME/critical-shell.json"; then
        /usr/bin/python3 -I - <<'PY'
import pathlib, subprocess
for name in ['labwc', 'dms', 'quickshell']:
    pids=subprocess.check_output(['pgrep','-u','1002','-x',name],text=True).split()
    if not pids: raise SystemExit('Missing private graphical process')
    for pid in pids:
        context=pathlib.Path(f'/proc/{pid}/attr/current').read_text().strip('\0\n')
        if context.split(':')[2]!='greyward_guard_t':
            raise SystemExit('Unconfined private graphical process')
PY
        exit 0
    fi
    sleep 0.3
done
exit 1
