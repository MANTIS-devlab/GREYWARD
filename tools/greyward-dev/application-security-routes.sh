#!/bin/bash
# Actual execution-route probes for the separately enrolled development account.
set -euo pipefail
test "$(id -un)" = greyward-guard-probe
test "$HOME" = /home/greyward-guard-probe
test "$(getenforce)" = Enforcing
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
test -S "$XDG_RUNTIME_DIR/bus"
result_dir=$(mktemp -d "$HOME/.guard-routes.XXXXXXXX")
unit=greyward-guard-routes-${result_dir##*.}
cleanup() {
    systemctl --user stop "$unit.service" "$unit.timer" "$unit-owner.service" >/dev/null 2>&1 || true
}
trap cleanup EXIT
probe=/usr/local/libexec/greyward-application-security-probe.py
python3 -I "$probe" --home "$HOME" --route-only > "$result_dir/ssh.json"
systemd-run --user --quiet --collect --wait --pipe \
    --property=RuntimeMaxSec=30 --property=MemoryMax=64M \
    python3 -I "$probe" --home "$HOME" --route-only > "$result_dir/service.json"
systemd-run --user --quiet --unit="$unit" --on-active=1s \
    --timer-property=AccuracySec=100ms --property=RuntimeMaxSec=30 \
    --property=MemoryMax=64M --property="StandardOutput=file:$result_dir/timer.json" \
    python3 -I "$probe" --home "$HOME" --route-only
for attempt in {1..60}; do
    if test -s "$result_dir/timer.json" && \
       ! systemctl --user is-active --quiet "$unit.service"; then break; fi
    sleep 0.5
done
# Asking the ordinary user manager for the grant-bearing context must fail at
# exec. No synthetic resource content is printed even if this gate regresses.
if systemd-run --user --quiet --wait --pipe --unit="$unit-owner" \
    --property=RuntimeMaxSec=10 --property=MemoryMax=64M \
    --property=SELinuxContext=greyward_guard_u:greyward_guard_owner_r:greyward_guard_owner_t:s0 \
    python3 -I -c "open('/home/greyward-guard-probe/protected/credential', 'rb').read(1)" \
    > "$result_dir/owner-output.txt" 2> "$result_dir/owner-error.txt"; then
    echo '0' > "$result_dir/owner-exec-status.txt"
else
    systemctl --user show "$unit-owner.service" --property=ExecMainStatus --value \
        > "$result_dir/owner-exec-status.txt"
fi
python3 -I - "$result_dir" <<'PY'
import json
import pathlib
import sys
directory = pathlib.Path(sys.argv[1])
results = []
for route in ("ssh", "service", "timer"):
    try:
        result = json.loads((directory / (route + ".json")).read_text())
        valid = result["schema"] == "greyward.application-security.probe/v1" and \
            result["scope"] == "synthetic-confined-route" and result["passed"] and \
            len(result["results"]) == 24 and all(item["passed"] for item in result["results"])
        results.append({"route": route, "passed": bool(valid), "checks": result["results"]})
    except (OSError, ValueError, KeyError) as error:
        results.append({"route": route, "passed": False, "reason": type(error).__name__})
status = (directory / "owner-exec-status.txt").read_text().strip()
results.append({"route": "user-manager-owner-transition", "passed": status == "203",
                "exec_status": status})
passed = all(result["passed"] for result in results)
print(json.dumps({"schema": "greyward.application-security.routes/v1", "passed": passed,
                  "scope": "separate-confined-account", "results": results}, sort_keys=True))
sys.exit(0 if passed else 1)
PY
