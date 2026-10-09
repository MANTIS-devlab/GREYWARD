#!/bin/bash
# Root-owned storage and fresh-owner review only; no enrollment or active grants.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
confinement_arguments=()
workflow_parent_owns_display=false
case "${1:-}" in
    '') test "$#" = 0 ;;
    --confined) test "$#" = 1; confinement_arguments=(-E GREYWARD_REQUIRE_CONFINED_AUTH_PEER=1) ;;
    --end-to-end) test "$#" = 1; confinement_arguments=(-E GREYWARD_REQUIRE_CONFINED_AUTH_PEER=1 -E GREYWARD_CRITICAL_REGISTRATION=1 -E GREYWARD_CRITICAL_GRANTS=1) ;;
    --workflow) test "$#" = 1; workflow_parent_owns_display=true; confinement_arguments=(-E GREYWARD_REQUIRE_CONFINED_AUTH_PEER=1 -E GREYWARD_CRITICAL_REGISTRATION=1 -E GREYWARD_CRITICAL_GRANTS=1 -E GREYWARD_CRITICAL_TRANSPORT=1) ;;
    *) echo 'Only the fixed optional --confined probe is supported' >&2; exit 2 ;;
esac
if pgrep -u 1002 >/dev/null; then echo 'Probe account is busy' >&2; exit 1; fi
source=/var/tmp/greyward-application-security-build/security-center
stage=/var/tmp/greyward-application-security-probe
state=/var/lib/greyward-development/application-security
action=/usr/share/polkit-1/actions/systems.mantis.greyward.ApplicationSecurity1.policy
helper=/usr/local/libexec/greyward-application-security-authorization-probe
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
sudo -n test ! -e /var/lib/greyward/application-security/policy.sqlite3
test "$(sudo -n stat -c '%u %a' "$state")" = '0 700'
sudo -n test ! -e "$action"
log=$(mktemp /var/tmp/greyward-application-security-build/intent-artifact.XXXXXXXX)
action_created=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    for unit in greyward-appsec-auth-peer greyward-appsec-intent-storage greyward-appsec-intent-refusal greyward-application-security-auth-probe; do
        sudo -n systemctl stop "$unit.service" >/dev/null 2>&1
    done
    if $action_created; then
        sudo -n /usr/bin/python3 -I "$helper" --restore || result=1
        sudo -n rm -f -- "$action" || result=1
    fi
    rm -f -- "$log"
    test "$(getenforce)" = Enforcing || result=1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    sudo -n test ! -e /var/lib/greyward/application-security/policy.sqlite3 || result=1
    # PAM closes the private login before logind's ordinary user-manager stop
    # delay expires. Account teardown is part of this fixture's result; await
    # it before reporting leftover workloads to the outer rollback owner.
    # --workflow's private parent compositor belongs to the outer fixture.
    # Its owner stops it before checking account quiescence and rolling back.
    if ! $workflow_parent_owns_display; then
        for attempt in {1..200}; do
            if ! pgrep -u 1002 >/dev/null; then break; fi
            sleep 0.1
        done
        if pgrep -u 1002 >/dev/null; then result=1; fi
    fi
    exit "$result"
}
trap cleanup EXIT
systemd-run --user --quiet --wait --pipe --collect --unit=greyward-appsec-intent-build \
    -p RuntimeMaxSec=180 -p MemoryMax=1G -p CPUQuota=100% -p "WorkingDirectory=$source" \
    -E PATH=/usr/bin:/bin -E CARGO=/usr/bin/cargo -E RUSTC=/usr/bin/rustc \
    -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
    /usr/bin/cargo test -p greyward-application-security --lib --test system_bus_peer \
        --test system_bus_authorization --no-run --message-format=json --offline --locked > "$log"
mapfile -t binaries < <(/usr/bin/python3 -I - "$source" "$log" <<'PY'
import json, pathlib, sys
base = pathlib.Path(sys.argv[1]) / 'target/debug/deps'
names = ['greyward_application_security', 'system_bus_peer', 'system_bus_authorization']
matches = {name: [] for name in names}
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    item = json.loads(line)
    name = item.get('target', {}).get('name')
    if item.get('reason') == 'compiler-artifact' and name in matches and item.get('executable'):
        candidate = pathlib.Path(item['executable'])
        if candidate.parent != base or not candidate.name.startswith(name + '-'):
            raise SystemExit('Unexpected intent test artifact')
        matches[name].append(str(candidate))
if any(len(matches[name]) != 1 for name in names):
    raise SystemExit('Exactly three current intent test artifacts required')
for name in names:
    print(matches[name][0])
PY
)
test "${#binaries[@]}" = 3
destinations=(/usr/local/libexec/greyward-application-security-intent-storage-test \
    /usr/local/libexec/greyward-application-security-auth-test \
    /usr/local/libexec/greyward-application-security-fresh-auth-test)
for index in 0 1 2; do
    sha256sum -- "${binaries[$index]}"
    sudo -n install -m0755 "${binaries[$index]}" "${destinations[$index]}"
    sudo -n restorecon "${destinations[$index]}"
done
sudo -n install -m0755 "$stage/application-security-authorization.py" "$helper"
sudo -n restorecon "$helper"
sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-intent-storage \
    -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=32 \
    -p PrivateNetwork=yes -p PrivateTmp=yes -p ProtectSystem=strict -p "ReadWritePaths=$state" \
    "${destinations[0]}" --ignored --exact \
    store::tests::root_filesystem_store_rejects_unsafe_owners_modes_links_and_corruption --nocapture
sudo -n install -m0644 "$source/packaging/application-security/systems.mantis.greyward.ApplicationSecurity1.policy" "$action"
action_created=true
sudo -n restorecon "$action"
sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-intent-refusal \
    -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=32 \
    "${destinations[1]}" --ignored --exact root_broker_checks_do_not_authorize_an_unauthenticated_subject --nocapture
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-auth-probe \
    -p RuntimeMaxSec=180 -p MemoryMax=1G -p CPUQuota=100% -p TasksMax=32 \
    -p SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0 \
    "${confinement_arguments[@]}" \
    /usr/bin/python3 -I "$helper"
