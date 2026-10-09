#!/bin/bash
# Generated denial CIL on synthetic objects; never changes the production session.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
if pgrep -u 1002 >/dev/null; then echo 'Probe account is busy' >&2; exit 1; fi
source=/var/tmp/greyward-application-security-build/security-center
stage=/var/tmp/greyward-application-security-probe
state=/var/lib/greyward-development/application-security
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
log=$(mktemp /var/tmp/greyward-application-security-build/resource-policy-artifact.XXXXXXXX)
build=$(mktemp -d /var/tmp/greyward-application-security-build/resource-policy.XXXXXXXX)
fixture=$(sudo -n mktemp -d "$state/resource-policy.XXXXXXXX")
case "$fixture" in "$state"/resource-policy.*) ;; *) exit 2;; esac
guard_setup=false
policy_attempted=false
conflict_attempted=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-appsec-resource-policy-probe.service >/dev/null 2>&1
    sudo -n systemctl stop greyward-appsec-resource-fd-probe.service >/dev/null 2>&1
    sudo -n systemctl stop greyward-appsec-resource-fd-coordinator.service >/dev/null 2>&1
    sudo -n systemctl stop greyward-appsec-policy-lifecycle-child.service greyward-appsec-policy-lifecycle-coordinator.service >/dev/null 2>&1
    sudo -n restorecon /usr/local/libexec/greyward-application-security-policy-readback-probe >/dev/null 2>&1
    if $conflict_attempted; then sudo -n semodule -r greyward_resource_label_conflict >/dev/null 2>&1; fi
    sudo -n restorecon -R "$fixture" || result=1
    if $policy_attempted && sudo -n semodule -l | /usr/bin/awk '$1 == "greyward_resource_label_probe" {found=1} END {exit !found}'; then
        sudo -n semodule -r greyward_resource_label_probe || result=1
    fi
    if $guard_setup; then sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || result=1; fi
    rm -f -- "$log"
    test "$(getenforce)" = Enforcing || result=1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    if pgrep -u 1002 >/dev/null; then result=1; fi
    exit "$result"
}
trap cleanup EXIT
if sudo -n semodule -l | /usr/bin/awk '$1 ~ /^greyward_resource_label_(probe|conflict)$/ {found=1} END {exit !found}'; then
    echo 'Generated resource policy fixture is already installed' >&2; exit 1
fi
systemd-run --user --quiet --wait --pipe --collect --unit=greyward-appsec-resource-policy-build \
    -p RuntimeMaxSec=180 -p MemoryMax=1G -p CPUQuota=100% -p "WorkingDirectory=$source" \
    -E PATH=/usr/bin:/bin -E CARGO=/usr/bin/cargo -E RUSTC=/usr/bin/rustc \
    -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
    /usr/bin/cargo build -p greyward-application-security --example resource-policy-check \
        --message-format=json --offline --locked > "$log"
binary=$(/usr/bin/python3 -I - "$source" "$log" <<'PY'
import json, pathlib, sys
base = pathlib.Path(sys.argv[1]) / 'target/debug/examples'
matches = []
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    item = json.loads(line)
    if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'resource-policy-check' and item.get('executable'):
        candidate = pathlib.Path(item['executable'])
        if candidate.parent != base or candidate.name != 'resource-policy-check':
            raise SystemExit('Unexpected current policy emitter')
        matches.append(str(candidate))
if len(matches) != 1:
    raise SystemExit('Exactly one current policy emitter required')
print(matches[0])
PY
)
sha256sum -- "$binary"
"$binary" --emit-development-fixture > "$build/greyward_resource_label_probe.cil"
sha256sum -- "$build/greyward_resource_label_probe.cil"
sudo -n install -m0755 "$binary" /usr/local/libexec/greyward-application-security-policy-readback-probe
sudo -n restorecon /usr/local/libexec/greyward-application-security-policy-readback-probe
sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-resource-policy-absent \
    -p RuntimeMaxSec=15 -p MemoryMax=64M -p CPUQuota=100% -p TasksMax=16 \
    /usr/local/libexec/greyward-application-security-policy-readback-probe --expect-absent-development-fixture
guard_setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
sudo -n /usr/bin/python3 -I - "$fixture" <<'PY'
import pathlib, sys
base = pathlib.Path(sys.argv[1])
configuration = pathlib.Path('/etc/selinux/semanage.conf').read_text()
if configuration.count('expand-check=0') != 1:
    raise SystemExit('Review changed Fedora semanage configuration before this probe')
path = base / 'semanage.conf'
with path.open('x') as stream:
    stream.write(configuration.replace('expand-check=0', 'expand-check=1'))
path.chmod(0o600)
PY
sudo -n install -m0600 "$build/greyward_resource_label_probe.cil" "$fixture/greyward_resource_label_probe.cil"
policy_attempted=true
sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-resource-policy-install \
    -p RuntimeMaxSec=120 -p MemoryMax=1G -p CPUQuota=100% \
    /usr/sbin/semodule -g "$fixture/semanage.conf" -i "$fixture/greyward_resource_label_probe.cil"
label=greyward_as_resource_$(printf '%064d' 0 | tr 0 d)_t
printf '(allow greyward_guard_t %s (file (read)))\n' "$label" > "$build/greyward_resource_label_conflict.cil"
sudo -n install -m0600 "$build/greyward_resource_label_conflict.cil" "$fixture/greyward_resource_label_conflict.cil"
conflict_attempted=true
if sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-resource-policy-conflict \
    -p RuntimeMaxSec=120 -p MemoryMax=1G -p CPUQuota=100% \
    /usr/sbin/semodule -g "$fixture/semanage.conf" -i "$fixture/greyward_resource_label_conflict.cil" \
    2>&1 | /usr/bin/tee "$build/conflict.log"; then
    echo 'Contradictory sensitive-access allow unexpectedly compiled' >&2; exit 1
fi
if ! rg -q 'neverallow.*failed|neverallow.*violat' "$build/conflict.log"; then
    tail -n 20 "$build/conflict.log"; echo 'No authoritative neverallow rejection' >&2; exit 1
fi
# Failed libsemanage transactions can retain a staged module: remove it before
# other compilation. Absence is harmless, but active presence is checked below.
sudo -n semodule -r greyward_resource_label_conflict >/dev/null 2>&1 || true
if sudo -n semodule -l | /usr/bin/awk '$1 == "greyward_resource_label_conflict" {found=1} END {exit !found}'; then exit 1; fi
conflict_attempted=false
sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-resource-policy-readback \
    -p RuntimeMaxSec=15 -p MemoryMax=64M -p CPUQuota=100% -p TasksMax=16 \
    /usr/local/libexec/greyward-application-security-policy-readback-probe --check-development-fixture
sudo -n install -d -m0700 -o greyward-guard-probe -g greyward-guard-probe "$fixture/home" "$fixture/home/protected"
sudo -n chcon -t user_home_t "$fixture/home"
sudo -n chcon -t "$label" "$fixture/home/protected"
sudo -n /usr/bin/python3 -I - "$fixture/home" "$label" <<'PY'
import os, pathlib, sys
base = pathlib.Path(sys.argv[1])
protected = base / 'protected'
for name in ['initial', 'new-file', 'atomic', 'atomic-replacement']:
    path = protected / name
    with path.open('x') as stream:
        stream.write('synthetic resource-policy data')
    path.chmod(0o600)
    os.chown(path, 1002, 1002)
os.replace(protected / 'atomic-replacement', protected / 'atomic')
for name in ['initial', 'new-file', 'atomic']:
    if os.getxattr(protected / name, 'security.selinux').decode().strip('\0').split(':')[2] != sys.argv[2]:
        raise SystemExit('Root create/replacement did not inherit the generated label')
os.symlink('protected/initial', base / 'symlink')
os.link(protected / 'initial', base / 'hardlink')
(base / 'bound-alias').touch(mode=0o600)
os.chown(base / 'bound-alias', 1002, 1002)
(base / 'late-file').write_text('synthetic descriptor control')
(base / 'late-file').chmod(0o600)
os.chown(base / 'late-file', 1002, 1002)
PY
sudo -n chcon -t user_home_t "$fixture/home/symlink" "$fixture/home/bound-alias" "$fixture/home/late-file" -h
sudo -n install -m0755 "$stage/application-security-resource-policy.py" /usr/local/libexec/greyward-application-security-resource-policy-probe
sudo -n restorecon /usr/local/libexec/greyward-application-security-resource-policy-probe
sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-resource-policy-probe \
    -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=32 \
    -p User=greyward-guard-probe -p Group=greyward-guard-probe \
    -p SELinuxContext=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0 \
    -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p PrivateNetwork=yes \
    -p PrivateMounts=yes -p PrivateTmp=yes -p ProtectSystem=strict \
    -p "BindPaths=$fixture/home:/mnt/greyward-resource-label-probe" \
    -p "BindReadOnlyPaths=$fixture/home/protected/initial:/mnt/greyward-resource-label-probe/bound-alias" \
    /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-resource-policy-probe
sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-resource-fd-coordinator \
    -p RuntimeMaxSec=45 -p MemoryMax=128M -p CPUQuota=100% -p TasksMax=32 \
    -p SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0 \
    /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-resource-policy-probe --coordinate-descriptor "$fixture"
sudo -n systemd-run --wait --pipe --collect --unit=greyward-appsec-policy-lifecycle-coordinator \
    -p RuntimeMaxSec=45 -p MemoryMax=1G -p CPUQuota=100% -p TasksMax=32 \
    -p SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0 \
    /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-resource-policy-probe --coordinate-policy "$fixture"
