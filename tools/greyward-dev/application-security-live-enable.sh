#!/usr/bin/bash
# Explicit, recoverable activation of the installed development runtime.
# No account conversion, default login mapping, password or resource relabeling.
set -euo pipefail
test "$(id -u)" = 0
test "$(getenforce)" = Enforcing
test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' greyward-application-security-experimental)" = 0.1.0-20.fc44
base=/var/lib/greyward-development/application-security-live
inputs="$base/inputs"
test ! -L "$base"
test "$(stat -c '%u %g %a' "$base")" = '0 0 700'
test ! -e "$base/active.json"
test "$(stat -c '%u %g %a' "$inputs")" = '0 0 700'
for path in "$inputs/greyward_guard_probe.te" "$inputs/greyward-guard-isolation-host.cil"; do
    test ! -L "$path"
    test "$(stat -c '%u %g %a %h' "$path")" = '0 0 444 1'
done
for module in greyward_guard_probe greyward_guard_isolation_host; do
    if semodule -l | awk '{print $1}' | grep -Fxq "$module"; then
        echo 'Refuse to replace an existing policy module' >&2; exit 1
    fi
done
if semanage user -l | grep -q '^greyward_guard_u '; then
    echo 'Existing SELinux identity requires review' >&2; exit 1
fi
semanage export > "$base/previous-local-policy.txt"
chmod 0600 "$base/previous-local-policy.txt"
rpm -q greyward-security-center greyward-security-context greyward-application-security-experimental > "$base/packages.txt"
sha256sum "$inputs/greyward_guard_probe.te" "$inputs/greyward-guard-isolation-host.cil" > "$base/inputs.sha256"
install -d -m0700 "$base/build"
install -m0600 "$inputs/greyward_guard_probe.te" "$base/build/greyward_guard_probe.te"
install -m0600 "$inputs/greyward-guard-isolation-host.cil" "$base/build/greyward_guard_isolation_host.cil"
cd "$base/build"
make -f /usr/share/selinux/devel/Makefile greyward_guard_probe.pp > "$base/policy-build.log" 2>&1
installed=0
created_user=0
cleanup_error() {
    systemctl disable --now greyward-application-security-workflows.service || true
    if test "$created_user" = 1; then semanage user -d greyward_guard_u; fi
    if test "$installed" = 1; then semodule -r greyward_guard_isolation_host greyward_guard_probe; fi
}
trap cleanup_error ERR
semodule -i greyward_guard_probe.pp -i greyward_guard_isolation_host.cil
installed=1
semanage user -a -R greyward_guard_r -r s0 -L s0 greyward_guard_u
created_user=1
systemctl daemon-reload
systemctl enable --now greyward-application-security-workflows.service
systemctl is-active --quiet greyward-application-security-workflows.service
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s systems.mantis.greyward.ApplicationSecurity1 | grep -Fx 'b true'
python3 -I - "$base/active.json" <<'PY'
import json, os, sys
fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
with os.fdopen(fd,'w') as stream:
    json.dump({'schema':'greyward.application-security.live-development/v1',
        'runtime':'0.1.0-20.fc44','managed_isolation':True,'whole_session_enrollment':False},stream)
    stream.flush(); os.fsync(stream.fileno())
PY
trap - ERR
echo 'Installed managed-workflow backend active; session enrollment is separate.'
