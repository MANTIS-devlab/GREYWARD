#!/usr/bin/bash
# Withdraw only the owned managed-isolation development activation.
# Refuse if account enrollment or Protected Data now requires a real migration.
set -euo pipefail
test "$(id -u)" = 0
case "${1:-}" in ''|--check) ;; *) exit 2;; esac
base=/var/lib/greyward-development/application-security-live
test ! -L "$base"
test "$(stat -c '%u %g %a' "$base")" = '0 0 700'
test ! -L "$base/active.json"
test "$(stat -c '%u %g %a %h' "$base/active.json")" = '0 0 600 1'
python3 -I - "$base/active.json" <<'PY'
import json, os, sqlite3, sys
with open(sys.argv[1]) as stream:
    receipt=json.load(stream)
assert receipt['schema']=='greyward.application-security.live-development/v1'
assert receipt['managed_isolation'] is True
assert receipt['whole_session_enrollment'] is False
path='/var/lib/greyward/application-security/policy.sqlite3'
st=os.lstat(path)
assert st.st_uid==st.st_gid==0 and st.st_mode & 0o777==0o600 and st.st_nlink==1
with sqlite3.connect('file:'+path+'?mode=ro',uri=True) as db:
    assert db.execute('PRAGMA quick_check').fetchall()==[('ok',)]
    for table in ('resource_intents','grant_intents','resource_label_journal','enrollment_accounts'):
        assert db.execute('SELECT count(*) FROM '+table).fetchone()[0]==0, table
PY
if semanage login -l | grep -q 'greyward_guard_u'; then
    echo 'Account mapping exists; this isolation-only rollback cannot undo enrollment.' >&2
    exit 1
fi
for module in greyward_guard_probe greyward_guard_isolation_host; do
    semodule -l | awk '{print $1}' | grep -Fx "$module" >/dev/null
done
sha256sum --check --strict "$base/inputs.sha256" >/dev/null
if test "${1:-}" = --check; then
    echo 'Managed-isolation rollback prerequisites verified; no mutation performed.'
    exit 0
fi
test ! -e "$base/rollback.json"
systemctl disable --now greyward-application-security-workflows.service
mapfile -t units < <(systemctl list-units --all --plain --no-legend 'greyward-appsec-isolated-*' | awk '{print $1}')
for unit in "${units[@]}"; do
    [[ "$unit" =~ ^greyward-appsec-isolated-[0-9a-f]{64}\.service$ ]]
    systemctl stop "$unit"
done
semanage user -d greyward_guard_u
semodule -r greyward_guard_isolation_host greyward_guard_probe
python3 -I - "$base" <<'PY'
import json, os, sys
base=sys.argv[1]
fd=os.open(base+'/rollback.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as stream:
    json.dump({'schema':'greyward.application-security.live-development/v1',
               'managed_isolation':False,'whole_session_enrollment':False,
               'policy_database_preserved':True},stream)
    stream.flush(); os.fsync(stream.fileno())
os.rename(base+'/active.json',base+'/inactive.json')
PY
echo 'Owned isolation service/policy withdrawn; inventory and user data preserved.'
