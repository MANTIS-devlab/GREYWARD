#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
top=${1:?RPM build directory required}
inputs=${2:?Verified upstream archive directory required}
mkdir -p "$top"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS,TMP}
python3 - "$repo" "$top" "$inputs" <<'PY'
import sys,json,hashlib,shutil,tarfile
from pathlib import Path
repo,top,inputs=map(Path,sys.argv[1:]);p=repo/'packaging/greyward-intelligence';m=json.loads((p/'source.json').read_text())
for name,key in [('go.mod','go_mod_sha256'),('go.sum','go_sum_sha256'),('btf-compat.patch','compat_patch_sha256')]:
 assert hashlib.sha256((p/name).read_bytes()).hexdigest()==m[key],name
for name,value in m['sources'].items():
 source=inputs/name
 assert hashlib.sha256(source.read_bytes()).hexdigest()==value['sha256'],name
 shutil.copyfile(source,top/'SOURCES'/name)
with tarfile.open(top/'SOURCES/greyward-intelligence-integration.tar.gz','w:gz') as t:
 t.add(repo/'LICENSE',arcname='GREYWARD-LICENSE')
 for name in ('go.mod','go.sum','btf-compat.patch','source.json','configure-policies.py','attest-sensor.py'):t.add(p/name,arcname=name)
 for name in ('greyward-intelligence-sensor.service','greyward-intelligence-provider.service'):t.add(repo/'security-center/security-context/systemd'/name,arcname=name)
 name='systems.mantis.greyward.Intelligence1.conf';t.add(repo/'security-center/security-context/dbus'/name,arcname=name)
shutil.copyfile(p/'greyward-intelligence.spec',top/'SPECS/greyward-intelligence.spec')
PY
rpmbuild --define "_topdir $top" --define "_tmppath $top/TMP" -ba "$top/SPECS/greyward-intelligence.spec"
