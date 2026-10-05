#!/usr/bin/env bash
set -euo pipefail
# Run inside an isolated Fedora 44 builder with these inputs already present.
# No dependency/network resolution is allowed in rpmbuild.
repo=$(cd "$(dirname "$0")/../.." && pwd)
inputs=${1:?Usage: build.sh VERIFIED-INPUT-DIRECTORY NEW-OUTPUT-DIRECTORY}
output=${2:?Provide a new output directory}
test ! -e "$output"
mkdir -p "$output"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
python3 - "$repo/environment/production/dms-release.json" "$inputs" <<'PY'
import hashlib,json,pathlib,sys
m=json.load(open(sys.argv[1]))
for item in m['inputs'].values():
 p=pathlib.Path(sys.argv[2])/item['file']
 if hashlib.sha256(p.read_bytes()).hexdigest()!=item['sha256']: raise SystemExit('Input digest mismatch: '+str(p))
PY
cp "$inputs/dms-source.tar.gz" "$inputs/dms-cli-1.6.2.tar.gz" "$output/SOURCES/"
tar -C "$repo" -czf "$output/SOURCES/greyward-dms-inputs.tar.gz" \
  packaging/greyward-dms/assemble.py packaging/greyward-dms/verify.py \
  environment/production/dms-release.json environment/patches/dms \
  environment/session/greyward-dms environment/session/dankmaterialshell/plugins
python3 - "$repo/environment/production/dms-release.json" "$repo/packaging/greyward-dms/greyward-dms.spec" "$output/SPECS/greyward-dms.spec" <<'PY'
import json,pathlib,re,sys
m=json.load(open(sys.argv[1])); version=m['dms']['tag'].removeprefix('v')
match=re.fullmatch(r'v'+re.escape(version)+r'-(\d+)',m['releaseId'])
if not match: raise SystemExit('Invalid canonical DMS package identity')
pins={'dms-greeter' if k=='greeter' else k:v for k,v in m['compatibility'].items() if k in ('quickshell','greeter','labwc','uwsm')}
prefix=f'%global greyward_version {version}\n%global greyward_revision {match[1]}\n%global greyward_runtime /usr/lib/greyward/dms/{m["releaseId"]}\n'
prefix+=''.join(f'Requires: {name} = {value}\n' for name,value in sorted(pins.items()))
pathlib.Path(sys.argv[3]).write_text(prefix+pathlib.Path(sys.argv[2]).read_text())
PY
rpmbuild --define "_topdir $(realpath "$output")" -ba "$output/SPECS/greyward-dms.spec"
