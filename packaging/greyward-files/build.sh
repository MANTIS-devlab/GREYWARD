#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
inputs=${1:?Usage: build.sh VERIFIED-INPUTS NEW-OUTPUT}
output=${2:?Provide a new output directory}
test ! -e "$output"
mkdir -p "$output"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
python3 - "$repo/packaging/greyward-files/source.json" "$inputs" "$output/SOURCES" <<'PY'
import hashlib,json,pathlib,shutil,sys
manifest=json.loads(pathlib.Path(sys.argv[1]).read_text())
for item in manifest['inputs'].values():
    path=pathlib.Path(sys.argv[2])/item['file']
    if hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
        raise SystemExit('Source digest mismatch: '+path.name)
    shutil.copyfile(path,pathlib.Path(sys.argv[3])/path.name)
PY
tar -C "$repo" -czf "$output/SOURCES/greyward-files-inputs.tar.gz" \
  environment/session/desktop environment/session/greyward-files-seed \
  environment/session/greyward-desktop-icons environment/session/greyward-desktop-icons.service \
  environment/session/greyward-desktop-shortcut packaging/greyward-files/source.json \
  branding/source/greyward-files.svg branding/LICENSE
cp "$repo/packaging/greyward-files/greyward-files.spec" "$output/SPECS/"
rpmbuild --define "_topdir $(realpath "$output")" -ba "$output/SPECS/greyward-files.spec"
