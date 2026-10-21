#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
inputs=${1:?Usage: build.sh VERIFIED-INPUTS NEW-OUTPUT}
output=${2:?Provide a new output directory}
test ! -e "$output"
mkdir -p "$output"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,TMP}
# The spec can reuse a builder-owned cache, but a fresh documented invocation
# must also work without a caller-supplied Cargo target directory.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(realpath "$output")/cargo-target}"
mkdir -p "$CARGO_TARGET_DIR"
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
  packaging/greyward-files/pcmanfm-desktop-only.patch \
  packaging/greyward-files/pcmanfm-multi-output.patch tests/test_desktop_output_layout.cpp \
  packaging/greyward-files/strata-preview-mode.patch packaging/greyward-files/strata-native-icons.patch \
  branding/source/greyward-files.svg branding/source/greyward-icon-family.json \
  tools/generate-file-icons.py branding/LICENSE
cp "$repo/packaging/greyward-files/greyward-files.spec" "$output/SPECS/"
rpmbuild --define "_topdir $(realpath "$output")" \
  --define "_tmppath $(realpath "$output")/TMP" -ba "$output/SPECS/greyward-files.spec"
