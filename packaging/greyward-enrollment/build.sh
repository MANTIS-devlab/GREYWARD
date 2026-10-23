#!/bin/bash
# Offline package build only. No installation, policy load or account mutation.
set -euo pipefail
test "$(id -u)" != 0
repo=$(cd "$(dirname "$0")/../.." && pwd)
input=$(realpath -e "$1")
output=$(realpath -m "$2")
manifest=${3:-$repo/environment/production/dms-release.json}
# Candidate dependency selection is explicit; default image builds retain the
# production selector. Never derive a package constraint from untrusted argv.
dms_dependency=$(python3 - "$manifest" <<'PYDEP'
import json,re,sys
from pathlib import Path
manifest=json.loads(Path(sys.argv[1]).read_text())
release=manifest.get('releaseId','')
if manifest.get('schema')!='greyward.dms-release/v1' or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]*',release):
    raise SystemExit('Invalid DMS package dependency receipt')
version,generation=release[1:].rsplit('-',1)
package_revision=manifest.get('build',{}).get('rpmRelease',generation)
if not isinstance(package_revision,str) or not re.fullmatch(re.escape(generation)+r'(?:\.[1-9][0-9]*)?',package_revision):
    raise SystemExit('Invalid DMS package-only revision')
print(version+'-'+package_revision)
PYDEP
)
test ! -e "$output"
mkdir -p "$output"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
printf '67fe996c4e5afd855fdbfbc3af0b05245667ec97666f463472a1961b46047f48  %s\n' "$input" | sha256sum --check --strict
cp "$input" "$output/SOURCES/labwc-0.9.6-canonical.tar"
source_tree="$output/BUILD/source-tree"
mkdir -p "$source_tree/packaging" "$source_tree/environment/production" \
 "$source_tree/security-center/packaging/application-security/desktop" \
 "$source_tree/security-center/packaging/application-security"
cp -a "$repo/packaging/greyward-enrollment" "$source_tree/packaging/"
cp -a "$repo/environment/production/selinux" "$source_tree/environment/production/"
for relative in \
 security-center/packaging/application-security/desktop/labwc-protected-input.patch \
 security-center/packaging/application-security/desktop/labwc-administration-indicator.patch \
 security-center/packaging/application-security/maintenance.py \
 security-center/packaging/application-security/greyward-maintenance.target \
 security-center/packaging/application-security/greyward-maintenance-console.service; do
 install -D -m 0644 "$repo/$relative" "$source_tree/$relative"
done
# Windows checkouts can have CRLF in SELinux policy files; normalize only this
# isolated package input tree before compiling or archiving it.
python3 "$repo/environment/image/stage-text.py" --stage "$source_tree"
tar --sort=name --mtime=@1791590400 --owner=0 --group=0 --numeric-owner \
 --transform='s,^,greyward-application-enrollment-0.1.0/,' -C "$source_tree" -czf "$output/SOURCES/greyward-application-enrollment-0.1.0.tar.gz" \
 packaging/greyward-enrollment environment/production/selinux \
 security-center/packaging/application-security/desktop/labwc-protected-input.patch \
 security-center/packaging/application-security/desktop/labwc-administration-indicator.patch \
 security-center/packaging/application-security/maintenance.py \
 security-center/packaging/application-security/greyward-maintenance.target \
 security-center/packaging/application-security/greyward-maintenance-console.service
cp "$repo/packaging/greyward-enrollment/greyward-enrollment.spec" "$output/SPECS/"
rpmbuild -bb --define "_topdir $output" --define "greyward_dms_dependency $dms_dependency" "$output/SPECS/greyward-enrollment.spec"
