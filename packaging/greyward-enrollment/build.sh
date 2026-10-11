#!/bin/bash
# Offline package build only. No installation, policy load or account mutation.
set -euo pipefail
test "$(id -u)" != 0
repo=$(cd "$(dirname "$0")/../.." && pwd)
input=$(realpath -e "$1")
output=$(realpath -m "$2")
test ! -e "$output"
mkdir -p "$output"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
printf '67fe996c4e5afd855fdbfbc3af0b05245667ec97666f463472a1961b46047f48  %s\n' "$input" | sha256sum --check --strict
cp "$input" "$output/SOURCES/labwc-0.9.6-canonical.tar"
tar --sort=name --mtime=@1791590400 --owner=0 --group=0 --numeric-owner \
 --transform='s,^,greyward-application-enrollment-0.1.0/,' -C "$repo" -czf "$output/SOURCES/greyward-application-enrollment-0.1.0.tar.gz" \
 packaging/greyward-enrollment environment/production/selinux \
 security-center/packaging/application-security/desktop/labwc-protected-input.patch \
 security-center/packaging/application-security/desktop/labwc-administration-indicator.patch \
 security-center/packaging/application-security/maintenance.py \
 security-center/packaging/application-security/greyward-maintenance.target \
 security-center/packaging/application-security/greyward-maintenance-console.service
cp "$repo/packaging/greyward-enrollment/greyward-enrollment.spec" "$output/SPECS/"
rpmbuild -bb --define "_topdir $output" "$output/SPECS/greyward-enrollment.spec"
