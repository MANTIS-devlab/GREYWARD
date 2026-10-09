#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
output=${1:?Usage: build.sh NEW-OUTPUT}
test ! -e "$output"
mkdir -p "$output"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
tar -C "$repo" -czf "$output/SOURCES/greyward-session.tar.gz" environment/session environment/production/greyward-start-labwc environment/production/labwc-environment environment/production/labwc-autostart environment/flatpak/labwc-portals.conf environment/flatpak/greyward-portal-backends.conf
cp "$repo/packaging/greyward-session/greyward-session.spec" "$output/SPECS/"
rpmbuild --define "_topdir $(realpath "$output")" -ba "$output/SPECS/greyward-session.spec"
