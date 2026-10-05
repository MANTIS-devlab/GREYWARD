#!/usr/bin/env bash
set -euo pipefail
# Install only a local, already-built runtime RPM. Sources/patches belong to %prep.
test "$(id -u)" -eq 0
stage=$(cd "$(dirname "$0")" && pwd)
manifest="$stage/dms-release.json"
release=$(jq -er '.releaseId' "$manifest")
runtime="/usr/lib/greyward/dms/$release"
rpm_file=${GREYWARD_DMS_RPM:-}
if [[ -n "$rpm_file" ]]; then
  test -f "$rpm_file"
  test "$(rpm -qp --qf '%{NAME}' "$rpm_file")" = greyward-dms
  test "$(rpm -qp --qf '%{VERSION}' "$rpm_file")" = "$(jq -r '.dms.tag | ltrimstr("v")' "$manifest")"
  rpm -Uvh --replacepkgs "$rpm_file"
fi
test "$(rpm -q --qf '%{VERSION}' greyward-dms)" = "$(jq -r '.dms.tag | ltrimstr("v")' "$manifest")"
test -r "$runtime/release.json"
jq -e --slurpfile expected "$manifest" '.releaseId == $expected[0].releaseId and .inputs == $expected[0].inputs and .patches == $expected[0].patches and .shell == $expected[0].shell' "$runtime/release.json" >/dev/null
# The RPM replaces its default selector on upgrade; explicit activation also
# supports restoring a saved selector with the matching previous RPM.
if [[ "${GREYWARD_DMS_ACTIVATE:-0}" == 1 ]]; then
  install -d -m0755 /etc/greyward
  tmp=$(mktemp /etc/greyward/.dms-release.XXXXXX)
  trap 'rm -f "$tmp"' EXIT
  printf '%s\n' "$release" > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" /etc/greyward/dms-release
fi
/usr/libexec/greyward-dms-verify >/dev/null
rpm -qf /usr/local/bin/greyward-dms >/dev/null
# Retain the historical 1.5.3 payload and saved wrapper for rollback.
