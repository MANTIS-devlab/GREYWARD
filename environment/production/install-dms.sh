#!/usr/bin/env bash
set -euo pipefail

# Reproducible GREYWARD DMS foundation. Keep this version and digest aligned
# with docs/decisions/DANK_UPSTREAM.md; never replace the tag with latest or *-git.
readonly DMS_VERSION='v1.5.3'
readonly DMS_COMMIT='069ddab041c738236a8910e4c39b65d9628d3018'
readonly DMS_ARCHIVE_SHA256='ed543447b98568a092845164ea9cc20538ed8efa421214fba2969ab1b90a3f53'
readonly DMS_URL="https://github.com/AvengeMedia/DankMaterialShell/releases/download/${DMS_VERSION}/dms-full-amd64.tar.gz"
readonly DMS_ROOT="/usr/local/share/greyward-dms/${DMS_VERSION}"
readonly DMS_PATCH_DIR="${GREYWARD_DMS_PATCH_DIR:-/tmp/greyward-dms-patches}"

test "$(id -u)" -eq 0
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

if [[ -n "${GREYWARD_DMS_ARCHIVE:-}" ]]; then
  cp -- "$GREYWARD_DMS_ARCHIVE" "$tmp_dir/dms-full-amd64.tar.gz"
elif [[ "${GREYWARD_OFFLINE_INSTALL:-0}" == 1 ]]; then
  echo 'The offline DMS archive is missing; installation cannot continue.' >&2
  exit 1
else
  curl --fail --location --proto '=https' --tlsv1.2 "$DMS_URL" -o "$tmp_dir/dms-full-amd64.tar.gz"
fi
printf '%s  %s\n' "$DMS_ARCHIVE_SHA256" "$tmp_dir/dms-full-amd64.tar.gz" | sha256sum -c -
tar -xzf "$tmp_dir/dms-full-amd64.tar.gz" -C "$tmp_dir"
test -x "$tmp_dir/bin/dms"
test "$(tr -d '[:space:]' < "$tmp_dir/dms/VERSION")" = "$DMS_VERSION"

rm -rf "$DMS_ROOT"
install -d -m 0755 "$DMS_ROOT/bin" "$DMS_ROOT/quickshell"
install -m 0755 "$tmp_dir/bin/dms" "$DMS_ROOT/bin/dms"
cp -a "$tmp_dir/dms" "$DMS_ROOT/quickshell/dms"
for dms_patch in "$DMS_PATCH_DIR"/*.patch; do
  [[ -f "$dms_patch" ]] || continue
  patch --directory="$DMS_ROOT" --forward --batch -p1 < "$dms_patch"
done
printf '%s\n' "$DMS_VERSION" > "$DMS_ROOT/VERSION"
printf '%s\n' "$DMS_COMMIT" > "$DMS_ROOT/COMMIT"
printf '%s\n' "$DMS_ARCHIVE_SHA256" > "$DMS_ROOT/SOURCE_SHA256"

install -d -m 0755 /usr/local/bin
cat > /usr/local/bin/greyward-dms <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root=/usr/local/share/greyward-dms/v1.5.3
export PATH="$root/bin:/usr/local/bin:/usr/bin:/bin"
export XDG_DATA_DIRS="$root:/usr/local/share:/usr/share${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}"
exec "$root/bin/dms" "$@"
EOF
chmod 0755 /usr/local/bin/greyward-dms
