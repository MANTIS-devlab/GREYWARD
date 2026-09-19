#!/usr/bin/env bash
set -euo pipefail
# Run in a network namespace with no interfaces. Also used by the builder
# against a completely empty user installation to prove dependency closure.
stage=$(realpath -e "$1")
scope="${2:---system}"
[[ "$scope" == --system || "$scope" == --user ]] || exit 2
test -r "$stage/offline/flathub.flatpakrepo"
test -d "$stage/offline/flatpak/.ostree/repo"
flatpak remote-add "$scope" --if-not-exists --from --disable \
  flathub "$stage/offline/flathub.flatpakrepo"
# The offline transaction must not even attempt Flathub metadata refresh.  The
# remote is restored on both success and failure so ordinary post-install
# updates retain the normal system Flathub source.
restore_flathub() {
  flatpak remote-modify "$scope" --enable flathub 2>/dev/null || true
}
trap restore_flathub EXIT
flatpak remote-modify "$scope" --disable flathub
offline_repo="$stage/offline/flatpak/.ostree/repo"
offline_uri="file://$offline_repo"
offline_remote=greyward-offline
# create-usb exports a partial collection mirror. The image factory publishes
# a local summary over ordinary heads, so clean targets resolve the refs from
# the ISO even when Flathub is unreachable. This remote is removed only after
# every selected commit has been installed; a failed retry keeps it available.
flatpak remote-add "$scope" --if-not-exists --no-gpg-verify "$offline_remote" "$offline_uri"
flatpak remote-modify "$scope" --no-gpg-verify --url="$offline_uri" "$offline_remote"
python3 "$stage/baseline.py" flatpak-args --baseline "$stage/artifacts/runtime-baseline.json" > "$stage/flatpak-baseline.tsv"
refs=()
commits=()
while IFS=$'\t' read -r ref commit; do
  refs+=("$ref")
  commits+=("$commit")
done < "$stage/flatpak-baseline.tsv"
test "${#refs[@]}" -gt 0
# The staged OSTree repository contains the complete verified closure. The
# caller runs this script in an empty network namespace, so one local
# transaction can install all selected refs without any HTTPS fallback. A
# single transaction avoids repeating Flatpak's repository and deployment
# setup for every application while preserving per-ref commit verification.
flatpak install "$scope" --noninteractive \
  --sideload-repo="$offline_repo" "$offline_remote" "${refs[@]}"
for index in "${!refs[@]}"; do
  test "$(flatpak info "$scope" --show-commit "${refs[$index]}")" = "${commits[$index]}"
done
flatpak remote-delete "$scope" --force "$offline_remote"
