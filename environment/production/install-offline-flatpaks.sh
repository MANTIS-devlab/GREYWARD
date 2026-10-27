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
# Keep the canonical origin on installed refs. A temporary remote followed by
# remote-delete --force leaves deployments pointing at a missing origin, which
# breaks later dependency transactions even when Flathub is enabled.
online_uri=https://dl.flathub.org/repo/
# The verified media supplies the local summary and exact captured commits.
# Restore the online URL and commit signature verification on success AND
# failure. Neither restoration command resolves metadata over the network.
restore_flathub() {
  flatpak remote-modify "$scope" --url="$online_uri" --gpg-verify --enable flathub
}
trap restore_flathub EXIT
offline_repo="$stage/offline/flatpak/.ostree/repo"
offline_uri="file://$offline_repo"
# create-usb exports a partial collection mirror. The image factory publishes
# a local summary over ordinary heads, so clean targets resolve the refs from
# the ISO even when Flathub is unreachable. Unsigned local-summary use is
# restricted to this verified media transaction, never retained for HTTPS.
flatpak remote-modify "$scope" --no-gpg-verify --url="$offline_uri" --enable flathub
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
  --sideload-repo="$offline_repo" flathub "${refs[@]}"
for index in "${!refs[@]}"; do
  test "$(flatpak info "$scope" --show-commit "${refs[$index]}")" = "${commits[$index]}"
  test "$(flatpak info "$scope" --show-origin "${refs[$index]}")" = flathub
done
