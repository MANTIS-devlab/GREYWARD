#!/usr/bin/env bash
set -euo pipefail

# Validate the production tree copied by Anaconda. A checksum manifest alone
# cannot detect a file omitted before that manifest was generated, so this
# validator also reads the provisioner's literal staged-file contract.

stage=${1:-}
if [[ -z "$stage" || ! -d "$stage" ]]; then
  echo "Usage: $0 STAGE-DIRECTORY" >&2
  exit 2
fi

stage=$(realpath -e "$stage")
provision="$stage/provision.sh"
test -r "$provision" || { echo "Missing staged provisioner: $provision" >&2; exit 1; }

missing=()
require_file() {
  local relative=$1
  if [[ ! -r "$stage/$relative" ]]; then
    missing+=("$relative")
  fi
}

# These paths are consumed through variables or by first-boot code and are not
# all visible as literal "$stage/..." checks in provision.sh.
for required in \
  packages.txt repositories.txt external-rpms.txt install-dms.sh \
  install-offline-flatpaks.sh provision.sh provision-firstboot.sh \
  provision-firstboot.service firstboot-status.sh firstboot-status.service \
  production-acceptance.sh payload.sha256 manifest.json artifact-policy.json \
  security-center-contract.tsv offline/manifest.json \
  offline/rpm/repodata/repomd.xml offline/comps.xml \
  offline/installer-packages.ks offline/flatpak-inventory.tsv; do
  require_file "$required"
done

mapfile -t declared < <(
  sed -n -E 's/^[[:space:]]*test[[:space:]]+-r[[:space:]]+"\$stage\/([^"]+)".*$/\1/p' \
    "$provision" | LC_ALL=C sort -u
)
for relative in "${declared[@]}"; do
  [[ -n "$relative" ]] && require_file "$relative"
done

for package in greyward-security-center greyward-security-context greyward-branding; do
  shopt -s nullglob
  matches=("$stage/rpms/$package-"*.rpm)
  shopt -u nullglob
  if [[ "${#matches[@]}" -ne 1 ]]; then
    missing+=("rpms/$package-*.rpm (expected exactly one, found ${#matches[@]})")
  fi
done

if ((${#missing[@]})); then
  printf 'PRODUCTION_STAGE_VALIDATION=FAIL\n'
  printf 'MISSING_OR_INVALID: %s\n' "${missing[@]}"
  exit 1
fi

printf 'PRODUCTION_STAGE_VALIDATION=PASS\n'
printf 'STAGE=%s\n' "$stage"
printf 'DECLARED_PATHS=%d\n' "${#declared[@]}"
