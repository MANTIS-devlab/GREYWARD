#!/usr/bin/env bash
set -euo pipefail

# Build the internal GREYWARD installer ISO. This is intentionally based on
# Fedora Everything/netinst media, not on a Workstation/live desktop: Anaconda
# owns storage, encryption, account creation, and the final reboot. The
# production stage is embedded on the media and is applied to the installed
# target by the Kickstart/first-boot path.

usage() {
  cat <<'EOF'
Usage: environment/image/build-iso.sh --base-iso FILE --output FILE \
  --branding-rpm FILE --security-rpm FILE --security-rpm FILE \
  --security-build-manifest FILE --production-rpm FILE... \
  --baseline FILE --base-sha256 SHA256

The base ISO must be Fedora Everything/netinst media with an Anaconda stage2.
Do not pass a Fedora Workstation/KDE live ISO: those profiles may hide the
Anaconda account page and delegate account creation to a first-boot setup
agent, which GREYWARD deliberately does not ship. The output is an internal
GREYWARD installer ISO: it boots directly into graphical Anaconda and has no
live desktop or temporary live account.
EOF
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
stage_validator="$repo_root/environment/image/validate-production-stage.sh"
work_root="${GREYWARD_ISO_WORK_ROOT:-$repo_root}"
base_iso=''
output=''
security_rpms=()
production_rpms=()
branding_rpm=''
security_build_manifest=''
baseline=''
base_sha256=''

# mkksiso/mkefiboot must run as root.  Re-exec the complete canonical build
# non-interactively instead of merely checking sudo and failing at the final
# composition step after the expensive dependency work has completed.
if [[ "$(id -u)" != 0 ]]; then
  sudo -n true || { echo 'ISO composition requires noninteractive sudo.' >&2; exit 1; }
  exec sudo -n env "GREYWARD_ISO_WORK_ROOT=$work_root" bash "$0" "$@"
fi

while (($#)); do
  case "$1" in
    --baseline) (($# >= 2)) || exit 2; baseline=$(realpath -e "$2"); shift 2 ;;
    --base-sha256) (($# >= 2)) || exit 2; base_sha256="$2"; shift 2 ;;
    --base-iso)
      (($# >= 2)) || { usage >&2; exit 2; }
      base_iso=$(realpath -e "$2")
      shift 2
      ;;
    --output)
      (($# >= 2)) || { usage >&2; exit 2; }
      output=$(realpath -m "$2")
      shift 2
      ;;
    --security-rpm)
      (($# >= 2)) || { usage >&2; exit 2; }
      security_rpms+=("$(realpath -e "$2")")
      shift 2
      ;;
    --branding-rpm)
      (($# >= 2)) || { usage >&2; exit 2; }
      [[ -z "$branding_rpm" ]] || { usage >&2; exit 2; }
      branding_rpm=$(realpath -e "$2")
      shift 2
      ;;
    --security-build-manifest)
      (($# >= 2)) || { usage >&2; exit 2; }
      [[ -z "$security_build_manifest" ]] || { usage >&2; exit 2; }
      security_build_manifest=$(realpath -e "$2")
      shift 2
      ;;
    --production-rpm)
      (($# >= 2)) || { usage >&2; exit 2; }
      production_rpms+=("$(realpath -e "$2")")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$base_iso" && -n "$output" && -n "$branding_rpm" && -n "$security_build_manifest" && ${#security_rpms[@]} -eq 2 && ${#production_rpms[@]} -ge 1 ]] || { usage >&2; exit 2; }
[[ "$(basename "$branding_rpm")" == greyward-branding-*.rpm ]] || { echo "Invalid branding RPM." >&2; exit 2; }
[[ -f "$base_iso" ]] || { echo "Base ISO not found: $base_iso" >&2; exit 1; }
[[ ! -e "$output" ]] || { echo "Output already exists: $output" >&2; exit 2; }
[[ -n "$baseline" && "$base_sha256" =~ ^[0-9a-fA-F]{64}$ ]] || {
  echo 'A captured --baseline and verified vendor --base-sha256 are required.' >&2; exit 2;
}
printf '%s  %s\n' "$base_sha256" "$base_iso" | sha256sum -c -

for command in mkksiso xorriso rpm rpmkeys rpm2cpio cpio tar gzip sha256sum awk sed realpath python3 find sort xargs df cmp createrepo_c dnf5 flatpak git curl unshare; do
  command -v "$command" >/dev/null || { echo "Required command not found: $command" >&2; exit 1; }
done
bash -n "$stage_validator"
# The checkout can live on Windows and therefore carry CRLF source files. The
# canonical stager normalizes these files before hashing; syntax-check the same
# normalized bytes here instead of rejecting an otherwise valid source checkout.
check_shell_syntax() {
  local path=$1
  tr -d '\r' < "$path" | bash -n
}
check_shell_syntax "$repo_root/environment/production/provision-firstboot.sh"
check_shell_syntax "$repo_root/environment/production/provision.sh"
check_shell_syntax "$repo_root/environment/production/install-offline-flatpaks.sh"
python3 -c 'import rpm, libdnf5'
if [[ "$(id -u)" != 0 ]]; then
  sudo -n true || { echo 'Offline dependency validation requires noninteractive sudo.' >&2; exit 1; }
fi
[[ -d "$work_root" ]] || { echo "ISO work root is not a directory." >&2; exit 1; }
mkdir -p "$(dirname "$output")"
[[ ! -e "$output.manifest.json" && ! -e "$output.sha256" ]] || {
  echo 'Output sidecars already exist; choose a new output name.' >&2; exit 2;
}
for directory in "$work_root" "$repo_root" "$(dirname "$output")"; do
  available=$(df -Pk "$directory" | awk 'END {print $4}')
  [[ "$available" -ge 41943040 ]] || { echo "At least 40 GiB free required at $directory for standalone media and dependency validation." >&2; exit 1; }
done

# Fedora Workstation media intentionally suppress the account page because
# GNOME Initial Setup owns account creation after reboot. GREYWARD removes that
# path, so accepting such media would recreate the no-account/CLI failure. The
# Fedora Everything/netinst volume id starts with Fedora-E-; reject other
# product media before doing the expensive staging and ISO compose.
base_volume_id=$(xorriso -indev "$base_iso" -pvd_info 2>&1 | awk -F"'" '/Volume id/ { print $2; exit }')
if [[ "$base_volume_id" != Fedora-E-* ]]; then
  echo "Unsupported base ISO volume id '$base_volume_id'. Use Fedora Everything/netinst media (Fedora-E-*), not a Workstation/live ISO." >&2
  exit 2
fi

# build.sh is the only producer of the production payload. Keep the large
# stage, branding extraction, and mkksiso working tree on the native Linux
# filesystem selected by the caller; only the final ISO may be copied elsewhere.
stage=$(mktemp -d "$repo_root/.greyward-iso-stage.XXXXXX")
iso_tree=$(mktemp -d "$work_root/.greyward-installer-iso.XXXXXX")
branding_root=$(mktemp -d "$work_root/.greyward-installer-branding.XXXXXX")
publication=$(mktemp -d "$(dirname "$output")/.greyward-iso-publication.XXXXXX")
cleanup() { rm -rf "$stage" "$iso_tree" "$branding_root" "$publication"; }
trap cleanup EXIT

staging_args=(
  --output "$stage/production"
  --branding-rpm "$branding_rpm"
  --security-rpm "${security_rpms[0]}"
  --security-rpm "${security_rpms[1]}"
  --security-build-manifest "$security_build_manifest"
  --baseline "$baseline"
)
for rpm in "${production_rpms[@]}"; do
  staging_args+=(--production-rpm "$rpm")
done
bash "$repo_root/environment/image/build.sh" "${staging_args[@]}" --require-complete
# Inject only the GREYWARD GTK branding assets into Anaconda's supported
# updates.img mechanism. Do not replace Anaconda's account pages, storage
# logic, or stage2 code: Fedora's native Everything profile remains the owner
# of installation behavior. The full branding RPM remains in the target stage
# and is applied before the first installed-system LUKS unlock.
branding_payload="$branding_root/root"
mkdir -p "$branding_payload"
rpm2cpio "$branding_rpm" | (cd "$branding_payload" && cpio -idm --quiet)
# Stable RPM names must not disguise old branding. Match the actual installer
# and boot assets to this checkout, just as the Security Center manifest does.
while IFS='|' read -r source installed; do
  cmp "$repo_root/$source" "$branding_payload/$installed" || {
    echo "Branding RPM is stale: $installed. Rebuild branding from this source." >&2; exit 1;
  }
done <<'BRANDING'
packaging/greyward-branding/SOURCES/greyward-anaconda.conf|etc/anaconda/profile.d/greyward.conf
packaging/greyward-branding/SOURCES/greyward-anaconda.css|usr/share/anaconda/pixmaps/greyward-anaconda.css
branding/generated/boot/greyward-symbol-256.png|usr/share/anaconda/pixmaps/greyward-anaconda-logo.png
packaging/greyward-branding/SOURCES/greyward.script|usr/share/plymouth/themes/greyward/greyward.script
packaging/greyward-branding/SOURCES/greyward.plymouth|usr/share/plymouth/themes/greyward/greyward.plymouth
packaging/greyward-branding/SOURCES/greyward-update-status.service|usr/lib/systemd/system/greyward-update-status.service
BRANDING
for installer_branding_path in \
  etc/anaconda/profile.d/greyward.conf \
  usr/share/anaconda/pixmaps/greyward-anaconda-logo.png \
  usr/share/anaconda/pixmaps/greyward-anaconda.css; do
  test -s "$branding_payload/$installer_branding_path"
done
(
  cd "$branding_payload"
  printf '%s\n' \
    etc/anaconda/profile.d/greyward.conf \
    usr/share/anaconda/pixmaps/greyward-anaconda-logo.png \
    usr/share/anaconda/pixmaps/greyward-anaconda.css |
    cpio -o -H newc --quiet | gzip -9 > "$iso_tree/updates.img"
)

# Downloads happen here, never on the user's installation. The helper uses
# disposable package databases and tests the closure with networking absent.
if [[ "$(id -u)" == 0 ]]; then
  python3 "$repo_root/environment/image/build-offline.py" --stage "$stage/production"
else
  sudo -n python3 "$repo_root/environment/image/build-offline.py" --stage "$stage/production"
fi
# Hash the actual staged configuration, assets and RPM bytes, after baseline
# preferences have been applied. The installed first-boot gate verifies this.
(
  cd "$stage/production"
  find . -type f ! -name payload.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > payload.sha256
)
# Validate only after the offline repository, Flatpak inventory and payload
# manifest have been generated. This is the complete tree copied into the ISO.
bash "$stage_validator" "$stage/production"

# The target Kickstart resolves this tree from the mounted installer media
# (normally /run/install/repo/greyward, with controlled fallbacks). Keep the
# account hand-off artifacts out: a direct boot ISO has no disposable
# account and Anaconda creates the only user that will remain installed.
mkdir -p "$iso_tree/greyward"
cp -a "$stage/production" "$iso_tree/greyward/"
# Anaconda's CD-ROM source reads root repodata. Package URLs point to the one
# embedded payload; the first reboot uses that same repository after copying.
createrepo_c --outputdir "$iso_tree" --location-prefix greyward/production/offline/rpm \
  --groupfile "$iso_tree/greyward/production/offline/comps.xml" \
  "$iso_tree/greyward/production/offline/rpm"
if [[ "$(id -u)" == 0 ]]; then
  python3 "$repo_root/environment/image/build-offline.py" --verify-media-repo "$iso_tree"
else
  sudo -n python3 "$repo_root/environment/image/build-offline.py" --verify-media-repo "$iso_tree"
fi

awk -v stage="$stage" '
  {
    gsub("__GREYWARD_STAGE__", stage)
    print
  }
' "$repo_root/environment/image/installer.ks.tmpl" > "$iso_tree/installer.ks"

# mkksiso injects the Kickstart, production payload, and the minimal GTK
# branding image into every normal boot path. The menu remains useful for the explicit
# media-test/basic-graphics paths, while the default entry is unmistakably the
# GREYWARD installer.
# Hyper-V's basic Linux framebuffer can stay black when Anaconda starts its
# graphical stage with accelerated mode selection. Keep the normal installer
# entry conservative; the installed GREYWARD desktop keeps its native mode.
mkksiso \
  --tmp "$work_root" \
  --no-md5sum \
  --ks "$iso_tree/installer.ks" \
  --updates "$iso_tree/updates.img" \
  --cmdline 'inst.profile=greyward inst.geoloc=0' \
  --add "$iso_tree/greyward" \
  --add "$iso_tree/repodata" \
  --replace 'Install Fedora 44' 'Install GREYWARD OS' \
  --replace 'Test this media & install Fedora 44' 'Test GREYWARD media & install GREYWARD OS' \
  --replace 'set default="1"' 'set default="0"' \
  --replace 'linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=GREYWARD-INSTALLER-44 quiet' \
            'linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=GREYWARD-INSTALLER-44 nomodeset quiet' \
  --volid GREYWARD-INSTALLER-44 \
  "$base_iso" "$publication/image.iso"

# Inspect the embedded payload, not merely mkksiso's exit status. A failed
# compose/inspection never leaves a plausibly complete final ISO filename.
xorriso -osirrox on -indev "$publication/image.iso" \
  -extract /greyward/production "$publication/production"
(cd "$publication/production" && sha256sum --quiet -c payload.sha256)
bash "$stage_validator" "$publication/production"
# Exercise the same recursive copy boundary used by Anaconda. This catches a
# manifest/tree mismatch before a candidate is attached to a VM.
mkdir -p "$publication/payload-copy"
cp -a "$publication/production" "$publication/payload-copy/"
(cd "$publication/payload-copy/production" && sha256sum --quiet -c payload.sha256)
grep -Fq 'remote-modify "$scope" --disable flathub' \
  "$publication/production/install-offline-flatpaks.sh" || {
  echo 'Final ISO is missing the disabled Flathub offline guard.' >&2; exit 1;
}
if grep -Eq 'remote-add.*flathub[[:space:]]+https?://' \
  "$publication/production/install-offline-flatpaks.sh"; then
  echo 'Final ISO offline Flatpak helper contains a network Flathub remote.' >&2; exit 1
fi
grep -Fq 'tee -a "$log" "$console"' \
  "$publication/production/provision-firstboot.sh" || {
  echo 'Final ISO does not stream first-boot logs to tty1.' >&2; exit 1;
}
grep -Fq 'GREYWARD provisioning:' "$publication/production/provision.sh" || {
  echo 'Final ISO is missing provisioning phase markers.' >&2; exit 1;
}
cmp "$baseline" "$publication/production/artifacts/runtime-baseline.json" || \
  python3 - "$baseline" "$publication/production/artifacts/runtime-baseline.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2])), 'Embedded baseline mismatch'
PY
final_volume=$(xorriso -indev "$publication/image.iso" -pvd_info 2>&1 | awk -F"'" '/Volume id/ {print $2; exit}')
[[ "$final_volume" == GREYWARD-INSTALLER-44 ]]
python3 - "$publication" "$base_iso" "$baseline" "$branding_rpm" "$security_build_manifest" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
def sha(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
json.dump({'schema': 'greyward.iso-provenance/v1', 'iso_sha256': sha(root/'image.iso'),
           'base_iso_sha256': sha(sys.argv[2]), 'baseline_sha256': sha(sys.argv[3]),
           'branding_rpm_sha256': sha(sys.argv[4]), 'security_manifest_sha256': sha(sys.argv[5]),
           'payload_manifest_sha256': sha(root/'production/payload.sha256'),
           'offline_payload_sha256': sha(root/'production/offline/manifest.json'),
           'installation_requires_network': False,
           'installer_dependency_resolution_tested': True,
           'installed_system_tested': False}, open(root/'manifest.json', 'w'), indent=2)
PY
iso_sha256=$(sha256sum "$publication/image.iso" | awk '{print $1}')
printf '%s  %s\n' "$iso_sha256" "$(basename "$output")" > "$publication/image.sha256"
ln "$publication/manifest.json" "$output.manifest.json"
ln "$publication/image.sha256" "$output.sha256"
ln "$publication/image.iso" "$output"

printf 'GREYWARD installer ISO: %s\n' "$output"
printf 'SHA256: '
sha256sum "$output" | awk '{print $1}'
