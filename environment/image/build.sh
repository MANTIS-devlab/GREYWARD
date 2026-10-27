#!/usr/bin/env bash
set -euo pipefail

# Prepare the repository-owned inputs for the internal production image
# installer. It creates the exact stage layout consumed by
# environment/production/provision.sh and records source traceability. It is
# not a release builder and never includes the development overlay.

usage() {
  cat <<'EOF'
Usage: environment/image/build.sh [--output DIRECTORY] [--security-rpm FILE]... [--security-build-manifest FILE] [--security-source-root DIRECTORY] [--dms-rpm FILE] [--files-rpm FILE] [--production-rpm FILE]... [--enrollment-rpm FILE]... --branding-rpm FILE [--baseline FILE] [--dms-candidate] [--require-complete]

Without --security-rpm this prepares an incomplete development input set and
marks the missing production RPMs in the manifest. A production image tool
must supply twelve GREYWARD RPMs: greyward-branding, greyward-session,
greyward-security-center, greyward-security-context, greyward-dms,
greyward-application-security-experimental, greyward-application-enrollment,
greyward-files, and the four --office-rpm inputs, plus every pinned external production RPM listed in
environment/production/external-rpms.txt. Use
  --require-complete to reject an incomplete input set instead of preparing it
  for source inspection. Complete staging also requires the manifest emitted
  by environment/development/build-security-center.sh; it binds the RPMs to
  the source tree that produced them and prevents stale package drift. Pass
  --security-source-root when selected cached Security Center RPMs were built
  from a preserved source snapshot distinct from the current checkout.
EOF
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
output="$repo_root/output/greyward-production-inputs"
security_rpms=()
production_rpms=()
enrollment_rpms=()
office_rpms=()
branding_rpm=''
dms_rpm=''
session_rpm=''
files_rpm=''
security_build_manifest=''
security_source_root=''
baseline=''
require_complete=false
dms_candidate=false
# Package-file inspection does not need the host RPM database. When the image
# builder is launched through sudo, keep these read-only queries under the
# invoking user's namespace; a full or damaged host root must not turn a valid
# staged RPM into a false "missing asset" result.
rpm_query_user="${GREYWARD_RPM_QUERY_USER:-${SUDO_USER:-}}"
rpm_query() {
  if [[ "$(id -u)" -eq 0 && -n "$rpm_query_user" && "$rpm_query_user" != root ]] \
    && id "$rpm_query_user" >/dev/null 2>&1; then
    runuser -u "$rpm_query_user" -- /usr/bin/rpm "$@"
  else
    /usr/bin/rpm "$@"
  fi
}

while (($#)); do
  case "$1" in
    --dms-candidate) dms_candidate=true; shift ;;
    --office-rpm)
      (($# >= 2)) || exit 2
      office_rpms+=("$(realpath -e "$2")")
      shift 2
      ;;
    --enrollment-rpm)
      (($# >= 2)) || exit 2
      enrollment_rpms+=("$(realpath -e "$2")")
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
    --production-rpm)
      (($# >= 2)) || { usage >&2; exit 2; }
      production_rpms+=("$(realpath -e "$2")")
      shift 2
      ;;
    --session-rpm)
      (($# >= 2)) || exit 2
      [[ -z "$session_rpm" ]] || { echo 'Provide exactly one GREYWARD session RPM.' >&2; exit 2; }
      session_rpm=$(realpath -e "$2")
      test "$(rpm_query -qp --qf '%{NAME}' "$session_rpm")" = greyward-session
      shift 2
      ;;
    --files-rpm)
      (($# >= 2)) || { usage >&2; exit 2; }
      [[ -z "$files_rpm" ]] || { echo 'Provide exactly one GREYWARD Files RPM.' >&2; exit 2; }
      files_rpm=$(realpath -e "$2")
      test "$(rpm_query -qp --qf '%{NAME}' "$files_rpm")" = greyward-files || { echo 'Unexpected file-manager RPM.' >&2; exit 2; }
      shift 2
      ;;
    --dms-rpm)
      (($# >= 2)) || { usage >&2; exit 2; }
      [[ -z "$dms_rpm" ]] || { echo 'Duplicate DMS runtime RPM' >&2; exit 2; }
      dms_rpm=$(realpath -e "$2")
      test "$(rpm_query -qp --qf '%{NAME}' "$dms_rpm")" = greyward-dms
      shift 2
      ;;
    --branding-rpm)
      (($# >= 2)) || { usage >&2; exit 2; }
      [[ -z "$branding_rpm" ]] || { echo "Provide exactly one GREYWARD branding RPM." >&2; exit 2; }
      branding_rpm=$(realpath -e "$2")
      case "$(basename "$branding_rpm")" in greyward-branding-*.rpm) ;; *) echo "Unexpected branding RPM: $branding_rpm" >&2; exit 2 ;; esac
      shift 2
      ;;
    --security-build-manifest)
      (($# >= 2)) || { usage >&2; exit 2; }
      [[ -z "$security_build_manifest" ]] || { echo "Provide exactly one Security Center build manifest." >&2; exit 2; }
      security_build_manifest=$(realpath -e "$2")
      shift 2
      ;;
    --security-source-root)
      (($# >= 2)) || { usage >&2; exit 2; }
      security_source_root=$(realpath -e "$2")
      test -d "$security_source_root" || { echo 'Security source root must be a directory.' >&2; exit 2; }
      shift 2
      ;;
    --baseline)
      (($# >= 2)) || { usage >&2; exit 2; }
      baseline=$(realpath -e "$2")
      shift 2
      ;;
    --require-complete)
      require_complete=true
      shift
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

python3 "$repo_root/packaging/greyward-office/verify-inputs.py" --repo "$repo_root" --sources-only
if $require_complete || ((${#office_rpms[@]})); then
  office_args=()
  for rpm in "${office_rpms[@]}"; do office_args+=(--rpm "$rpm"); done
  python3 "$repo_root/packaging/greyward-office/verify-inputs.py" --repo "$repo_root" "${office_args[@]}"
fi

case "$output" in
  "$repo_root"|"$repo_root"/*) ;;
  *) echo "Refusing output outside the repository workspace: $output" >&2; exit 2 ;;
esac
test ! -e "$output" || { echo "Output already exists; choose a new directory: $output" >&2; exit 2; }

production="$repo_root/environment/production"
release_manifest="$production/dms-release.json"
plugin_source="$repo_root/environment/session/dankmaterialshell/plugins"
if $dms_candidate; then
  release_manifest="$production/dms-2.0-candidate.json"
  plugin_source="$repo_root/environment/session/dms-2.0-plugins"
fi
test -s "$release_manifest"
session="$repo_root/environment/session"
flatpak="$repo_root/environment/flatpak"
branding="$repo_root/branding"
patches="$repo_root/environment/patches"
kickstart="$repo_root/environment/image/installer.ks.tmpl"
security_context_unit="$repo_root/security-center/security-context/systemd/greyward-security-context-user.service"

if $require_complete && ((${#enrollment_rpms[@]} != 2)); then
  echo 'Complete staging requires the matched Application Security runtime and enrollment RPMs.' >&2
  exit 2
fi
declare -A enrollment_names=()
for rpm in "${enrollment_rpms[@]}"; do
  name=$(rpm_query -qp --qf '%{NAME}' "$rpm")
  case "$name" in greyward-application-security-experimental|greyward-application-enrollment) ;; *) echo 'Unexpected enrollment package' >&2; exit 2;; esac
  [[ -z "${enrollment_names[$name]:-}" ]] || { echo 'Duplicate enrollment package' >&2; exit 2; }
  enrollment_names[$name]=1
done
for required in \
  "$repo_root/packaging/greyward-enrollment/installer-accounts.py" \
  "$production/packages.txt" "$production/repositories.txt" \
  "$production/external-rpms.txt" \
  "$production/install-dms.sh" "$production/provision.sh" \
  "$production/configure-zsh.sh" "$production/zsh/sources.env" \
  "$production/zsh/zshrc" "$production/zsh/p10k.zsh" \
  "$production/zsh/greyward-terminal-brief.py" \
  "$production/production-acceptance.sh" \
  "$production/crypto-policy/GREYWARD.pmod" \
  "$production/desktop-entry-overrides/rygel-preferences.desktop" \
  "$production/desktop-entry-overrides/com.raggesilver.BlackBox.desktop" \
  "$production/blackbox/schemes/greyward-obsidian.json" \
  "$production/blackbox/schemes/dark-pastel.json" \
  "$production/blackbox/schemes/paraiso-dark.json" \
  "$production/blackbox/schemes/seti.json" \
  "$production/blackbox/schemes/vibrant-ink.json" \
  "$production/provision-firstboot.sh" "$production/provision-firstboot.service" \
  "$production/firstboot-status.sh" "$production/firstboot-status.service" \
  "$production/greyward-sync-greeter-wallpaper" \
  "$production/greyward-start-dms-greeter" \
  "$production/dms-greeter-ui/shell.qml" \
  "$production/dms-greeter-ui/Modules/Greetd/GreeterSurface.qml" \
  "$production/dms-greeter-ui/Modules/Greetd/GreeterContent.qml" \
  "$production/artifact-policy.json" "$production/dms-release.json" \
  "$production/security-center-contract.tsv" \
  "$security_context_unit" \
  "$session/dankmaterialshell/monitors.json" \
  "$production/labwc-autostart" \
  "$production/manifest.json" "$patches/dms/launcher-canonical-hitbox.patch" \
  "$patches/dms/greyward-desktop-shortcuts.patch" \
  "$patches/dms/polkit-auth-dialog.patch" \
  "$patches/dms/greyward-settings-curation.patch" \
  "$patches/dms/greyward-labwc-runtime.patch" \
  "$patches/dms/apps-dock-taskbar-labels.patch" \
  "$patches/dms/apps-dock-toggle-minimize.patch" \
  "$patches/dms/apps-dock-spacing.patch" \
  "$patches/dms/greyward-flatpak-icon-resolution.patch" \
  "$patches/dms/greyward-tray-icon-fallback.patch" \
  "$session/dankmaterialshell/settings.json" \
  "$session/dankmaterialshell/plugin_settings.json" \
  "$session/dankmaterialshell/plugins/greywardPublicIp/plugin.json" \
  "$session/dankmaterialshell/plugins/greywardPublicIp/PublicIpWidget.qml" \
  "$session/dankmaterialshell/plugins/greywardNetworkTraffic/plugin.json" \
  "$session/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficWidget.qml" \
  "$session/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficModel.qml" \
  "$session/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficMath.js" \
  "$session/dankmaterialshell/plugins/greywardSecure/plugin.json" \
  "$session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml" \
  "$session/dankmaterialshell/plugins/greywardSoftware/plugin.json" \
  "$session/dankmaterialshell/plugins/greywardSoftware/SoftwareWidget.qml" \
  "$session" "$session/labwc" "$session/dankmaterialshell" "$flatpak" \
  "$branding" "$branding/source/greyward-terminal.svg" \
  "$branding/wallpaper/greyward-wallpaper-black-art-4k.jpg" "$production/dconf" "$kickstart"; do
  test -e "$required" || { echo "Missing production input: $required" >&2; exit 1; }
done

# The ISO must install the DMS unit built from this checkout. A stale
# greyward-session RPM silently restores the absolute Wayland socket path and
# breaks DMS monitor configuration, even when the source unit is fixed.
if [[ -n "$session_rpm" ]]; then
  session_unit_path='./usr/lib/systemd/user/greyward-dms.service'
  session_migration_path='./usr/local/libexec/greyward-dms-state-migrate'
  session_pin_migration_path='./usr/local/libexec/greyward-dms-session-migrate'
  session_monitors_path='./usr/share/greyward/defaults/dankmaterialshell/monitors.json'
  session_autostart_path='./usr/share/greyward/defaults/labwc/autostart'
  session_labwc_path='./usr/share/greyward/defaults/labwc/rc.xml'
  if ! grep -Fqx 'Environment=WAYLAND_DISPLAY=wayland-0' "$session/greyward-dms.service"; then
    echo 'The source DMS unit must set WAYLAND_DISPLAY=wayland-0.' >&2
    exit 1
  fi
  if ! rpm2cpio "$session_rpm" | cpio -i --quiet --to-stdout "$session_unit_path" | cmp -s - "$session/greyward-dms.service"; then
    echo 'The greyward-session RPM contains a stale DMS unit; rebuild it from this checkout before ISO staging.' >&2
    exit 1
  fi
  if ! rpm2cpio "$session_rpm" | cpio -i --quiet --to-stdout "$session_migration_path" | cmp -s - "$session/greyward-dms-state-migrate"; then
    echo 'The greyward-session RPM contains stale DMS migration logic; rebuild it from this checkout before ISO staging.' >&2
    exit 1
  fi
  if ! rpm2cpio "$session_rpm" | cpio -i --quiet --to-stdout "$session_monitors_path" | cmp -s - "$session/dankmaterialshell/monitors.json"; then
    echo 'The greyward-session RPM lacks the current first-session display profile; rebuild it from this checkout before ISO staging.' >&2
    exit 1
  fi
  if ! rpm2cpio "$session_rpm" | cpio -i --quiet --to-stdout "$session_autostart_path" | cmp -s - "$production/labwc-autostart"; then
    echo 'The greyward-session RPM lacks the current VM display fallback; rebuild it from this checkout before ISO staging.' >&2
    exit 1
  fi
  if ! rpm2cpio "$session_rpm" | cpio -i --quiet --to-stdout "$session_pin_migration_path" | cmp -s - "$session/greyward-dms-session-migrate"; then
    echo 'The greyward-session RPM contains stale taskbar defaults; rebuild it from this checkout before ISO staging.' >&2
    exit 1
  fi
  # Retain native edge/corner snapping in the actual packaged defaults, not
  # just in the loose installer configuration or a development account.
  if ! rpm2cpio "$session_rpm" | cpio -i --quiet --to-stdout "$session_labwc_path" | cmp -s - "$session/labwc/rc.xml"; then
    echo 'The greyward-session RPM contains stale Labwc defaults (including window snapping); rebuild it before ISO staging.' >&2
    exit 1
  fi
  if $dms_candidate; then
    # BEGIN candidate visual payload contract
    (
    # Both the system theme DMS reads and the next-account Overview must match
    # canonical sources. A matching NEVRA alone cannot establish these bytes.
    # RPM can encode identical files as newc hard links, with the data only on
    # the last member. Extract this closed three-file set together in a private
    # directory; selecting each member with --to-stdout can return empty data.
    visual_contracts=(
      './usr/share/greyward/dms/greyward-obsidian.json|dankmaterialshell/greyward-obsidian.json'
      './usr/share/greyward/defaults/dankmaterialshell/greyward-obsidian.json|dankmaterialshell/greyward-obsidian.json'
      './usr/share/greyward/defaults/dms-2.0/experience.json|dms-2.0-defaults/experience.json'
    )
    visual_stage=$(mktemp -d -t greyward-visual-XXXXXXXX)
    trap 'rm -rf -- "$visual_stage"' EXIT
    rpm2cpio "$session_rpm" | (cd "$visual_stage"; cpio -id --quiet --no-absolute-filenames "${visual_contracts[@]%%|*}")
    for visual_contract in "${visual_contracts[@]}"; do
      visual_rpm_path=${visual_contract%%|*}
      visual_source_path=${visual_contract#*|}
      visual_file="$visual_stage/${visual_rpm_path#./}"
      if [[ ! -f "$visual_file" || -L "$visual_file" ]] || ! cmp -s "$visual_file" "$session/$visual_source_path"; then
        echo "The greyward-session RPM contains stale or missing visual defaults at $visual_rpm_path; rebuild it before ISO staging." >&2
        exit 1
      fi
    done
    )
    # END candidate visual payload contract
  fi
fi

if [[ -n "$files_rpm" ]]; then
  files_session_requirement='greyward-session >= 0.1.0-17'
  if ! rpm_query -qp --requires "$files_rpm" | grep -Fqx "$files_session_requirement"; then
    echo "The greyward-files RPM must retain its session compatibility requirement ($files_session_requirement)." >&2
    exit 1
  fi
  for file_contract in \
    './usr/bin/strata|/usr/bin/strata' \
    './usr/share/greyward/files/source.json|/usr/share/greyward/files/source.json' \
    './usr/lib/systemd/user/greyward-desktop-icons.service|/usr/lib/systemd/user/greyward-desktop-icons.service' \
    './usr/local/libexec/greyward-desktop-icons|/usr/local/libexec/greyward-desktop-icons' \
    './usr/local/libexec/greyward-desktop-shortcut|/usr/local/libexec/greyward-desktop-shortcut'; do
    rpm_path=${file_contract%%|*}
    source_path=${file_contract#*|}
    rpm_query -qpl "$files_rpm" | awk -v expected="$source_path" '$0 == expected { found = 1 } END { exit !found }' || {
      echo "The greyward-files RPM is missing required integration file $source_path." >&2
      exit 1
    }
    case "$source_path" in
      /usr/lib/systemd/user/greyward-desktop-icons.service) source_file="$repo_root/environment/session/greyward-desktop-icons.service" ;;
      /usr/local/libexec/greyward-desktop-icons) source_file="$repo_root/environment/session/greyward-desktop-icons" ;;
      /usr/local/libexec/greyward-desktop-shortcut) source_file="$repo_root/environment/session/greyward-desktop-shortcut" ;;
      /usr/bin/strata) source_file="$repo_root/environment/session/desktop/strata-launcher" ;;
      /usr/share/greyward/files/source.json) source_file="$repo_root/packaging/greyward-files/source.json" ;;
    esac
    if ! rpm2cpio "$files_rpm" | cpio -i --quiet --to-stdout "./${source_path#/}" | cmp -s - "$source_file"; then
      echo "The greyward-files RPM contains stale integration code at $source_path." >&2
      exit 1
    fi
  done
fi

if ((${#security_rpms[@]} > 2)); then
  echo "Too many Security Center RPMs; provide exactly one center and one context RPM." >&2
  exit 2
fi
center_count=0
context_count=0
for rpm in "${security_rpms[@]}"; do
  case "$(basename "$rpm")" in
    greyward-security-center-*.rpm) center_count=$((center_count + 1)) ;;
    greyward-security-context-*.rpm) context_count=$((context_count + 1)) ;;
    *) echo "Unexpected Security Center RPM name: $rpm" >&2; exit 2 ;;
  esac
done
if ((center_count > 1 || context_count > 1)); then
  echo "Duplicate Security Center package type; provide one center and one context RPM." >&2
  exit 2
fi
if $require_complete && ((center_count != 1 || context_count != 1)); then
  echo "Complete production staging requires one greyward-security-center RPM and one greyward-security-context RPM." >&2
  exit 2
fi
if $require_complete && [[ -z "$session_rpm" ]]; then
  echo "Complete staging requires a greyward-session RPM" >&2; exit 2
fi
if $require_complete && [[ -z "$files_rpm" ]]; then
  echo "Complete production staging requires one greyward-files RPM." >&2; exit 2
fi
if $require_complete && [[ -z "$dms_rpm" ]]; then
  echo "Complete production staging requires a verified greyward-dms RPM." >&2
  exit 2
fi
if $require_complete && [[ -z "$security_build_manifest" ]]; then
  echo "Complete production staging requires a Security Center artifact manifest." >&2
  exit 2
fi
if $require_complete; then
  if [[ -z "$session_rpm" || -z "$files_rpm" ]]; then
    echo "Complete production staging requires one greyward-session and one greyward-files RPM." >&2
    exit 2
  fi
  if ((${#enrollment_rpms[@]} != 2)); then
    echo "Complete production staging requires exactly one Application Security and one Enrollment RPM." >&2
    exit 2
  fi
  enrollment_count=0
  appsec_count=0
  for candidate in "${enrollment_rpms[@]}"; do
    case "$(rpm_query -qp --qf '%{NAME}' "$candidate")" in
      greyward-application-enrollment) enrollment_count=$((enrollment_count + 1)) ;;
      greyward-application-security-experimental) appsec_count=$((appsec_count + 1)) ;;
      *) echo "Unexpected enrollment/runtime package: $candidate" >&2; exit 2 ;;
    esac
  done
  if ((enrollment_count != 1 || appsec_count != 1)); then
    echo "Complete production staging requires exactly one RPM of each enrollment/runtime package." >&2
    exit 2
  fi
  selected_dms_version=$(rpm_query -qp --qf '%{VERSION}-%{RELEASE}' "$dms_rpm")
  expected_dms_requirement="greyward-dms = $selected_dms_version"
  enrollment_rpm=''
  appsec_rpm=''
  for candidate in "${enrollment_rpms[@]}"; do
    if [[ "$(rpm_query -qp --qf '%{NAME}' "$candidate")" == greyward-application-enrollment ]]; then
      enrollment_rpm=$candidate
    elif [[ "$(rpm_query -qp --qf '%{NAME}' "$candidate")" == greyward-application-security-experimental ]]; then
      appsec_rpm=$candidate
    fi
  done
  if [[ -z "$enrollment_rpm" ]] || ! rpm_query -qp --requires "$enrollment_rpm" | grep -Fqx "$expected_dms_requirement"; then
    echo "The enrollment RPM must require the selected DMS runtime exactly ($expected_dms_requirement)." >&2
    exit 1
  fi
  if [[ -z "$appsec_rpm" ]]; then
    echo 'The matching Application Security RPM is missing.' >&2
    exit 1
  fi
  selected_appsec_version=$(rpm_query -qp --qf '%{VERSION}-%{RELEASE}' "$appsec_rpm")
  expected_appsec_requirement="greyward-application-security-experimental = $selected_appsec_version"
  if [[ -z "$appsec_rpm" ]] || ! rpm_query -qp --requires "$enrollment_rpm" | grep -Fqx "$expected_appsec_requirement"; then
    echo "The enrollment RPM must require the selected Application Security runtime exactly ($expected_appsec_requirement)." >&2
    exit 1
  fi
  enrollment_runtime_path='./usr/libexec/greyward-enrollment'
  if ! rpm_query -qpl "$enrollment_rpm" | awk -v expected='/usr/libexec/greyward-enrollment' '$0 == expected { found = 1 } END { exit !found }'; then
    echo 'The enrollment RPM is missing its fixed enrollment runtime.' >&2
    exit 1
  fi
  if [[ "$(awk -F= '$1 == "schema" { print substr($0, index($0, "=") + 1); exit }' "$security_build_manifest")" == 'greyward.security-center-build/v1' ]] && \
     ! rpm2cpio "$enrollment_rpm" | cpio -i --quiet --to-stdout "$enrollment_runtime_path" | cmp -s - "$repo_root/packaging/greyward-enrollment/enroll.py"; then
    echo 'The enrollment RPM contains stale enrollment logic; rebuild it from this checkout before ISO staging.' >&2
    exit 1
  fi
fi
if $require_complete && [[ -z "$branding_rpm" ]]; then
  echo "Complete production staging requires one greyward-branding RPM." >&2
  exit 2
fi
if [[ -z "$security_source_root" ]]; then
  security_source_root="$repo_root/security-center"
fi
test -d "$security_source_root" || { echo 'Security Center source snapshot is missing.' >&2; exit 2; }
if [[ -n "$security_build_manifest" ]]; then
  test -r "$security_build_manifest"
fi
mapfile -t expected_production_rpms < <(awk -F'|' '!/^[[:space:]]*(#|$)/ {print $1}' "$production/external-rpms.txt")
for rpm in "${production_rpms[@]}"; do
  rpm_name=$(basename "$rpm")
  if ! printf '%s\n' "${expected_production_rpms[@]}" | grep -Fxq "$rpm_name"; then
    echo "Unexpected production dependency RPM name: $rpm_name" >&2
    exit 2
  fi
done
if $require_complete; then
  if ((${#production_rpms[@]} != ${#expected_production_rpms[@]})); then
    echo "Complete production staging requires every pinned external RPM listed in external-rpms.txt." >&2
    exit 2
  fi
  for expected in "${expected_production_rpms[@]}"; do
    found=false
    for rpm in "${production_rpms[@]}"; do
      if [[ "$(basename "$rpm")" == "$expected" ]]; then found=true; break; fi
    done
    $found || { echo "Missing pinned production dependency RPM: $expected" >&2; exit 2; }
  done
fi

mkdir -p "$output/patches" "$output/rpms"
cp -a "$production/packages.txt" "$production/repositories.txt" "$production/install-dms.sh" \
  "$production/external-rpms.txt" \
  "$production/configure-zsh.sh" "$production/install-offline-flatpaks.sh" \
  "$production/provision.sh" "$production/provision-firstboot.sh" \
  "$production/production-acceptance.sh" \
  "$production/provision-firstboot.service" "$production/firstboot-status.sh" \
  "$production/firstboot-status.service" "$production/greyward-sync-greeter-wallpaper" \
  "$production/greyward-start-dms-greeter" \
  "$production/manifest.json" \
  "$production/artifact-policy.json" "$production/security-center-contract.tsv" "$output/"
cp -a "$release_manifest" "$output/dms-release.json"
cp -a "$production/dms-greeter-ui" "$output/dms-greeter-ui"
mkdir -p "$output/desktop-entry-overrides"
cp -a "$production/desktop-entry-overrides/rygel-preferences.desktop" \
  "$output/desktop-entry-overrides/"
cp -a "$production/desktop-entry-overrides/com.raggesilver.BlackBox.desktop" \
  "$output/desktop-entry-overrides/"
mkdir -p "$output/blackbox/schemes"
cp -a "$production/blackbox/schemes/"*.json "$output/blackbox/schemes/"
mkdir -p "$output/zsh"
cp -a "$production/zsh/sources.env" "$production/zsh/zshrc" "$production/zsh/p10k.zsh" \
  "$production/zsh/greyward-terminal-brief.py" "$output/zsh/"
mkdir -p "$output/audit" "$output/selinux" "$output/crypto-policy"
cp -a "$production/crypto-policy/GREYWARD.pmod" "$output/crypto-policy/"
cp -a "$production/audit/greyward.rules" "$output/audit/"
cp -a "$production/selinux/greyward-dms-greeter.cil" "$output/selinux/"
# Keep the production stage deliberately curated.  The source session tree
# also contains the disposable VM's Labwc environment/autostart files; those
# force a software renderer and a Virtual-1 mode and must stay in the
# development overlay.  Production consumes the shared session helpers below
# plus the hardware-neutral files from environment/production.
mkdir -p "$output/session"
for session_file in \
  greyward-decoration.tokens.conf \
  greyward-display-power \
  greyward-dms \
  greyward-dms-state-migrate \
  greyward-dms-runtime-check \
  greyward-dms-session-migrate \
  greyward-dms.service \
  greyward-labwc.desktop \
  greyward-minimize.sh \
  greyward-restore.sh \
  greyward-session-lock \
  hyprland.conf; do
  cp -a "$session/$session_file" "$output/session/"
done
cp -a "$production/labwc-autostart" "$production/labwc-environment" "$output/"
cp -a "$production/greyward-start-labwc" "$output/"
cp -a "$production/dconf" "$output/dconf"
# DMS patches are build inputs already recorded in the runtime receipt.
# Labwc's compositor definition and theme are shared with the development VM,
# but its VM-only environment and autostart are intentionally not staged.
mkdir -p "$output/labwc/Greyward"
cp -a "$session/labwc/rc.xml" "$output/labwc/"
cp -a "$session/labwc/themerc" "$output/labwc/Greyward/"
cp -a "$session/labwc/Greyward"/*.svg "$output/labwc/Greyward/"
cp -a "$session/dankmaterialshell" "$output/dankmaterialshell"
rm -rf "$output/dankmaterialshell/plugins"
cp -a "$flatpak" "$output/flatpak"
cp -a "$branding" "$output/branding"
cp -a "$kickstart" "$output/installer.ks.tmpl"

if [[ -n "$dms_rpm" ]]; then cp -a "$dms_rpm" "$output/rpms/"; fi
if [[ -n "$session_rpm" ]]; then cp -a "$session_rpm" "$output/rpms/"; fi
if [[ -n "$files_rpm" ]]; then cp -a "$files_rpm" "$output/rpms/"; fi
if [[ -n "$branding_rpm" ]]; then cp -a "$branding_rpm" "$output/rpms/"; fi
for rpm in "${security_rpms[@]}"; do cp -a "$rpm" "$output/rpms/"; done
for rpm in "${production_rpms[@]}"; do cp -a "$rpm" "$output/rpms/"; done
for rpm in "${enrollment_rpms[@]}"; do cp -a "$rpm" "$output/rpms/"; done
for rpm in "${office_rpms[@]}"; do cp -a "$rpm" "$output/rpms/"; done
mkdir -p "$output/office-source/packaging/greyward-office" "$output/office-source/branding"
# Copy declared source types only: no interpreter caches or builder artifacts.
cp -a "$repo_root/packaging/greyward-office/"*.py \
  "$repo_root/packaging/greyward-office/"*.json \
  "$repo_root/packaging/greyward-office/"*.in \
  "$repo_root/packaging/greyward-office/patches" \
  "$repo_root/packaging/greyward-office/licenses" \
  "$repo_root/packaging/greyward-office/keys" \
  "$output/office-source/packaging/greyward-office/"
cp -a "$branding/source" "$output/office-source/branding/"
cp -a "$repo_root/packaging/greyward-enrollment/installer-accounts.py" "$output/"

mkdir -p "$output/artifacts"
if [[ -n "$baseline" ]]; then
  python3 "$repo_root/environment/image/baseline.py" stage --repo "$repo_root" \
    --baseline "$baseline" --destination "$output"
fi

security_manifest_value() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$security_build_manifest"
}

security_source_tree_sha256() {
  (
    cd "$security_source_root"
    LC_ALL=C find . -type f \
      ! -path '*/target/*' \
      ! -path '*/node_modules/*' \
      ! -path '*/__pycache__/*' ! -name '*.pyc' \
      ! -path './.git/*' \
      -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' file; do
        sha256sum "$file"
      done | sha256sum | awk '{print $1}'
  )
}

if $require_complete; then
  release_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["releaseId"])' "$release_manifest")
  receipt_path="./usr/lib/greyward/dms/$release_id/release.json"
  rpm2cpio "$dms_rpm" | cpio -i --quiet --to-stdout "$receipt_path" > "$output/artifacts/dms-build-manifest.json"
  python3 - "$release_manifest" "$output/artifacts/dms-build-manifest.json" <<'PY'
import json,sys
expected,actual=[json.load(open(p)) for p in sys.argv[1:]]
for key in ('schema','releaseId','dms','inputs','patches','shell','build','compatibility'):
    if key == 'build':
        if any(actual[key].get(k) != v for k,v in expected[key].items()): raise SystemExit('DMS build input mismatch')
    elif expected[key] != actual.get(key): raise SystemExit('DMS runtime receipt mismatch: '+key)
if not actual.get('binarySha256') or not actual.get('firstPartyFiles'): raise SystemExit('Incomplete DMS RPM receipt')
PY
  security_manifest_schema=$(security_manifest_value schema)
  case "$security_manifest_schema" in
    greyward.security-center-build/v1)
      test "$(security_manifest_value source_tree_sha256)" = "$(security_source_tree_sha256)"
      ;;
    greyward.security-center-installed-import/v1)
      python3 "$repo_root/environment/image/validate-installed-rpm-import.py" \
        --manifest "$security_build_manifest" \
        --rpm "$dms_rpm" --rpm "${security_rpms[0]}" --rpm "${security_rpms[1]}" \
        --rpm "${enrollment_rpms[0]}" --rpm "${enrollment_rpms[1]}"
      ;;
    *)
      echo "Unsupported Security Center artifact manifest schema: $security_manifest_schema" >&2
      exit 1
      ;;
  esac
  normalize_plugin_text() {
    python3 -c 'import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data if b"\0" in data else data.replace(b"\r\n", b"\n"))'
  }
  # Version agreement alone cannot detect an RPM built before the USB approval
  # entrypoint, focus or SELinux fixes. Compare the actual selected payloads.
  usb_context_rpm=''
  for candidate in "${security_rpms[@]}"; do
    if [[ "$(rpm_query -qp --qf '%{NAME}' "$candidate")" == greyward-security-context ]]; then
      usb_context_rpm=$candidate
    fi
  done
  test -n "$usb_context_rpm" || { echo 'USB approval requires the Security Context RPM.' >&2; exit 1; }
  # A migrated reference does not exercise first-install role assembly. Never
  # import its stale generator merely because its active seat verifies.
  python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind ordinary-role --rpm "$appsec_rpm"
  # Reference-only policy modules are absent from installed-RPM exports. Refuse
  # stale Flatpak session inputs on both source and imported artifact paths.
  python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind flatpak-session --rpm "$enrollment_rpm"
  python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind screenshot-enrollment --rpm "$enrollment_rpm"
  python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind screenshot-session --rpm "$session_rpm"
  python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind desktop-session --rpm "$session_rpm"
  if [[ "$security_manifest_schema" == 'greyward.security-center-build/v1' ]]; then
    python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind dms --rpm "$dms_rpm" --dms-manifest "$release_manifest"
    python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind context --rpm "$usb_context_rpm"
    python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind application-security --rpm "$appsec_rpm"
    python3 "$repo_root/environment/image/verify-usbguard-inputs.py" --repo "$repo_root" --kind enrollment --rpm "$enrollment_rpm"
  fi
  plugin_count=0
  if [[ "$security_manifest_schema" == 'greyward.security-center-build/v1' ]]; then
    while IFS= read -r -d '' plugin_file; do
      plugin_count=$((plugin_count + 1))
      plugin_relative=${plugin_file#"$plugin_source"/}
      rpm_plugin_path="./etc/xdg/quickshell/dms-plugins/$plugin_relative"
      if ! rpm2cpio "$dms_rpm" | cpio -i --quiet --to-stdout "$rpm_plugin_path" | normalize_plugin_text | \
        cmp -s - <(normalize_plugin_text < "$plugin_file"); then
        echo "The greyward-dms RPM contains a stale first-party plugin: $plugin_relative; rebuild it from this checkout before ISO staging." >&2
        exit 1
      fi
    done < <(find "$plugin_source" -type f -print0 | LC_ALL=C sort -z)
    if ((plugin_count == 0)); then
      echo 'No current first-party DMS plugins were found for RPM verification.' >&2
      exit 1
    fi
  fi
  for branding_path in \
    /usr/share/anaconda/pixmaps/greyward-anaconda-logo.png \
    /usr/share/anaconda/pixmaps/greyward-anaconda.css \
    /etc/anaconda/profile.d/greyward.conf \
    /etc/cockpit/branding/branding.css \
    /etc/cockpit/branding/greyward-symbol.svg; do
    rpm_query -qpl "$branding_rpm" | awk -v expected="$branding_path" '$0 == expected { found = 1 } END { exit !found }' || {
      echo "Branding RPM is missing required Anaconda asset: $branding_path" >&2
      exit 1
    }
  done
  if [[ "$security_manifest_schema" == 'greyward.security-center-build/v1' ]]; then
    test "$(security_manifest_value source_tree_sha256)" = "$(security_source_tree_sha256)"
  fi
  center_rpm=$(printf '%s\n' "${security_rpms[@]}" | grep '/greyward-security-center-' | head -n 1)
  context_rpm=$(printf '%s\n' "${security_rpms[@]}" | grep '/greyward-security-context-' | head -n 1)
  test "$(basename "$center_rpm")" = "$(security_manifest_value center_filename)"
  test "$(basename "$context_rpm")" = "$(security_manifest_value context_filename)"
  test "$(sha256sum "$center_rpm" | awk '{print $1}')" = "$(security_manifest_value center_sha256)"
  test "$(sha256sum "$context_rpm" | awk '{print $1}')" = "$(security_manifest_value context_sha256)"
  test "$(rpm_query -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$center_rpm")" = "$(security_manifest_value center_nevra)"
  test "$(rpm_query -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$context_rpm")" = "$(security_manifest_value context_nevra)"
  if [[ "$security_manifest_schema" == 'greyward.security-center-installed-import/v1' ]]; then
    for package_label in dms center context appsec enrollment; do
      case "$package_label" in
        dms) package_rpm="$dms_rpm" ;;
        center) package_rpm="$center_rpm" ;;
        context) package_rpm="$context_rpm" ;;
        appsec) package_rpm="$appsec_rpm" ;;
        enrollment) package_rpm="$enrollment_rpm" ;;
      esac
      test "$(basename "$package_rpm")" = "$(security_manifest_value ${package_label}_filename)"
      test "$(sha256sum "$package_rpm" | awk '{print $1}')" = "$(security_manifest_value ${package_label}_sha256)"
      test "$(rpm_query -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$package_rpm")" = "$(security_manifest_value ${package_label}_nevra)"
      test "$(rpm_query -qp --qf '%{SHA1HEADER}' "$package_rpm" | tr 'A-F' 'a-f')" = "$(security_manifest_value ${package_label}_header_sha1)"
    done
  fi

  while IFS='|' read -r package path; do
    [[ -z "$package" || "$package" == \#* ]] && continue
    case "$package" in
      greyward-security-center) package_rpm="$center_rpm" ;;
      greyward-security-context) package_rpm="$context_rpm" ;;
      *) echo "Unknown Security Center contract package: $package" >&2; exit 2 ;;
    esac
    rpm_query -qpl "$package_rpm" | awk -v expected="$path" '$0 == expected { found = 1 } END { exit !found }' || {
      echo "Security Center RPM contract is missing $path from $package." >&2
      exit 1
    }
  done < <(tr -d '\r' < "$production/security-center-contract.tsv")
  cp -a "$security_build_manifest" "$output/artifacts/security-center-build-manifest.tsv"
fi

# Source staging cannot resolve the final image's package NEVRAs or Flatpak
# commits. Emit deterministic records and mark them unresolved so host state
# cannot be mistaken for the installed image's state.
{
  printf 'kind\tname\trequested\tresolved\n'
  while IFS= read -r package; do
    [[ -z "$package" || "$package" == \#* ]] && continue
    printf 'rpm\t%s\t%s\tUNRESOLVED_AT_IMAGE_BUILD\n' "$package" "$package"
  done < <(tr -d '\r' < "$production/packages.txt")
  if [[ -n "$branding_rpm" ]]; then
    printf 'rpm\t%s\t%s\tGREYWARD_PACKAGE_INPUT\n' "$(basename "$branding_rpm")" "$(basename "$branding_rpm")"
  fi
  if [[ -n "$dms_rpm" ]]; then
    printf 'rpm\t%s\t%s\tGREYWARD_PACKAGE_INPUT\n' "$(basename "$dms_rpm")" "$(basename "$dms_rpm")"
  fi
  if [[ -n "$session_rpm" ]]; then
    printf 'rpm\t%s\t%s\tGREYWARD_PACKAGE_INPUT\n' "$(basename "$session_rpm")" "$(basename "$session_rpm")"
  fi
  if [[ -n "$files_rpm" ]]; then
    printf 'rpm\t%s\t%s\tGREYWARD_PACKAGE_INPUT\n' "$(basename "$files_rpm")" "$(basename "$files_rpm")"
  fi
  for rpm in "${enrollment_rpms[@]}"; do
    printf 'rpm\t%s\t%s\tGREYWARD_PACKAGE_INPUT\n' "$(basename "$rpm")" "$(basename "$rpm")"
  done
  for rpm in "${security_rpms[@]}"; do
    printf 'rpm\t%s\t%s\tNEVRA_REQUIRES_FEDORA_QUERY\n' "$(basename "$rpm")" "$(basename "$rpm")"
  done
  for rpm in "${office_rpms[@]}"; do
    printf 'rpm\t%s\t%s\tGREYWARD_PACKAGE_INPUT\n' "$(basename "$rpm")" "$(basename "$rpm")"
  done
  for rpm in "${production_rpms[@]}"; do
    printf 'rpm\t%s\t%s\tPINNED_EXTERNAL_INPUT\n' "$(basename "$rpm")" "$(basename "$rpm")"
  done
} > "$output/artifacts/package-inventory.txt"
{
  printf '# COPR build records are resolved by production provisioning; source staging does not query a host package database.\n'
  while IFS= read -r repository; do
    [[ -z "$repository" || "$repository" == \#* ]] && continue
    printf '%s\tBUILD_ID=UNRESOLVED_AT_IMAGE_BUILD\n' "$repository"
  done < <(tr -d '\r' < "$production/repositories.txt")
} > "$output/artifacts/copr-build-record.txt"
{
  printf 'application\tref\tcommit\tversion\n'
  while IFS='|' read -r application desktop; do
    [[ -z "$application" || "$application" == \#* ]] && continue
    printf '%s\tREF=UNRESOLVED_AT_IMAGE_BUILD\tCOMMIT=UNRESOLVED_AT_IMAGE_BUILD\tVERSION=UNRESOLVED_AT_IMAGE_BUILD\n' "$application"
  done < <(tr -d '\r' < "$flatpak/default-applications.list")
} > "$output/artifacts/flatpak-refs.tsv"
{
  printf '{\n'
  printf '  "schema": "greyward.internal-alpha-artifacts/v1",\n'
  printf '  "kind": "source-stage-inventory",\n'
  printf '  "licenses": "UNRESOLVED_AT_IMAGE_BUILD",\n'
  printf '  "sbom": "UNRESOLVED_AT_IMAGE_BUILD",\n'
  printf '  "note": "Resolve these records from the installed Fedora image; do not use source-host package state."\n'
  printf '}\n'
} > "$output/artifacts/license-sbom.json"

git_commit=UNKNOWN
git_dirty=false
if command -v git >/dev/null 2>&1; then
  git_commit=$(git -c safe.directory="$repo_root" -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'UNKNOWN')
  if [[ -n "$(git -c safe.directory="$repo_root" -C "$repo_root" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then git_dirty=true; fi
fi

sha256() { sha256sum "$1" | awk '{print $1}'; }
security_rpm_json=""
for rpm in "${security_rpms[@]}"; do security_rpm_json+="\"$(basename "$rpm")\","; done
security_rpm_json="${security_rpm_json%,}"
cat > "$output/build-manifest.json" <<EOF
{
  "schema": "greyward.production-image-inputs/v1",
  "purpose": "internal production image input staging; not an ISO or release artifact",
  "source_commit": "$git_commit",
  "source_dirty": $git_dirty,
  "production_manifest_sha256": "$(sha256 "$production/manifest.json")",
  "kickstart_template_sha256": "$(sha256 "$kickstart")",
  "artifact_policy_sha256": "$(sha256 "$production/artifact-policy.json")",
  "branding_rpm": "$(basename "${branding_rpm:-MISSING}")",
  "dms_rpm": "$(basename "${dms_rpm:-MISSING}")",
  "session_rpm": "$(basename "${session_rpm:-MISSING}")",
  "files_rpm": "$(basename "${files_rpm:-MISSING}")",
  "dms_release_manifest_sha256": "$(sha256 "$release_manifest")",
  "dms_candidate_selected": $dms_candidate,
  "security_rpm_count": ${#security_rpms[@]},
  "security_build_manifest": "$(if [[ -n "$security_build_manifest" ]]; then printf '%s' artifacts/security-center-build-manifest.tsv; else printf '%s' MISSING; fi)",
  "production_dependency_rpm_count": ${#production_rpms[@]},
  "enrollment_rpm_count": ${#enrollment_rpms[@]},
  "office_rpm_count": ${#office_rpms[@]},
  "production_inputs_complete": $([[ -n "$session_rpm" && -n "$files_rpm" && -n "$dms_rpm" && -n "$branding_rpm" && $center_count -eq 1 && $context_count -eq 1 && ${#enrollment_rpms[@]} -eq 2 && ${#office_rpms[@]} -eq 4 && ${#production_rpms[@]} -eq ${#expected_production_rpms[@]} ]] && printf true || printf false),
  "security_rpms": [$security_rpm_json],
  "artifacts": {
    "package_inventory": "artifacts/package-inventory.txt",
    "copr_build_record": "artifacts/copr-build-record.txt",
    "flatpak_refs": "artifacts/flatpak-refs.tsv",
    "license_sbom": "artifacts/license-sbom.json",
    "resolved_at_source_staging": false,
    "resolve_from_installed_image": true
  }
}
EOF

if [[ -z "$branding_rpm" || -z "$dms_rpm" || -z "$session_rpm" || -z "$files_rpm" ]] || ((${#security_rpms[@]} != 2 || ${#enrollment_rpms[@]} != 2 || ${#office_rpms[@]} != 4 || ${#production_rpms[@]} != ${#expected_production_rpms[@]})); then
  echo "WARNING: staged inputs are incomplete; provide all twelve GREYWARD RPMs and every pinned external RPM for production image construction." >&2
fi
# cp preserves Windows checkout line endings. Normalize only the staged source
# after provenance checks, before dependency building and payload hashing.
python3 "$repo_root/environment/image/stage-text.py" --stage "$output"
python3 "$repo_root/environment/image/verify-software-inputs.py" \
  --repo "$repo_root" --stage "$output"
printf 'Prepared GREYWARD production image inputs: %s\n' "$output"
