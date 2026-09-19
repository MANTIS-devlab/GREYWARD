#!/usr/bin/env bash
set -eEuo pipefail

# This is the installed-system boundary. It is deliberately independent of
# the development account and of Hyper-V access.
stage="${GREYWARD_PRODUCTION_STAGE:-/tmp/greyward-production}"
target_install="${GREYWARD_TARGET_INSTALL:-0}"
packages_file="$stage/packages.txt"
repositories_file="$stage/repositories.txt"
phase_file="$stage/provision-current-phase.txt"
failure_file="$stage/provision-failure.txt"
anaconda_closure_marker=/var/lib/greyward/installer/anaconda-package-closure-installed
current_phase='initializing'

greyward_record_failure() {
  local code="$1"
  local command="$2"
  local line="$3"
  {
    printf 'exit_code=%s\n' "$code"
    printf 'phase=%s\n' "$current_phase"
    printf 'line=%s\n' "$line"
    printf 'command=%s\n' "$command"
  } > "$failure_file"
}

trap 'greyward_record_failure "$?" "$BASH_COMMAND" "${BASH_LINENO[0]:-0}"' ERR

phase() {
  current_phase="$*"
  printf '%s\n' "$current_phase" > "$phase_file"
  printf '\n[%s] GREYWARD provisioning: %s\n' "$(date --iso-8601=seconds)" "$*"
}

# ISO finalization has exactly one package source. Future update repositories
# are installed below, but cannot be used by this shell's DNF transactions.
if [[ "${GREYWARD_OFFLINE_INSTALL:-0}" == 1 ]]; then
  test -r "$stage/offline/manifest.json"
  test -r "$stage/offline/rpm/repodata/repomd.xml"
  dnf() {
    unshare --net -- /usr/bin/dnf --disablerepo='*' \
      --repofrompath="greyward-media,file://$stage/offline/rpm" \
      --enablerepo=greyward-media --setopt=greyward-media.gpgcheck=0 "$@"
  }
fi
phase 'Validating the staged offline production payload'
test -r "$packages_file"
test -r "$repositories_file"
test -r "$stage/external-rpms.txt"
test -r "$stage/install-dms.sh"
test -r "$stage/production-acceptance.sh"
test -r "$stage/provision-firstboot.sh"
test -r "$stage/provision-firstboot.service"
test -r "$stage/firstboot-status.sh"
test -r "$stage/firstboot-status.service"
test -r "$stage/greyward-start-labwc"
test -r "$stage/desktop-entry-overrides/rygel-preferences.desktop"
test -r "$stage/desktop-entry-overrides/com.raggesilver.BlackBox.desktop"
test -r "$stage/blackbox/schemes/greyward-obsidian.json"
test -r "$stage/blackbox/schemes/dark-pastel.json"
test -r "$stage/blackbox/schemes/paraiso-dark.json"
test -r "$stage/blackbox/schemes/seti.json"
test -r "$stage/blackbox/schemes/vibrant-ink.json"
test -r "$stage/configure-zsh.sh"
test -r "$stage/zsh/sources.env"
test -r "$stage/zsh/zshrc"
test -r "$stage/zsh/p10k.zsh"
test -r "$stage/zsh/greyward-terminal-brief.py"
test -r "$stage/audit/greyward.rules"
test -r "$stage/selinux/greyward-dms-greeter.cil"
test -r "$stage/greyward-sync-greeter-wallpaper"
test -r "$stage/patch-uwsm-labwc.sh"
test -r "$stage/patches/dms/launcher-canonical-hitbox.patch"
test -r "$stage/patches/dms/polkit-auth-dialog.patch"
test -r "$stage/patches/dms/running-apps-icon-scale.patch"
test -r "$stage/patches/dms/greyward-settings-curation.patch"
test -r "$stage/patches/dms/greyward-labwc-runtime.patch"
test -r "$stage/patches/dms/apps-dock-taskbar-labels.patch"
test -r "$stage/patches/dms/apps-dock-toggle-minimize.patch"
test -r "$stage/patches/dms/apps-dock-spacing.patch"
test -r "$stage/patches/dms/disable-changelog.patch"
test -r "$stage/patches/dms/greyward-flatpak-icon-resolution.patch"
test -r "$stage/patches/dms/greyward-tray-icon-fallback.patch"
test -r "$stage/crypto-policy/GREYWARD.pmod"
test -r "$stage/security-center-contract.tsv"
test -r "$stage/security-context/greyward-security-context-user.service"

if [[ "$target_install" == 1 || "${GREYWARD_LOCAL_FINALIZE:-0}" != 1 ]]; then
  phase 'Preparing the offline RPM repository'
  # These repositories provide the compositor, shell runtime, and GREYWARD
  # greeter used by the current functional VM. They are part of the production
  # package inputs; compilers and other development tools remain in the overlay.
  if [[ "${GREYWARD_OFFLINE_INSTALL:-0}" == 1 ]]; then
    install -m 0644 "$stage/offline/keys/"*.gpg /etc/pki/rpm-gpg/
    install -m 0644 "$stage/offline/update-repos/"*.repo /etc/yum.repos.d/
  else
    dnf -y install dnf-plugins-core
    mapfile -t repositories < <(grep -Ev '^[[:space:]]*(#|$)' "$repositories_file")
    for repository in "${repositories[@]}"; do
      dnf -y copr enable "$repository"
    done
  fi

  # OpenSnitch is not packaged by Fedora or by one of the GREYWARD COPRs. The
  # image factory stages its hash-verified upstream RPM as a production input.
  # Install it without RPM scriptlets because this helper may run
  # inside an offline Anaconda root where systemd is not running; the final root
  # enables services below.
  shopt -s nullglob
  external_rpm_prefixes=(opensnitch-)
  phase 'Installing external production RPMs'
  for prefix in "${external_rpm_prefixes[@]}"; do
    external_rpms=("$stage/rpms/${prefix}"*.rpm)
    test "${#external_rpms[@]}" -eq 1
    external_name=$(basename "${external_rpms[0]}")
    external_hash=$(awk -F'|' -v name="$external_name" '$1 == name { print $3 }' "$stage/external-rpms.txt")
    test -n "$external_hash"
    printf '%s  %s\n' "$external_hash" "${external_rpms[0]}" | sha256sum -c -
    dnf -y --setopt=tsflags=noscripts install "${external_rpms[0]}"
  done
  shopt -u nullglob

  # Upgrades from the former development image may still have the old Tabby
  # RPM. Remove only that exact package; do not touch the user's old config.
  if rpm -q tabby-terminal >/dev/null 2>&1; then
    dnf -y remove --no-autoremove tabby-terminal
  fi

  mapfile -t packages < <(grep -Ev '^[[:space:]]*(#|$)' "$packages_file")
  anaconda_closure_ready=false
  if [[ -f "$anaconda_closure_marker" ]]; then
    missing_packages=()
    for package in "${packages[@]}"; do
      rpm -q "$package" >/dev/null 2>&1 || missing_packages+=("$package")
    done
    if (( ${#missing_packages[@]} == 0 )); then
      anaconda_closure_ready=true
      phase 'Using the verified Anaconda RPM closure from the installer media'
    else
      phase "Anaconda RPM closure incomplete; reconciling ${#missing_packages[@]} missing package(s)"
      printf 'GREYWARD provisioning: missing Anaconda packages: %s\n' "${missing_packages[*]}"
    fi
  fi
  if [[ "$anaconda_closure_ready" != true ]]; then
    if [[ -r "$stage/artifacts/runtime-baseline.json" ]]; then
      # Bring the base installer packages forward on retry/legacy roots. A
      # fresh Anaconda install already has the exact ISO-local closure and
      # takes the marker path above, avoiding this duplicate transaction.
      phase 'Updating the installed base packages from ISO media'
      dnf -y --refresh upgrade
    fi
    phase "Installing ${#packages[@]} GREYWARD production packages from ISO media"
    dnf -y install "${packages[@]}"
  fi

  # GREYWARD production layers a small, supported Fedora crypto-policy module
  # on DEFAULT. Keep RSA-2048 compatibility while removing legacy algorithms.
  test -x /usr/bin/update-crypto-policies
  install -D -m 0644 "$stage/crypto-policy/GREYWARD.pmod" /etc/crypto-policies/policies/modules/GREYWARD.pmod
  update-crypto-policies --set DEFAULT:GREYWARD
  test "$(update-crypto-policies --show)" = DEFAULT:GREYWARD
  update-crypto-policies --is-applied

  # Enable the GREYWARD audit baseline. Fedora's no-audit profile may be
  # present on inherited roots; remove only that explicit disabling input,
  # preserve unrelated administrator rules, and make our policy canonical.
  install -d -m 0750 /etc/audit/rules.d
  for disabled_rules in /etc/audit/rules.d/10-no-audit.rules /etc/audit/rules.d/audit.rules; do
    if [[ -f "$disabled_rules" ]] && grep -Eq '^[[:space:]]*-a[[:space:]]+task,never([[:space:]]|$)' "$disabled_rules"; then
      rm -f "$disabled_rules"
    fi
  done
  install -D -m 0640 "$stage/audit/greyward.rules" /etc/audit/rules.d/40-greyward.rules
  systemctl enable auditd.service audit-rules.service
  if auditctl -s | grep -q '^enabled 2'; then
    # The finalized policy cannot be changed until reboot. A retry after a
    # later provisioning step failed is safe when the expected rule is live.
    auditctl -l | grep -q -- '-w /etc/passwd -p wa -k identity' || {
      echo 'Audit policy is locked but is not the GREYWARD policy; reboot and repair before retrying.' >&2
      exit 1
    }
  else
    augenrules --load
  fi

  # Install the smallest GREYWARD SELinux adjustment for DMS Greeter. It
  # grants service-status metadata only and suppresses two known broad watch
  # probes; it does not grant root or /var file access.
  install -D -m 0644 "$stage/selinux/greyward-dms-greeter.cil" \
    /etc/selinux/targeted/greyward-dms-greeter.cil
  semodule -i /etc/selinux/targeted/greyward-dms-greeter.cil

  # UWSM's Labwc plugin writes a reload drop-in without creating its parent
  # directory. Apply the guarded, GREYWARD-owned runtime fix after uwsm is
  # installed and before the graphical session can start.
  install -D -m 0755 "$stage/patch-uwsm-labwc.sh" /usr/local/libexec/greyward-patch-uwsm-labwc
  /usr/local/libexec/greyward-patch-uwsm-labwc

  # SSH belongs to the development overlay only. Some Fedora package groups
  # or inherited target roots can still carry openssh-server, so remove the
  # package when present and disable both service names before acceptance.
  if rpm -q openssh-server >/dev/null 2>&1; then
    dnf -y remove --no-autoremove openssh-server
  fi
  systemctl disable sshd.service ssh.service 2>/dev/null || true

  # The branding and Security Center RPMs are required, image-staged production
  # inputs. Install them in one transaction after the Fedora closure so the
  # fresh-install path does not start three independent DNF solvers.
  # The branding RPM owns the
  # Plymouth script and the raster generated from the canonical SVG; Plymouth
  # remains presentation only and dracut keeps its normal text fallback.
  shopt -s nullglob
  branding_rpms=("$stage/rpms/greyward-branding-"*.rpm)
  shopt -u nullglob
  test "${#branding_rpms[@]}" -eq 1
  # Security Center uses Fedora's native DNF5 D-Bus provider for transactional
  # updates. Keep both the daemon packages and the D-Bus activation file explicit
  # so a future image cannot silently fall back to a CLI-only base.
  rpm -q dnf5daemon-server dnf5daemon-server-polkit
  test -f /usr/share/dbus-1/system-services/org.rpm.dnf.v0.service

  # The component builder supplies these RPMs. A production image must not be
  # considered complete if the Security Center or its context package is absent.
  shopt -s nullglob
  security_rpms=("$stage/rpms/greyward-security-center-"*.rpm "$stage/rpms/greyward-security-context-"*.rpm)
  shopt -u nullglob
  test "${#security_rpms[@]}" -eq 2
  dnf -y install "${branding_rpms[0]}" "${security_rpms[@]}"
  rpm -q greyward-branding plymouth-plugin-script
  plymouth-set-default-theme greyward
  dracut --regenerate-all --force
  for branding_path in \
    /usr/share/anaconda/pixmaps/greyward-anaconda-logo.png \
    /usr/share/anaconda/pixmaps/greyward-anaconda.css \
    /etc/anaconda/profile.d/greyward.conf \
    /etc/cockpit/branding/branding.css \
    /etc/cockpit/branding/greyward-symbol.svg; do
    test "$(rpm -qf --qf '%{NAME}' "$branding_path" 2>/dev/null)" = greyward-branding || {
      echo "Installed branding package does not own required Anaconda asset: $branding_path" >&2
      exit 1
    }
  done

  # The image stager validates the RPM inputs against the canonical component
  # build manifest. Repeat the installed-package contract here so a manually
  # assembled stage cannot silently omit a provider/helper or install a package
  # whose NEVRA differs from the artifact that was validated for the image.
  security_manifest="$stage/artifacts/security-center-build-manifest.tsv"
  security_manifest_value() {
    awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$security_manifest"
  }
  center_rpm=$(printf '%s\n' "${security_rpms[@]}" | grep '/greyward-security-center-' | head -n 1)
  context_rpm=$(printf '%s\n' "${security_rpms[@]}" | grep '/greyward-security-context-' | head -n 1)
  while IFS='|' read -r package path; do
    [[ -z "$package" || "$package" == \#* ]] && continue
    case "$package" in
      greyward-security-center) package_rpm="$center_rpm" ;;
      greyward-security-context) package_rpm="$context_rpm" ;;
      *) echo "Unknown Security Center contract package: $package" >&2; exit 2 ;;
    esac
    rpm -qpl "$package_rpm" | awk -v expected="$path" '$0 == expected { found = 1 } END { exit !found }' || {
      echo "Security Center RPM contract is missing $path from $package." >&2
      exit 1
    }
  done < "$stage/security-center-contract.tsv"
  if [[ "$target_install" == 1 ]]; then
    test -r "$security_manifest"
    test "$(security_manifest_value schema)" = 'greyward.security-center-build/v1'
    test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' greyward-security-center)" = "$(security_manifest_value center_nevra)"
    test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' greyward-security-context)" = "$(security_manifest_value context_nevra)"
  fi
fi

# The DMS archive and Flatpak applications need a running system
# environment. During Anaconda target installation they are completed by the
# one-shot first-boot finalizer below; ordinary provisioning keeps the
# original synchronous behavior.
if [[ "$target_install" != 1 ]]; then
  phase 'Installing the bundled DMS runtime and applying GREYWARD patches'
  # The DMS archive is a separately checked production input. Its builder and
  # patch are staged by the image factory, not installed as developer tooling.
  if [[ "${GREYWARD_OFFLINE_INSTALL:-0}" == 1 ]]; then
    export GREYWARD_DMS_ARCHIVE="$stage/offline/dms-full-amd64.tar.gz"
  fi
  GREYWARD_DMS_PATCH_DIR="$stage/patches/dms" bash "$stage/install-dms.sh"
fi

session="$stage/session"
labwc="$stage/labwc"
dms="$stage/dankmaterialshell"
flatpak="$stage/flatpak"
branding="$stage/branding"
wallpaper_variants="$branding/wallpaper"
desktop_wallpaper=/usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg
test -d "$session"
test -d "$labwc"
test -d "$dms"
test -d "$flatpak"
test -d "$branding"
test -d "$wallpaper_variants"
test -d "$stage/dconf"
test -r "$flatpak/default-applications.list"
test -r "$flatpak/mimeapps.list"
for dms_file in \
  "$dms/settings.json" \
  "$dms/plugin_settings.json" \
  "$dms/plugins/greywardPublicIp/plugin.json" \
  "$dms/plugins/greywardPublicIp/PublicIpWidget.qml" \
  "$dms/plugins/greywardNetworkTraffic/plugin.json" \
  "$dms/plugins/greywardNetworkTraffic/NetworkTrafficWidget.qml" \
  "$dms/plugins/greywardNetworkTraffic/NetworkTrafficModel.qml" \
  "$dms/plugins/greywardNetworkTraffic/NetworkTrafficMath.js" \
  "$dms/plugins/greywardSecure/plugin.json" \
  "$dms/plugins/greywardSecure/SecureWidget.qml" \
  "$dms/plugins/greywardSoftware/plugin.json" \
  "$dms/plugins/greywardSoftware/SoftwareWidget.qml"; do
  test -r "$dms_file"
done
test -r "$flatpak/brave-flags.conf"

install -d -m 0755 /etc/xdg /etc/xdg-desktop-portal /usr/share/greyward/bazaar /usr/share/greyward/dms \
  /usr/local/libexec /usr/local/share/applications
install -D -m 0755 "$stage/production-acceptance.sh" /usr/local/libexec/greyward-production-acceptance
install -D -m 0644 "$flatpak/labwc-portals.conf" /etc/xdg-desktop-portal/labwc-portals.conf
install -D -m 0644 "$flatpak/bazaar-main-runtime.yaml" /usr/share/greyward/bazaar/main.yaml
install -D -m 0644 "$flatpak/greyward-privacy-runtime.yaml" /usr/share/greyward/bazaar/greyward-privacy.yaml
install -D -m 0644 "$flatpak/greyward-software-banner.svg" /usr/share/greyward/bazaar/greyward-software-banner.svg
install -D -m 0644 "$branding/source/greyward-symbol.svg" /usr/share/greyward/bazaar/greyward-symbol.svg
install -D -m 0755 "$flatpak/greyward-software" /usr/local/libexec/greyward-software
install -D -m 0755 "$flatpak/greyward-software-selection" /usr/local/libexec/greyward-software-selection
install -D -m 0644 "$flatpak/software-runtime.desktop" /usr/local/share/applications/io.github.kolunmi.Bazaar.desktop
install -D -m 0644 "$flatpak/mimeapps.list" /etc/xdg/mimeapps.list
if [[ "$target_install" != 1 ]]; then
  if [[ "${GREYWARD_OFFLINE_INSTALL:-0}" == 1 ]]; then
    phase 'Installing bundled Flatpaks from the ISO only (network disabled)'
    unshare --net -- bash "$stage/install-offline-flatpaks.sh" "$stage"
  else
    flatpak remote-add --if-not-exists --system flathub https://dl.flathub.org/repo/flathub.flatpakrepo
    flatpak install --system --noninteractive flathub io.github.kolunmi.Bazaar

    # These are first-class production applications, not developer or Bazaar-only
    # recommendations. Keep the IDs in one repository-owned list so fresh images
    # and development deployments install the same set from system Flathub.
    mapfile -t default_flatpaks < <(awk -F'|' '!/^[[:space:]]*(#|$)/ {gsub(/[[:space:]]/, "", $1); print $1}' "$flatpak/default-applications.list")
    test "${#default_flatpaks[@]}" -eq 5
    flatpak install --system --noninteractive flathub "${default_flatpaks[@]}"
    if [[ -r "$stage/artifacts/runtime-baseline.json" ]]; then
      # Explicit commits reproduce the selected .149 application state. This is
      # an installation transaction, not a permanent update mask.
      python3 "$stage/baseline.py" flatpak-args --baseline "$stage/artifacts/runtime-baseline.json" > "$stage/flatpak-baseline.tsv"
      while IFS=$'\t' read -r ref commit; do
        flatpak install --system --noninteractive flathub "$ref"
        flatpak update --system --noninteractive --commit="$commit" "$ref"
      done < "$stage/flatpak-baseline.tsv"
    fi
  fi
  flatpak override --system --reset io.github.kolunmi.Bazaar
  flatpak override --system --filesystem=xdg-config/bazaar:ro io.github.kolunmi.Bazaar

  # Haruna is a local player by default. Its Flatpak sandbox can be given
  # network access later by an explicit user override when online features are
  # wanted; GREYWARD does not add any other application-specific overrides.
  flatpak override --system --reset org.kde.haruna
  flatpak override --system --unshare=network org.kde.haruna
fi

phase 'Applying post-Store desktop and session configuration'

# Keep Brave's Wayland decoration preference in the per-user Flatpak
# configuration, outside the application payload so app updates preserve it.
# Seed it for first-boot accounts even when Flatpak installation is deferred
# to the image's later account/application setup stage.
install -D -m 0644 "$flatpak/brave-flags.conf" /etc/skel/.var/app/com.brave.Browser/config/brave-flags.conf

# Labwc production defaults are hardware-neutral. The Hyper-V renderer and
# virtual-display commands remain in the development overlay only.
install -D -m 0644 "$labwc/rc.xml" /etc/skel/.config/labwc/rc.xml
install -D -m 0644 "$stage/labwc-environment" /etc/skel/.config/labwc/environment
install -D -m 0755 "$stage/labwc-autostart" /etc/skel/.config/labwc/autostart
install -D -m 0644 "$labwc/Greyward/themerc" /etc/skel/.local/share/themes/Greyward/labwc/themerc
find "$labwc/Greyward" -maxdepth 1 -type f -name '*.svg' -exec install -D -m 0644 {} /etc/skel/.local/share/themes/Greyward/labwc/ \;
install -D -m 0644 "$stage/dconf/00-greyward-appearance" /etc/dconf/db/local.d/00-greyward-appearance
install -D -m 0644 "$stage/dconf/50-greyward-blackbox" /etc/dconf/db/local.d/50-greyward-blackbox
dconf update

install -D -m 0644 "$session/greyward-dms.service" /etc/systemd/user/greyward-dms.service
install -D -m 0644 "$session/greyward-session-idle.service" /etc/systemd/user/greyward-session-idle.service
install -D -m 0755 "$session/greyward-dms-session-migrate" /usr/local/libexec/greyward-dms-session-migrate
install -D -m 0755 "$session/greyward-session-lock" /usr/local/bin/greyward-session-lock
install -D -m 0755 "$session/greyward-display-power" /usr/local/bin/greyward-display-power
install -D -m 0755 "$stage/greyward-start-labwc" /usr/local/libexec/greyward-start-labwc
# Hyprland remains a supported fallback, but its Polkit agent must not start
# in the canonical Labwc session. The upstream unit is D-Bus activatable, so
# package presence or a disabled [Install] section alone does not prevent it
# from winning the graphical-agent race. Keep it available only when an actual
# Hyprland session supplied its signature.
install -d -m 0755 /etc/systemd/user/hyprpolkitagent.service.d
cat > /etc/systemd/user/hyprpolkitagent.service.d/greyward-session-owner.conf <<'EOF'
[Unit]
ConditionEnvironment=HYPRLAND_INSTANCE_SIGNATURE
EOF
# Fedora wires the GNOME portal backend into every graphical session. Labwc
# has no Mutter service channel, so that eager activation adds a visible
# warning and cannot provide its GNOME-only interfaces. Leave the backend
# available for a real GNOME fallback session, but do not start it in Labwc.
install -d -m 0755 /etc/systemd/user/xdg-desktop-portal-gnome.service.d
cat > /etc/systemd/user/xdg-desktop-portal-gnome.service.d/greyward-session-owner.conf <<'EOF'
[Unit]
ConditionEnvironment=XDG_CURRENT_DESKTOP=GNOME
EOF
install -D -m 0644 "$session/greyward-labwc.desktop" /usr/share/wayland-sessions/greyward-labwc.desktop
# The installed product has one supported desktop entry: GREYWARD Labwc.
# The installer is a direct Anaconda environment, so GDM and GNOME Initial
# Setup are never used as a live-session hand-off or account-creation path.
# Rygel Preferences is an upstream service utility and is not a GREYWARD
# desktop application. A desktop-entry override keeps the runtime dependency
# intact while letting every standards-compliant launcher hide the entry.
install -D -m 0644 "$stage/desktop-entry-overrides/rygel-preferences.desktop" \
  /usr/local/share/applications/rygel-preferences.desktop
# Install the single user-facing Terminal entry over Black Box's upstream
# desktop ID. Keeping the real app ID makes DMS launcher and taskbar grouping
# deterministic while the visible product identity remains Terminal.
install -D -m 0644 "$stage/desktop-entry-overrides/com.raggesilver.BlackBox.desktop" \
  /usr/local/share/applications/com.raggesilver.BlackBox.desktop
# Retain old pinned launcher IDs without a second visible Terminal or a stale
# Kitty command. The compatibility entry is derived from the canonical source.
if test -f /usr/local/share/applications/greyward-terminal.desktop; then
  install -m 0644 "$stage/desktop-entry-overrides/com.raggesilver.BlackBox.desktop" /usr/local/share/applications/greyward-terminal.desktop
  printf '\nNoDisplay=true\n' >> /usr/local/share/applications/greyward-terminal.desktop
fi
install -D -m 0644 "$stage/blackbox/schemes/greyward-obsidian.json" \
  /usr/share/blackbox/schemes/greyward-obsidian.json
install -D -m 0644 "$stage/blackbox/schemes/dark-pastel.json" \
  /usr/share/blackbox/schemes/dark-pastel.json
install -D -m 0644 "$stage/blackbox/schemes/paraiso-dark.json" \
  /usr/share/blackbox/schemes/paraiso-dark.json
install -D -m 0644 "$stage/blackbox/schemes/seti.json" \
  /usr/share/blackbox/schemes/seti.json
install -D -m 0644 "$stage/blackbox/schemes/vibrant-ink.json" \
  /usr/share/blackbox/schemes/vibrant-ink.json
install -D -m 0644 "$branding/source/greyward-terminal.svg" \
  /usr/share/icons/hicolor/scalable/apps/greyward-terminal.svg
install -D -m 0755 "$stage/configure-zsh.sh" \
  /usr/local/libexec/greyward-configure-zsh
install -D -m 0644 "$stage/security-context/greyward-security-context-user.service" \
  /usr/lib/systemd/user/greyward-security-context-user.service
install -D -m 0755 "$stage/zsh/greyward-terminal-brief.py" \
  /usr/local/libexec/greyward-terminal-brief
install -D -m 0644 "$stage/zsh/sources.env" \
  /usr/share/greyward/zsh/sources.env
if [[ "${GREYWARD_OFFLINE_INSTALL:-0}" == 1 ]]; then
  test -f "$stage/offline/zsh-vendor/required"
  install -d -m 0755 /usr/share/greyward/zsh/vendor
  cp -a "$stage/offline/zsh-vendor/." /usr/share/greyward/zsh/vendor/
  chmod -R a+rX /usr/share/greyward/zsh/vendor
  test -d "$stage/offline/gitstatus"
  # gitstatusd may already be running when first-boot provisioning retries.
  # Copying over its executable truncates the active inode and fails with
  # `Text file busy`; stage each payload file and rename it into place so the
  # running process keeps its old inode while future shells see the new one.
  gitstatus_target=/usr/share/greyward/zsh/gitstatus
  gitstatus_stage=$(mktemp -d /usr/share/greyward/zsh/.gitstatus-stage.XXXXXX)
  cp -a "$stage/offline/gitstatus/." "$gitstatus_stage/"
  chmod -R a+rX "$gitstatus_stage"
  while IFS= read -r -d '' staged_file; do
    relative=${staged_file#"$gitstatus_stage/"}
    target_file="$gitstatus_target/$relative"
    install -d -m 0755 "$(dirname "$target_file")"
    mv -f -- "$staged_file" "$target_file"
  done < <(find "$gitstatus_stage" \( -type f -o -type l \) -print0)
  find "$gitstatus_stage" -depth -type d -empty -delete
fi
install -D -m 0644 "$stage/zsh/zshrc" /usr/share/greyward/zsh/zshrc
install -D -m 0644 "$stage/zsh/p10k.zsh" /usr/share/greyward/zsh/p10k.zsh
install -D -m 0644 "$stage/zsh/zshrc" /etc/skel/.zshrc
install -D -m 0644 "$stage/zsh/p10k.zsh" /etc/skel/.p10k.zsh
install -D -m 0644 "$dms/settings.json" /etc/skel/.config/DankMaterialShell/settings.json
install -D -m 0644 "$dms/greyward-obsidian.json" /etc/skel/.config/DankMaterialShell/greyward-obsidian.json
install -D -m 0644 "$dms/plugin_settings.json" /etc/skel/.config/DankMaterialShell/plugin_settings.json
install -D -m 0644 "$branding/source/greyward-symbol.svg" /etc/skel/.config/DankMaterialShell/greyward-symbol.svg
install -D -m 0644 "$dms/greyward-obsidian.json" /usr/share/greyward/dms/greyward-obsidian.json
install -D -m 0644 "$branding/source/greyward-symbol.svg" /usr/share/greyward/dms/greyward-symbol.svg
install -d -m 0755 /usr/share/backgrounds/greyward
find "$wallpaper_variants" -maxdepth 1 -type f -name 'greyward-wallpaper-*.jpg' -exec install -m 0644 {} /usr/share/backgrounds/greyward/ \;
test "$(find "$wallpaper_variants" -maxdepth 1 -type f -name 'greyward-wallpaper-*.jpg' | wc -l)" -eq 2
for wallpaper_file in \
  greyward-wallpaper-black-art-4k.jpg \
  greyward-wallpaper-2109-4k.jpg; do
  test -f "/usr/share/backgrounds/greyward/$wallpaper_file"
done
test -s "$desktop_wallpaper"
rm -f /etc/skel/.config/DankMaterialShell/greyward-wallpaper.png
ln -s /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg /etc/skel/.config/DankMaterialShell/greyward-wallpaper.png
find "$dms/plugins" -mindepth 2 -maxdepth 2 -type f -exec sh -c 'for file do relative=${file#"$1/"}; install -D -m 0644 "$file" "/etc/skel/.config/DankMaterialShell/$relative"; done' sh "$dms" {} +

# Anaconda creates the real account before the first-boot provisioner runs,
# so /etc/skel is no longer consumed for that account. Seed the actual human
# account(s) with the same canonical DMS/Labwc configuration while the
# production gate still prevents login. This is deliberately limited to the
# initial gated finalization path; no user data or existing history is read.
if [[ "$target_install" != 1 ]]; then
  phase 'Configuring the installed account, GREYWARD session and login gate'
  # Anaconda may leave the account with a temporary shell while finalizing the
  # user. The home path and UID identify the human account; the configurator
  # sets the final zsh shell below. Do not silently skip it because of the
  # pre-finalization shell field.
  mapfile -t production_users < <(awk -F: '$3 >= 1000 && $6 ~ /^\/home\// { print $1 }' /etc/passwd)
  for production_user in "${production_users[@]}"; do
    production_home=$(getent passwd "$production_user" | awk -F: '{ print $6 }')
    production_group=$(id -gn "$production_user")
    test -n "$production_home"
    /usr/local/libexec/greyward-configure-zsh "$production_user"
    # Anaconda or an earlier package may have created .local as root before
    # the account was finalized.  DMS writes its session state below
    # .local/state, so repair only the user-owned session roots here without
    # taking ownership of existing user data recursively.
    install -d -o "$production_user" -g "$production_group" -m 0700 \
      "$production_home/.local" "$production_home/.local/state" \
      "$production_home/.local/share" "$production_home/.local/share/themes"
    chown "$production_user:$production_group" "$production_home/.local" \
      "$production_home/.local/state" "$production_home/.local/share" \
      "$production_home/.local/share/themes"
    install -d -o "$production_user" -g "$production_group" -m 0700 \
      "$production_home/.config" "$production_home/.config/DankMaterialShell" \
      "$production_home/.config/labwc" "$production_home/.config/hypr" \
      "$production_home/.config/uwsm" \
      "$production_home/.config/greyward" \
      "$production_home/.local/share/themes/Greyward/labwc"
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$dms/settings.json" "$production_home/.config/DankMaterialShell/settings.json"
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$dms/greyward-obsidian.json" "$production_home/.config/DankMaterialShell/greyward-obsidian.json"
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$dms/plugin_settings.json" "$production_home/.config/DankMaterialShell/plugin_settings.json"
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$branding/source/greyward-symbol.svg" "$production_home/.config/DankMaterialShell/greyward-symbol.svg"
    rm -f "$production_home/.config/DankMaterialShell/greyward-wallpaper.png"
    ln -s /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg \
      "$production_home/.config/DankMaterialShell/greyward-wallpaper.png"
    find "$dms/plugins" -type f -print0 | while IFS= read -r -d '' file; do
      relative=${file#"$dms/"}
      install -D -o "$production_user" -g "$production_group" -m 0644 \
        "$file" "$production_home/.config/DankMaterialShell/$relative"
    done
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$labwc/rc.xml" "$production_home/.config/labwc/rc.xml"
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$stage/labwc-environment" "$production_home/.config/labwc/environment"
    install -o "$production_user" -g "$production_group" -m 0755 \
      "$stage/labwc-autostart" "$production_home/.config/labwc/autostart"
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$labwc/Greyward/themerc" "$production_home/.local/share/themes/Greyward/labwc/themerc"
    find "$labwc/Greyward" -maxdepth 1 -type f -name '*.svg' -exec install \
      -o "$production_user" -g "$production_group" -m 0644 {} \
      "$production_home/.local/share/themes/Greyward/labwc/" \;
    printf '%s\n' 'labwc' > "$production_home/.config/greyward/compositor"
    chown "$production_user:$production_group" "$production_home/.config/greyward/compositor"
    # UWSM keeps its compositor choice separately from GREYWARD's small
    # product marker.  Seed the canonical session for the newly created
    # production account so `uwsm start default` cannot inherit Fedora's
    # Hyprland fallback.  Do not overwrite an existing explicit choice on a
    # bounded retry of first-boot finalization.
    if [[ ! -e "$production_home/.config/uwsm/default-id" ]]; then
      printf '%s\n' 'greyward-labwc.desktop' > "$production_home/.config/uwsm/default-id"
      chown "$production_user:$production_group" "$production_home/.config/uwsm/default-id"
      chmod 0644 "$production_home/.config/uwsm/default-id"
    fi
    # Labwc is the canonical session. Keep the supported Hyprland fallback
    # fully configured as well, because a greeter/session choice must never
    # fall through to Hyprland's autogenerated config and its visible warning.
    # This is configuration only: it does not change the default compositor.
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$session/hyprland.conf" "$production_home/.config/hypr/hyprland.conf"
    install -o "$production_user" -g "$production_group" -m 0644 \
      "$session/greyward-decoration.tokens.conf" \
      "$production_home/.config/hypr/greyward-decoration.tokens.conf"
  done
fi

install -D -m 0644 "$session/hyprland.conf" /etc/skel/.config/hypr/hyprland.conf
install -D -m 0644 "$session/greyward-decoration.tokens.conf" /etc/skel/.config/hypr/greyward-decoration.tokens.conf
install -D -m 0755 "$session/greyward-minimize.sh" /etc/skel/.local/bin/greyward-minimize
install -D -m 0755 "$session/greyward-restore.sh" /etc/skel/.local/bin/greyward-restore
install -d -m 0755 /etc/skel/.config/greyward
printf '%s\n' 'labwc' > /etc/skel/.config/greyward/compositor
install -d -m 0755 /etc/skel/.config/uwsm
printf '%s\n' 'greyward-labwc.desktop' > /etc/skel/.config/uwsm/default-id

install -d -m 0755 /etc/greetd
phase 'Writing the GREYWARD login and first-boot boundary'
cat > /etc/greetd/config.toml <<'EOF'
[terminal]
vt = 1

[default_session]
user = "greeter"
command = "/usr/bin/env WLR_RENDERER=pixman WLR_RENDERER_ALLOW_SOFTWARE=1 WLR_NO_HARDWARE_CURSORS=1 WLR_DRM_NO_MODIFIERS=1 LIBGL_ALWAYS_SOFTWARE=1 QT_QUICK_BACKEND=software QSG_RHI_PREFER_SOFTWARE_RENDERER=1 QT_QPA_PLATFORM=wayland XDG_CURRENT_DESKTOP=Labwc:GREYWARD XDG_SESSION_DESKTOP=labwc XDG_CONFIG_HOME=/var/cache/dms-greeter/.config /usr/bin/dms-greeter --command labwc --no-save-session --no-save-username"
EOF
chown root:root /etc/greetd/config.toml
chmod 0644 /etc/greetd/config.toml
# DMS Greeter launches a separate Labwc compositor as the unprivileged
# greeter account. The command above carries the VMware-safe renderer settings
# only into that greeter process; they are not global service or user-session
# defaults.
getent passwd greeter >/dev/null
getent group greeter >/dev/null
install -d -o greeter -g greeter -m 2770 /var/cache/dms-greeter
install -o greeter -g greeter -m 0644 "$dms/settings.json" /var/cache/dms-greeter/settings.json
# The helper owns the persistent /var/cache/dms-greeter/greeter_wallpaper_override.jpg
# copy and is also called by greetd before every login-screen start.
install -D -m 0755 "$stage/greyward-sync-greeter-wallpaper" \
  /usr/local/libexec/greyward-sync-greeter-wallpaper
/usr/local/libexec/greyward-sync-greeter-wallpaper
install -d -m 0755 /etc/systemd/system/greetd.service.d
cat > /etc/systemd/system/greetd.service.d/greyward-wallpaper.conf <<'EOF'
[Service]
ExecStartPre=/usr/local/libexec/greyward-sync-greeter-wallpaper
EOF
if [[ "$target_install" != 1 ]]; then
  systemctl daemon-reload
fi

if [[ "$target_install" == 1 ]]; then
  # This path runs inside the installed root while Anaconda is building it.
  # There is no running systemd yet, so write the user-unit enablement
  # explicitly and leave display-manager selection to the first boot hand-off.
  install -d -m 0755 /etc/systemd/user/graphical-session.target.wants
  install -d -m 0755 /etc/systemd/user/default.target.wants
  ln -sfn ../greyward-dms.service /etc/systemd/user/graphical-session.target.wants/greyward-dms.service
  ln -sfn ../greyward-session-idle.service /etc/systemd/user/graphical-session.target.wants/greyward-session-idle.service
  ln -sfn /usr/lib/systemd/user/greyward-security-context-user.service /etc/systemd/user/graphical-session.target.wants/greyward-security-context-user.service
  ln -sfn /usr/lib/systemd/user/greyward-security-context-user.service /etc/systemd/user/default.target.wants/greyward-security-context-user.service
  systemctl --global enable greyward-update-center.service 2>/dev/null || true

  # Do not mask Initial Setup while Anaconda is still configuring the target.
  # Anaconda may inspect or enable this unit during its final system
  # configuration; masking it here makes the installation fail before the
  # account page can complete. The first-boot finalizer applies the mask after
  # Anaconda exits and before any user-facing login/setup service can start.

  # Finish the staged production inputs once the installed system has
  # booted. Install the canonical helper/service staged by build.sh; do not
  # maintain a second inline copy here because drift between the two paths
  # was the source of the first-boot race and the missing Initial Setup mask.
  install -D -m 0755 "$stage/provision-firstboot.sh" \
    /usr/local/libexec/greyward-production-firstboot
  install -D -m 0644 "$stage/provision-firstboot.service" \
    /etc/systemd/system/greyward-production-firstboot.service
  install -D -m 0755 "$stage/firstboot-status.sh" \
    /usr/local/libexec/greyward-firstboot-status
  install -D -m 0644 "$stage/firstboot-status.service" \
    /etc/systemd/system/greyward-firstboot-status.service
  install -d -m 0755 /etc/systemd/system/multi-user.target.wants
  ln -sfn ../greyward-production-firstboot.service /etc/systemd/system/multi-user.target.wants/greyward-production-firstboot.service
  ln -sfn ../firstboot-status.service /etc/systemd/system/multi-user.target.wants/greyward-firstboot-status.service
  # Ordering alone is not a safety boundary: if first-boot finalization fails,
  # systemd may still start the display manager and expose a half-configured
  # session. Gate both production greetd and the legacy Initial Setup unit
  # until the helper has completed. The helper removes these gates only after
  # production acceptance inputs have been installed successfully.
  install -d -m 0755 /etc/systemd/system/greetd.service.d /etc/systemd/system/initial-setup.service.d
  cat > /etc/systemd/system/greetd.service.d/greyward-production-firstboot.conf <<'EOF'
[Unit]
Requires=greyward-production-firstboot.service
After=greyward-production-firstboot.service
EOF
  cat > /etc/systemd/system/initial-setup.service.d/greyward-production-firstboot.conf <<'EOF'
[Unit]
Requires=greyward-production-firstboot.service
After=greyward-production-firstboot.service
EOF
else
  # Installed production finalization runs after system services are
  # available. The direct Anaconda workflow has no live account or wrapper.

  # The direct installer creates the only production account in Anaconda; no
  # account-handoff contract or live-installer artifacts are carried forward.
  # The native Anaconda workflow owns completion and reboot.
  rm -f /etc/systemd/system/getty@tty1.service.d/autologin.conf
  systemctl disable --now getty@tty1.service 2>/dev/null || true
  systemctl set-default graphical.target
  # The production login contract is greetd -> DMS Greeter -> Labwc. Remove
  # any residual GDM/Initial Setup packages after Anaconda has finished, with
  # autoremove disabled so unrelated desktop libraries and user applications
  # are not silently removed. DNF may also remove the package-owned GNOME
  # Wayland session as a direct dependent; acceptance verifies the result.
  setup_packages=()
  for package in gdm gnome-initial-setup gnome-session-wayland-session initial-setup initial-setup-gui; do
    if rpm -q "$package" >/dev/null 2>&1; then
      setup_packages+=("$package")
    fi
  done
  if (( ${#setup_packages[@]} > 0 )); then
    dnf remove --assumeyes --no-autoremove "${setup_packages[@]}"
  fi
  rm -f /usr/local/share/wayland-sessions/gnome.desktop
  # Anaconda has already created the first real account. Every installed
  # target, including first boot finalization, converges directly to the
  # production greetd/DMS/Labwc boundary; GDM is not part of the product.
  systemctl disable --now gdm.service 2>/dev/null || true
  systemctl --global enable greyward-dms.service
  systemctl --global enable greyward-session-idle.service
  systemctl --global enable greyward-security-context-user.service
  systemctl --global enable greyward-update-center.service
  # This branch runs from the first-boot finalizer after multi-user.target has
  # already been reached. `enable` alone only schedules these units for the
  # next boot, leaving the session Security Context with no live providers on
  # the first production login. Start provider services now and keep greetd
  # enabled-only until the gate is removed below.
  systemctl enable greetd
  phase 'Starting required production services'
  required_services=(
    NetworkManager
    bluetooth
    firewalld
    cups
    avahi-daemon
    greyward-opensnitch-control-plane
    opensnitch
    greyward-opensnitch-policy
    greyward-clamav-scan
    clamav-freshclam
    greyward-secure-dns
    usbguard
    usbguard-dbus
    greyward-auto-update.timer
  )
  for required_service in "${required_services[@]}"; do
    phase "Starting required production service: $required_service"
    # BlueZ is a required production capability when the machine exposes a
    # Bluetooth adapter, but its unit is conditionally skipped when no adapter
    # exists. VMware validation guests normally have no Bluetooth hardware;
    # do not turn that expected condition into a failed installation. On bare
    # metal with an adapter present, the normal strict start/active checks
    # below still apply.
    if [[ "$required_service" == bluetooth && ! -d /sys/class/bluetooth ]]; then
      phase 'Skipping conditionally applicable production service: bluetooth (no adapter present)'
      continue
    fi
    if ! timeout --foreground 120s systemctl enable --now "$required_service"; then
      greyward_record_failure 1 "systemctl enable --now $required_service" "${BASH_LINENO[0]:-0}"
      printf 'GREYWARD provisioning: required service failed: %s\n' "$required_service" >&2
      systemctl status --no-pager --full "$required_service" >&2 || true
      journalctl --no-pager -u "$required_service" -n 40 >&2 || true
      exit 1
    fi
    if ! timeout --foreground 30s systemctl is-active --quiet "$required_service"; then
      greyward_record_failure 1 "systemctl is-active --quiet $required_service" "${BASH_LINENO[0]:-0}"
      printf 'GREYWARD provisioning: required service is not active after start: %s\n' "$required_service" >&2
      systemctl status --no-pager --full "$required_service" >&2 || true
      journalctl --no-pager -u "$required_service" -n 40 >&2 || true
      exit 1
    fi
  done
  systemctl daemon-reload
fi

phase 'Recording installed image trace artifacts'
install -d -m 0755 /etc/greyward
printf '%s\n' 'GREYWARD production system definition installed' > /etc/greyward/production-system
artifact_dir=/var/lib/greyward/build-artifacts
install -d -m 0755 "$artifact_dir"
# The contract is needed by the installed acceptance gate on both the direct
# first boot path and any legacy target-install invocation. Keep it outside the
# target_install-only branch so a successful package transaction cannot be
# followed by a deterministic acceptance loop just because the metadata was
# omitted. The build manifest remains conditional for local finalization, where
# no image-build manifest is intentionally supplied.
install -D -m 0644 "$stage/security-center-contract.tsv" /usr/share/greyward/security-center-contract.tsv
if [[ -n "${security_manifest:-}" && -r "$security_manifest" ]]; then
  install -D -m 0644 "$security_manifest" "$artifact_dir/security-center-build-manifest.tsv"
fi

# Record what the installed image actually resolved. These are build-time
# trace artifacts, not runtime telemetry and not a substitute for a signed
# release manifest. Missing build metadata is recorded explicitly so an
# internal image cannot be mistaken for a fully traceable release.
rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > /etc/greyward-installed-nevras.txt
install -m 0644 /etc/greyward-installed-nevras.txt "$artifact_dir/package-inventory.txt"
if dnf repoquery --installed --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{REPOID}\n' 2>/dev/null | sort > "$artifact_dir/package-sources.tsv"; then
  :
else
  printf '%s\n' 'UNRESOLVED: dnf repoquery could not provide installed package source metadata.' > "$artifact_dir/package-sources.tsv"
fi
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{LICENSE}\n' | sort > "$artifact_dir/license-inventory.tsv"

if [[ -n "${GREYWARD_COPR_BUILD_RECORD:-}" && -r "$GREYWARD_COPR_BUILD_RECORD" ]]; then
  install -m 0644 "$GREYWARD_COPR_BUILD_RECORD" "$artifact_dir/copr-build-record.txt"
else
  {
    printf '# Exact COPR numeric build IDs were not supplied to this image build.\n'
    while IFS= read -r repository; do
      [[ -z "$repository" || "$repository" == \#* ]] && continue
      printf '%s\tBUILD_ID=UNRESOLVED\n' "$repository"
    done < "$repositories_file"
  } > "$artifact_dir/copr-build-record.txt"
fi

if command -v flatpak >/dev/null 2>&1; then
  if ! flatpak list --system --columns=application,ref,version,origin > "$artifact_dir/flatpak-inventory.tsv" 2>/dev/null; then
    flatpak list --system > "$artifact_dir/flatpak-inventory.tsv" 2>/dev/null || printf '%s\n' 'UNRESOLVED: Flatpak inventory query failed.' > "$artifact_dir/flatpak-inventory.tsv"
  fi
  {
    printf 'application\tref\tcommit\tversion\n'
    mapfile -t installed_flatpaks < <(flatpak list --system --columns=application 2>/dev/null || true)
    for application in "${installed_flatpaks[@]}"; do
      [[ -z "$application" || "$application" == "Application" || "$application" == \#* ]] && continue
      ref=$(flatpak info --system --show-ref "$application" 2>/dev/null || true)
      commit=$(flatpak info --system --show-commit "$application" 2>/dev/null || true)
      version=$(flatpak info --system --show-version "$application" 2>/dev/null || true)
      [[ -n "$ref" ]] || ref=UNRESOLVED
      [[ -n "$commit" ]] || commit=UNRESOLVED
      [[ -n "$version" ]] || version=UNRESOLVED
      printf '%s\t%s\t%s\t%s\n' "$application" "$ref" "$commit" "$version"
    done
  } > "$artifact_dir/flatpak-refs.tsv"
else
  printf '%s\n' 'UNRESOLVED: flatpak is unavailable during provisioning.' > "$artifact_dir/flatpak-inventory.tsv"
  printf '%s\n' 'UNRESOLVED: flatpak is unavailable during provisioning.' > "$artifact_dir/flatpak-refs.tsv"
fi
cat > "$artifact_dir/license-sbom.json" <<'EOF'
{
  "schema": "greyward.internal-alpha-artifacts/v1",
  "kind": "installed-image-inventory",
  "packageInventory": "package-inventory.txt",
  "packageSources": "package-sources.tsv",
  "licenses": "license-inventory.tsv",
  "flatpaks": "flatpak-refs.tsv",
  "coprBuilds": "copr-build-record.txt",
  "sbomScope": "GREYWARD installed package and Flatpak inventory; verify with a release-grade SBOM tool before public release"
}
EOF
# Record the persistent update sources without allowing first-boot provisioning
# to contact a network. `command dnf` deliberately bypasses the offline DNF
# wrapper above, so never use it on this path. Read repository definitions
# locally instead; online installations retain the richer DNF inventory.
if [[ "${GREYWARD_OFFLINE_INSTALL:-0}" == 1 ]]; then
  {
    printf '%s\n' '# Enabled repository definitions captured offline; no metadata refresh was performed.'
    awk '
      function emit() { if (section != "" && enabled != 0) print section }
      /^[[:space:]]*\[/ {
        emit()
        section = $0
        sub(/^[[:space:]]*\[/, "", section)
        sub(/\][[:space:]]*$/, "", section)
        enabled = 1
        next
      }
      /^[[:space:]]*enabled[[:space:]]*=/ {
        value = $0
        sub(/^[^=]*=[[:space:]]*/, "", value)
        enabled = (value == 1)
      }
      END { emit() }
    ' /etc/yum.repos.d/*.repo 2>/dev/null | sort -u
  } > /etc/greyward-enabled-repositories.txt
else
  command dnf repolist --enabled > /etc/greyward-enabled-repositories.txt
fi
install -m 0644 /etc/greyward-enabled-repositories.txt "$artifact_dir/enabled-repositories.txt"
phase 'Finalizing installed production state'
# Restore labels on the files written by the production finalizer, including
# the greeter's HOME-scoped configuration. The greeter itself is launched
# directly from the packaged executable in /etc/greetd/config.toml; no custom
# executable is copied into /usr/libexec by this path.
restorecon -RF /etc/greyward /etc/greetd /etc/skel /etc/systemd \
  /var/cache/dms-greeter || true
# The completion marker is intentionally written only by first-boot acceptance
# after /usr/local/libexec/greyward-production-acceptance succeeds.
rm -f /etc/greyward-production-complete

# The installer target intentionally has no production-ready marker at this
# stage. It is created only by the installed first-boot finalizer, after
# Anaconda has created the real account and staged production work
# has succeeded.
