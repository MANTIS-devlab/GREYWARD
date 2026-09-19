#!/usr/bin/env bash
set -euo pipefail

# Runtime acceptance for an installed GREYWARD system. The retryable first-boot
# finalizer calls this with --pre-marker and creates the completion marker only
# after every check below passes. Normal invocations also require that marker.
require_marker=true
case "${1:-}" in
  '') ;;
  --pre-marker) require_marker=false ;;
  *) printf 'usage: %s [--pre-marker]\n' "$0" >&2; exit 2 ;;
esac

current_check='startup'
checkpoint() {
  current_check="$1"
  printf 'GREYWARD acceptance: %s\n' "$current_check"
}
fail() {
  printf 'FAIL: %s (last check: %s)\n' "$1" "$current_check" >&2
  exit 1
}
is_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }

if "$require_marker"; then
  test -f /etc/greyward-production-complete || fail 'production completion marker is missing'
fi
checkpoint 'required production packages and login boundary'
rpm -q dms-greeter greyward-security-center greyward-security-context audit audit-rules policycoreutils swayidle swaylock wlopm net-tools >/dev/null || fail 'required production package is missing'
test -x /usr/bin/dms-greeter || fail 'DMS Greeter is not installed'
test -s /etc/greetd/config.toml || fail 'greetd configuration is missing'
is_enabled greetd || fail 'greetd is not enabled'
is_enabled auditd || fail 'auditd is not enabled'
is_enabled audit-rules || fail 'audit-rules is not enabled'
checkpoint 'security provider services'
for provider_service in opensnitch.service greyward-opensnitch-control-plane.service \
  greyward-opensnitch-policy.service greyward-clamav-scan.service \
  clamav-freshclam.service greyward-secure-dns.service usbguard.service \
  usbguard-dbus.service; do
  systemctl is-active --quiet "$provider_service" || fail "Security provider service is not active: $provider_service"
done
test -s /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg || fail 'GREYWARD desktop wallpaper is missing'
test -x /usr/local/libexec/greyward-sync-greeter-wallpaper || fail 'GREYWARD greeter wallpaper sync helper is missing'
test -s /var/cache/dms-greeter/greeter_wallpaper_override.jpg || fail 'GREYWARD greeter wallpaper override is missing'
cmp -s /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg \
  /var/cache/dms-greeter/greeter_wallpaper_override.jpg || fail 'GREYWARD greeter wallpaper override does not match the desktop wallpaper'
test -s /etc/systemd/system/greetd.service.d/greyward-wallpaper.conf || fail 'GREYWARD greetd wallpaper drop-in is missing'
grep -qx 'ExecStartPre=/usr/local/libexec/greyward-sync-greeter-wallpaper' \
  /etc/systemd/system/greetd.service.d/greyward-wallpaper.conf || fail 'GREYWARD greetd wallpaper sync is not applied before startup'
test -x /usr/libexec/greyward-auto-update || fail 'automatic update helper is missing'
is_enabled greyward-auto-update.timer || fail 'automatic update timer is not enabled'
systemctl is-active --quiet greyward-auto-update.timer || fail 'automatic update timer is not active'
checkpoint 'audit and SELinux policy'
test -s /etc/audit/rules.d/40-greyward.rules || fail 'GREYWARD audit policy is missing'
grep -q -- '-w /etc/passwd.*-k identity' /etc/audit/audit.rules || fail 'GREYWARD identity audit rule is not loaded'
grep -q -- '-a always,exit.*key=module-load' /etc/audit/audit.rules || fail 'GREYWARD module audit rule is not loaded'
semodule -l | grep -qx greyward-dms-greeter || fail 'GREYWARD greeter SELinux policy is not loaded'
test -x /usr/local/libexec/greyward-patch-uwsm-labwc || fail 'UWSM Labwc fix is missing'
grep -q 'GREYWARD_UWSM_LABWC_DROPIN_DIRECTORY' /usr/share/uwsm/plugins/labwc.sh || fail 'UWSM Labwc drop-in fix is not applied'
if is_enabled gdm; then fail 'temporary GDM setup path is still enabled'; fi
checkpoint 'Anaconda account and Initial Setup removal'
mapfile -t human_users < <(awk -F: '$3 >= 1000 && $6 ~ /^\/home\// { print $1 }' /etc/passwd)
(( ${#human_users[@]} >= 1 )) || fail 'Anaconda did not create a usable human account'
for forbidden_package in gdm gnome-initial-setup gnome-session-wayland-session; do
  if rpm -q "$forbidden_package" >/dev/null 2>&1; then
    fail "live-only GNOME package is still installed: $forbidden_package"
  fi
done
test ! -e /etc/systemd/system/getty@tty1.service.d/autologin.conf || fail 'tty autologin is still configured'
if "$require_marker"; then
  test ! -e /var/lib/greyward/installer/account-contract.env || fail 'obsolete account hand-off contract is present'
  test ! -e /var/lib/greyward/installer/account-complete || fail 'obsolete account hand-off record is present'
fi
test -L /etc/systemd/system/initial-setup.service || fail 'GNOME Initial Setup service is not masked'
test "$(readlink /etc/systemd/system/initial-setup.service)" = /dev/null || fail 'GNOME Initial Setup service is not masked'
test -e /var/lib/greyward/installer/production-ready || fail 'production finalization is not complete'
checkpoint 'branding assets'
test -s /usr/share/greyward/security-center-contract.tsv || fail 'Security Center package contract is missing'
for branding_path in \
  /usr/share/anaconda/pixmaps/greyward-anaconda-logo.png \
  /usr/share/anaconda/pixmaps/greyward-anaconda.css \
  /etc/anaconda/profile.d/greyward.conf \
  /etc/cockpit/branding/branding.css \
  /etc/cockpit/branding/greyward-symbol.svg; do
  test -s "$branding_path" || fail "Anaconda branding asset is missing: $branding_path"
  test "$(rpm -qf --qf '%{NAME}' "$branding_path" 2>/dev/null)" = greyward-branding || fail "Anaconda branding asset ownership is invalid: $branding_path"
done
grep -q '^profile_id = greyward$' /etc/anaconda/profile.d/greyward.conf || fail 'Anaconda GREYWARD profile is invalid'
grep -q '^base_profile = fedora$' /etc/anaconda/profile.d/greyward.conf || fail 'Anaconda GREYWARD profile must preserve Fedora as its base'
grep -q '^custom_stylesheet = /usr/share/anaconda/pixmaps/greyward-anaconda.css$' /etc/anaconda/profile.d/greyward.conf || fail 'Anaconda GREYWARD stylesheet hook is invalid'
grep -q '^\.product-logo' /usr/share/anaconda/pixmaps/greyward-anaconda.css || fail 'Anaconda GREYWARD product logo styling is missing'
grep -q 'greyward-symbol\.svg' /etc/cockpit/branding/branding.css || fail 'Cockpit GREYWARD logo styling is missing'
grep -q 'color-scheme: dark' /etc/cockpit/branding/branding.css || fail 'Cockpit GREYWARD dark theme styling is missing'
test -s /etc/cockpit/branding/greyward-symbol.svg || fail 'Cockpit GREYWARD SVG logo is missing'

checkpoint 'production security boundary'
test ! -e /etc/sudoers.d/90-greyward-dev || fail 'developer passwordless sudo policy is present'
# A production user may legitimately choose the same login name as the
# disposable factory bootstrap account. The username alone is not evidence of
# development contamination; the actual developer-only markers above are what
# the acceptance contract rejects.
if is_enabled sshd; then fail 'SSH is enabled in the production image'; fi
if is_enabled hypervkvpd; then fail 'Hyper-V guest services are enabled in the production image'; fi

checkpoint 'desktop shell and session'
test -s /usr/share/greyward/dms/greyward-obsidian.json || fail 'system DMS theme is missing'
test -s /usr/share/greyward/dms/greyward-symbol.svg || fail 'system DMS launcher logo is missing'
grep -q '/usr/share/greyward/dms/greyward-obsidian.json' /etc/skel/.config/DankMaterialShell/settings.json || fail 'DMS theme path is not production-safe'
grep -q '/usr/share/greyward/dms/greyward-symbol.svg' /etc/skel/.config/DankMaterialShell/settings.json || fail 'DMS logo path is not production-safe'
rpm -q cascadia-mono-nf-fonts git zsh blackbox-terminal >/dev/null || fail 'interactive shell/terminal prerequisites are missing'
test -x /usr/sbin/ifconfig || fail 'ifconfig is missing; net-tools was not installed'
test -s /usr/local/share/applications/com.raggesilver.BlackBox.desktop || fail 'GREYWARD Terminal desktop entry is missing'
grep -q '^Exec=/usr/bin/env GREYWARD_TERMINAL_BRIEF=1 SHELL=/usr/bin/zsh blackbox-terminal$' /usr/local/share/applications/com.raggesilver.BlackBox.desktop || fail 'Black Box must launch the production zsh shell'
test -s /usr/share/blackbox/schemes/greyward-obsidian.json || fail 'GREYWARD Black Box color scheme is missing'
test -s /usr/share/blackbox/schemes/dark-pastel.json || fail 'Dark Pastel Black Box color scheme is missing'
test -s /usr/share/blackbox/schemes/paraiso-dark.json || fail 'Paraiso Dark Black Box color scheme is missing'
test -s /usr/share/blackbox/schemes/seti.json || fail 'Seti Black Box color scheme is missing'
test -s /usr/share/blackbox/schemes/vibrant-ink.json || fail 'Vibrant Ink Black Box color scheme is missing'
test -s /etc/dconf/db/local.d/50-greyward-blackbox || fail 'GREYWARD Black Box defaults are missing'
test -s /usr/share/icons/hicolor/scalable/apps/greyward-terminal.svg || fail 'GREYWARD Terminal icon is missing'
test -x /usr/local/libexec/greyward-configure-zsh || fail 'GREYWARD zsh configurator is missing'
test -s /usr/share/greyward/zsh/sources.env || fail 'Oh My Zsh source pins are missing'
grep -q '^ZSH_THEME="powerlevel10k/powerlevel10k"$' /etc/skel/.zshrc || fail 'Powerlevel10k is not the default zsh theme'
grep -q '^  typeset -g POWERLEVEL9K_MODE=nerdfont-complete$' /etc/skel/.p10k.zsh || fail 'Powerlevel10k Nerd Font configuration is missing'
for human_user in "${human_users[@]}"; do
  test "$(getent passwd "$human_user" | awk -F: '{ print $7 }')" = /usr/bin/zsh || fail "user shell is not zsh: $human_user"
  user_home=$(getent passwd "$human_user" | awk -F: '{ print $6 }')
  test -s "$user_home/.oh-my-zsh/oh-my-zsh.sh" || fail "Oh My Zsh runtime is missing for: $human_user"
  test -d "$user_home/.oh-my-zsh/custom/themes/powerlevel10k" || fail "Powerlevel10k is not installed for: $human_user"
  test -s "$user_home/.zshrc" || fail "zsh configuration is missing for: $human_user"
  grep -q '^ZSH_THEME="powerlevel10k/powerlevel10k"$' "$user_home/.zshrc" || fail "GREYWARD zsh theme is not configured for: $human_user"
  grep -q 'source "\$ZSH/oh-my-zsh.sh"' "$user_home/.zshrc" || fail "Oh My Zsh is not sourced for: $human_user"
done
test -s /usr/share/wayland-sessions/greyward-labwc.desktop || fail 'GREYWARD Labwc session entry is missing'
test -x /usr/local/bin/greyward-session-lock || fail 'GREYWARD session locker entrypoint is missing'
test -x /usr/local/bin/greyward-display-power || fail 'GREYWARD display power entrypoint is missing'
test -s /etc/systemd/user/greyward-session-idle.service || fail 'GREYWARD idle service is missing'
for forbidden_session in \
  /usr/local/share/wayland-sessions/gnome.desktop \
  /usr/share/wayland-sessions/gnome.desktop \
  /usr/share/gdm/greeter/wayland-sessions/gnome-initial-setup.desktop; do
  test ! -e "$forbidden_session" || fail "GNOME session entry is still exposed: $forbidden_session"
done

checkpoint 'installed trace artifacts'
artifact_dir=/var/lib/greyward/build-artifacts
for artifact in package-inventory.txt package-sources.tsv license-inventory.tsv \
  copr-build-record.txt flatpak-refs.tsv license-sbom.json enabled-repositories.txt \
  security-center-build-manifest.tsv; do
  test -s "$artifact_dir/$artifact" || fail "installed-image trace artifact is missing: $artifact"
done

checkpoint 'Security Center package contract'
security_manifest_value() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
    "$artifact_dir/security-center-build-manifest.tsv"
}
test "$(security_manifest_value schema)" = 'greyward.security-center-build/v1' || fail 'Security Center build manifest schema is invalid'
test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' greyward-security-center)" = "$(security_manifest_value center_nevra)" || fail 'installed Security Center package differs from its build manifest'
test "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' greyward-security-context)" = "$(security_manifest_value context_nevra)" || fail 'installed Security Context package differs from its build manifest'
while IFS='|' read -r package path; do
  [[ -z "$package" || "$package" == \#* ]] && continue
  test "$(rpm -qf --qf '%{NAME}' "$path" 2>/dev/null)" = "$package" || fail "Security Center contract ownership is invalid: $path"
done < /usr/share/greyward/security-center-contract.tsv

checkpoint 'encrypted Btrfs root'
findmnt -no FSTYPE / | grep -qx btrfs || fail 'root filesystem is not Btrfs'
lsblk -nrpo NAME,FSTYPE | awk '$2 == "crypto_LUKS" { found = 1 } END { exit found ? 0 : 1 }' || fail 'no encrypted root backing device was detected'

printf 'RESULT: PRODUCTION CONTRACT HEALTHY\n'
