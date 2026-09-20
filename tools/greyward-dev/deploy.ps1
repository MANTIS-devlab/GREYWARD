[CmdletBinding()]
param([switch]$SkipBrandingValidation)
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
if (-not $SkipBrandingValidation) {
    & (Join-Path $script:RepoRoot 'tools\validate-branding.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Branding validation failed; deployment was not started.' }
}
$release = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$remoteRoot = "/home/stendev/.local/share/greyward/releases/$release"
Invoke-GreywardSessionSsh "mkdir -p '$remoteRoot'"
Invoke-GreywardSessionSsh "mkdir -p '$remoteRoot/patches'"
Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'branding') -Destination "$($script:SshAlias):$remoteRoot/"
Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'environment\production') -Destination "$($script:SshAlias):$remoteRoot/"
Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'environment\patches\dms') -Destination "$($script:SshAlias):$remoteRoot/patches/"
Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'environment\session\labwc') -Destination "$($script:SshAlias):$remoteRoot/"
Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'environment\session\dankmaterialshell') -Destination "$($script:SshAlias):$remoteRoot/"
Invoke-GreywardScp -Source (Join-Path $script:RepoRoot 'environment\session\hyprland.conf') -Destination "$($script:SshAlias):$remoteRoot/hyprland.conf"
Invoke-GreywardScp -Source (Join-Path $script:RepoRoot 'environment\session\greyward-decoration.tokens.conf') -Destination "$($script:SshAlias):$remoteRoot/greyward-decoration.tokens.conf"
Invoke-GreywardScp -Source (Join-Path $script:RepoRoot 'environment\session\greyward-minimize.sh') -Destination "$($script:SshAlias):$remoteRoot/greyward-minimize.sh"
Invoke-GreywardScp -Source (Join-Path $script:RepoRoot 'environment\session\greyward-restore.sh') -Destination "$($script:SshAlias):$remoteRoot/greyward-restore.sh"
Invoke-GreywardScp -Source (Join-Path $script:RepoRoot 'environment\session\greyward-labwc.desktop') -Destination "$($script:SshAlias):$remoteRoot/greyward-labwc.desktop"
Invoke-GreywardScp -Source (Join-Path $script:RepoRoot 'environment\production\greyward-start-labwc') -Destination "$($script:SshAlias):$remoteRoot/greyward-start-labwc"
Invoke-GreywardScp -Source (Join-Path $script:RepoRoot 'environment\session\greyward-dms.service') -Destination "$($script:SshAlias):$remoteRoot/greyward-dms.service"
Invoke-GreywardScp -Source (Join-Path $script:RepoRoot 'environment\session\greyward-dms-session-migrate') -Destination "$($script:SshAlias):$remoteRoot/greyward-dms-session-migrate"
Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'environment\flatpak') -Destination "$($script:SshAlias):$remoteRoot/"
$activate = @"
set -euo pipefail
release='$remoteRoot'
sudo dnf -y install git zsh blackbox-terminal audit audit-rules policycoreutils gnome-text-editor papers loupe gvfs-smb gvfs-mtp gvfs-gphoto2 gvfs-archive NetworkManager-openvpn
if rpm -q tabby-terminal >/dev/null 2>&1; then sudo dnf -y remove --no-autoremove tabby-terminal; fi
if rpm -q kitty >/dev/null 2>&1; then sudo dnf -y remove --no-autoremove kitty; fi
sudo install -D -m 0644 "`$release/production/crypto-policy/GREYWARD.pmod" /etc/crypto-policies/policies/modules/GREYWARD.pmod
sudo update-crypto-policies --set DEFAULT:GREYWARD
test "`$(sudo update-crypto-policies --show)" = DEFAULT:GREYWARD
sudo update-crypto-policies --is-applied
sudo env GREYWARD_DMS_PATCH_DIR="`$release/patches/dms" bash "`$release/production/install-dms.sh"
if command -v rsvg-convert >/dev/null 2>&1; then rsvg-convert -w 1920 -h 1080 "`$release/branding/wallpaper/greyward-wallpaper.svg" -o "`$release/branding/wallpaper/greyward-wallpaper.png"; fi
mkdir -p ~/.local/share/greyward
mkdir -p ~/.config/DankMaterialShell
install -D -m 0644 "`$release/dankmaterialshell/greyward-obsidian.json" ~/.config/DankMaterialShell/greyward-obsidian.json
install -D -m 0644 "`$release/dankmaterialshell/plugin_settings.json" ~/.config/DankMaterialShell/plugin_settings.json
install -D -m 0644 "`$release/branding/source/greyward-symbol.svg" ~/.config/DankMaterialShell/greyward-symbol.svg
sudo install -d -m 0755 /usr/share/greyward/dms
sudo install -D -m 0644 "`$release/dankmaterialshell/greyward-obsidian.json" /usr/share/greyward/dms/greyward-obsidian.json
sudo install -D -m 0644 "`$release/branding/source/greyward-symbol.svg" /usr/share/greyward/dms/greyward-symbol.svg
sudo install -d -o greeter -g greeter -m 2770 /var/cache/dms-greeter
sudo install -D -m 0644 "`$release/dankmaterialshell/settings.json" /var/cache/dms-greeter/settings.json
sudo install -D -m 0644 /dev/null /var/cache/dms-greeter/session.json
sudo tee /var/cache/dms-greeter/session.json >/dev/null <<'EOF'
{
  "wallpaperPath": "/usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg",
  "wallpaperFillMode": "PreserveAspectCrop"
}
EOF
sudo install -d -m 0755 /usr/share/backgrounds/greyward
find "`$release/branding/wallpaper" -maxdepth 1 -type f -name 'greyward-wallpaper-*.jpg' -exec sudo install -m 0644 {} /usr/share/backgrounds/greyward/ \;
test "`$(find "`$release/branding/wallpaper" -maxdepth 1 -type f -name 'greyward-wallpaper-*.jpg' | wc -l)" -eq 2
for wallpaper_file in \
  greyward-wallpaper-black-art-4k.jpg \
  greyward-wallpaper-2109-4k.jpg; do test -f "/usr/share/backgrounds/greyward/`$wallpaper_file"; done
sudo install -D -m 0644 /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg /var/cache/dms-greeter/greeter_wallpaper_override.jpg
sudo chown greeter:greeter /var/cache/dms-greeter/settings.json /var/cache/dms-greeter/session.json /var/cache/dms-greeter/greeter_wallpaper_override.jpg
rm -f ~/.config/DankMaterialShell/greyward-wallpaper.png
ln -s /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg ~/.config/DankMaterialShell/greyward-wallpaper.png
mkdir -p ~/.config/DankMaterialShell/plugins/greywardPublicIp
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardPublicIp/plugin.json" ~/.config/DankMaterialShell/plugins/greywardPublicIp/plugin.json
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardPublicIp/PublicIpWidget.qml" ~/.config/DankMaterialShell/plugins/greywardPublicIp/PublicIpWidget.qml
mkdir -p ~/.config/DankMaterialShell/plugins/greywardNetworkTraffic
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardNetworkTraffic/plugin.json" ~/.config/DankMaterialShell/plugins/greywardNetworkTraffic/plugin.json
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficWidget.qml" ~/.config/DankMaterialShell/plugins/greywardNetworkTraffic/NetworkTrafficWidget.qml
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficModel.qml" ~/.config/DankMaterialShell/plugins/greywardNetworkTraffic/NetworkTrafficModel.qml
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficMath.js" ~/.config/DankMaterialShell/plugins/greywardNetworkTraffic/NetworkTrafficMath.js
mkdir -p ~/.config/DankMaterialShell/plugins/greywardSecure
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardSecure/plugin.json" ~/.config/DankMaterialShell/plugins/greywardSecure/plugin.json
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml" ~/.config/DankMaterialShell/plugins/greywardSecure/SecureWidget.qml
mkdir -p ~/.config/DankMaterialShell/plugins/greywardSoftware
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardSoftware/plugin.json" ~/.config/DankMaterialShell/plugins/greywardSoftware/plugin.json
install -D -m 0644 "`$release/dankmaterialshell/plugins/greywardSoftware/SoftwareWidget.qml" ~/.config/DankMaterialShell/plugins/greywardSoftware/SoftwareWidget.qml
grep -q '"version": "2.0.0"' ~/.config/DankMaterialShell/plugins/greywardSecure/plugin.json
test -s ~/.config/DankMaterialShell/plugins/greywardSecure/SecureWidget.qml
grep -q '"id": "greywardNetworkTraffic"' ~/.config/DankMaterialShell/plugins/greywardNetworkTraffic/plugin.json
test -s ~/.config/DankMaterialShell/plugins/greywardNetworkTraffic/NetworkTrafficWidget.qml
mkdir -p ~/.config/labwc ~/.local/share/themes/Greyward/labwc
mkdir -p ~/.config/greyward
cp "`$release/labwc/rc.xml" ~/.config/labwc/rc.xml
cp "`$release/labwc/environment" ~/.config/labwc/environment
cp "`$release/labwc/autostart" ~/.config/labwc/autostart
chmod 0755 ~/.config/labwc/autostart
install -D -m 0644 "`$release/dankmaterialshell/settings.json" ~/.config/DankMaterialShell/settings.json
if [ ! -e ~/.local/share/themes/Greyward/labwc/themerc.greyward-original ] && [ -e ~/.local/share/themes/Greyward/labwc/themerc ]; then cp ~/.local/share/themes/Greyward/labwc/themerc ~/.local/share/themes/Greyward/labwc/themerc.greyward-original; fi
cp "`$release/labwc/Greyward/themerc" ~/.local/share/themes/Greyward/labwc/themerc
find "`$release/labwc/Greyward" -maxdepth 1 -type f -name '*.svg' -exec cp {} ~/.local/share/themes/Greyward/labwc/ \;
sudo install -D -m 0644 "`$release/greyward-labwc.desktop" /usr/share/wayland-sessions/greyward-labwc.desktop
sudo install -D -m 0755 "`$release/greyward-start-labwc" /usr/local/libexec/greyward-start-labwc
sudo install -D -m 0644 "`$release/greyward-dms.service" /etc/systemd/user/greyward-dms.service
sudo install -D -m 0755 "`$release/greyward-dms-session-migrate" /usr/local/libexec/greyward-dms-session-migrate
sudo install -D -m 0644 "`$release/flatpak/labwc-portals.conf" /etc/xdg-desktop-portal/labwc-portals.conf
sudo install -d -m 0755 /usr/share/greyward/bazaar /usr/local/libexec
sudo install -D -m 0644 "`$release/flatpak/greyward-privacy-runtime.yaml" /usr/share/greyward/bazaar/greyward-privacy.yaml
sudo install -D -m 0644 "`$release/flatpak/greyward-software-banner.svg" /usr/share/greyward/bazaar/greyward-software-banner.svg
sudo install -D -m 0644 "`$release/branding/source/greyward-symbol.svg" /usr/share/greyward/bazaar/greyward-symbol.svg
sudo install -D -m 0644 "`$release/flatpak/bazaar-main-runtime.yaml" /usr/share/greyward/bazaar/main.yaml
sudo install -D -m 0755 "`$release/flatpak/greyward-software" /usr/local/libexec/greyward-software
sudo install -D -m 0755 "`$release/flatpak/greyward-software-selection" /usr/local/libexec/greyward-software-selection
sudo install -D -m 0644 "`$release/flatpak/software-runtime.desktop" /usr/local/share/applications/io.github.kolunmi.Bazaar.desktop
sudo install -D -m 0644 "`$release/flatpak/mimeapps.list" /etc/xdg/mimeapps.list
sudo install -D -m 0644 "`$release/production/desktop-entry-overrides/com.raggesilver.BlackBox.desktop" /usr/local/share/applications/com.raggesilver.BlackBox.desktop
if test -f /usr/local/share/applications/greyward-terminal.desktop; then
  sudo install -m 0644 "`$release/production/desktop-entry-overrides/com.raggesilver.BlackBox.desktop" /usr/local/share/applications/greyward-terminal.desktop
  printf '\nNoDisplay=true\n' | sudo tee -a /usr/local/share/applications/greyward-terminal.desktop >/dev/null
fi
sudo install -D -m 0644 "`$release/production/blackbox/schemes/greyward-obsidian.json" /usr/share/blackbox/schemes/greyward-obsidian.json
sudo install -D -m 0644 "`$release/production/blackbox/schemes/dark-pastel.json" /usr/share/blackbox/schemes/dark-pastel.json
sudo install -D -m 0644 "`$release/production/blackbox/schemes/paraiso-dark.json" /usr/share/blackbox/schemes/paraiso-dark.json
sudo install -D -m 0644 "`$release/production/blackbox/schemes/seti.json" /usr/share/blackbox/schemes/seti.json
sudo install -D -m 0644 "`$release/production/blackbox/schemes/vibrant-ink.json" /usr/share/blackbox/schemes/vibrant-ink.json
sudo install -D -m 0644 "`$release/branding/source/greyward-terminal.svg" /usr/share/icons/hicolor/scalable/apps/greyward-terminal.svg
sudo install -D -m 0755 "`$release/production/configure-zsh.sh" /usr/local/libexec/greyward-configure-zsh
sudo install -D -m 0755 "`$release/production/zsh/greyward-terminal-brief.py" /usr/local/libexec/greyward-terminal-brief
sudo install -D -m 0644 "`$release/production/zsh/sources.env" /usr/share/greyward/zsh/sources.env
sudo install -D -m 0644 "`$release/production/zsh/zshrc" /usr/share/greyward/zsh/zshrc
sudo install -D -m 0644 "`$release/production/zsh/p10k.zsh" /usr/share/greyward/zsh/p10k.zsh
sudo install -D -m 0644 "`$release/production/zsh/zshrc" /etc/skel/.zshrc
sudo install -D -m 0644 "`$release/production/zsh/p10k.zsh" /etc/skel/.p10k.zsh
sudo install -d -m 0750 /etc/audit/rules.d
for disabled_rules in /etc/audit/rules.d/10-no-audit.rules /etc/audit/rules.d/audit.rules; do
    if [ -f "`$disabled_rules" ] && grep -Eq '^[[:space:]]*-a[[:space:]]+task,never([[:space:]]|`$)' "`$disabled_rules"; then sudo rm -f "`$disabled_rules"; fi
done
sudo install -D -m 0640 "`$release/production/audit/greyward.rules" /etc/audit/rules.d/40-greyward.rules
sudo install -D -m 0644 "`$release/production/selinux/greyward-dms-greeter.cil" /etc/selinux/targeted/greyward-dms-greeter.cil
sudo semodule -i /etc/selinux/targeted/greyward-dms-greeter.cil
sudo install -D -m 0755 "`$release/production/patch-uwsm-labwc.sh" /usr/local/libexec/greyward-patch-uwsm-labwc
sudo /usr/local/libexec/greyward-patch-uwsm-labwc
sudo systemctl enable auditd.service audit-rules.service
if sudo auditctl -s | grep -q '^enabled 2'; then
    sudo auditctl -l | grep -Eq '(^|[[:space:]])-k[[:space:]]+identity([[:space:]]|$)|(^|[[:space:]])key=identity([[:space:]]|$)'
else
    sudo augenrules --load
fi
sudo /usr/local/libexec/greyward-configure-zsh "`$USER"
if command -v update-desktop-database >/dev/null 2>&1; then sudo update-desktop-database /usr/local/share/applications; fi
rm -f ~/.cache/DankMaterialShell/launcher_cache.json
gsettings set com.raggesilver.BlackBox command-as-login-shell true
gsettings set com.raggesilver.BlackBox context-aware-header-bar true
gsettings set com.raggesilver.BlackBox cursor-blink-mode 0
gsettings set com.raggesilver.BlackBox cursor-shape 0
gsettings set com.raggesilver.BlackBox custom-shell-command ''
gsettings set com.raggesilver.BlackBox custom-working-directory '~'
gsettings set com.raggesilver.BlackBox delay-before-showing-floating-controls 400
gsettings set com.raggesilver.BlackBox easy-copy-paste true
gsettings set com.raggesilver.BlackBox fill-tabs true
gsettings set com.raggesilver.BlackBox floating-controls true
gsettings set com.raggesilver.BlackBox floating-controls-hover-area 10
gsettings set com.raggesilver.BlackBox font 'Cascadia Mono NF 14'
gsettings set com.raggesilver.BlackBox headerbar-drag-area true
gsettings set com.raggesilver.BlackBox notify-process-completion true
gsettings set com.raggesilver.BlackBox opacity 93
gsettings set com.raggesilver.BlackBox pixel-scrolling false
gsettings set com.raggesilver.BlackBox pretty false
gsettings set com.raggesilver.BlackBox remember-window-size true
gsettings set com.raggesilver.BlackBox scrollback-lines 1000
gsettings set com.raggesilver.BlackBox scrollback-mode 0
gsettings set com.raggesilver.BlackBox show-headerbar true
gsettings set com.raggesilver.BlackBox show-menu-button true
gsettings set com.raggesilver.BlackBox show-scrollbars true
gsettings set com.raggesilver.BlackBox style-preference 2
gsettings set com.raggesilver.BlackBox terminal-bell false
gsettings set com.raggesilver.BlackBox terminal-cell-height 1.0
gsettings set com.raggesilver.BlackBox terminal-cell-width 1.0
gsettings set com.raggesilver.BlackBox terminal-hide-cursor-while-typing false
gsettings set com.raggesilver.BlackBox terminal-padding '(uint32 12, uint32 12, uint32 12, uint32 12)'
gsettings set com.raggesilver.BlackBox theme-bold-is-bright true
gsettings set com.raggesilver.BlackBox theme-dark 'Dark Pastel'
gsettings set com.raggesilver.BlackBox theme-light 'Gruvbox Light'
gsettings set com.raggesilver.BlackBox use-custom-command false
gsettings set com.raggesilver.BlackBox use-overlay-scrolling true
gsettings set com.raggesilver.BlackBox use-sixel false
gsettings set com.raggesilver.BlackBox was-fullscreened false
gsettings set com.raggesilver.BlackBox was-maximized false
gsettings set com.raggesilver.BlackBox window-height 945
gsettings set com.raggesilver.BlackBox window-width 1237
gsettings set com.raggesilver.BlackBox working-directory-mode 0
if ! command -v flatpak >/dev/null 2>&1 && command -v dnf >/dev/null 2>&1; then sudo dnf -y install flatpak xdg-desktop-portal-gtk; fi
command -v flatpak >/dev/null 2>&1
sudo flatpak remote-add --if-not-exists --system flathub https://dl.flathub.org/repo/flathub.flatpakrepo
sudo flatpak install --system --noninteractive flathub io.github.kolunmi.Bazaar
sudo flatpak override --system --reset io.github.kolunmi.Bazaar
sudo flatpak override --system --filesystem=xdg-config/bazaar:ro io.github.kolunmi.Bazaar
mapfile -t default_flatpaks < <(awk -F'|' '!/^[[:space:]]*(#|$)/ {gsub(/[[:space:]]/, "", `$1); print `$1}' "`$release/flatpak/default-applications.list")
test "`${#default_flatpaks[@]}" -eq 4
sudo flatpak install --system --noninteractive flathub "`${default_flatpaks[@]}"
mkdir -p ~/.var/app/com.brave.Browser/config
install -D -m 0644 "`$release/flatpak/brave-flags.conf" ~/.var/app/com.brave.Browser/config/brave-flags.conf
sudo flatpak override --system --reset org.kde.haruna
sudo flatpak override --system --unshare=network org.kde.haruna
test -x /usr/local/bin/greyward-dms
cp "`$release/hyprland.conf" ~/.config/hypr/hyprland.conf
cp "`$release/greyward-decoration.tokens.conf" ~/.config/hypr/greyward-decoration.tokens.conf
install -D -m 0755 "`$release/greyward-minimize.sh" ~/.local/bin/greyward-minimize
install -D -m 0755 "`$release/greyward-restore.sh" ~/.local/bin/greyward-restore
gsettings set org.gnome.desktop.wm.preferences button-layout 'appmenu:minimize,maximize,close' >/dev/null 2>&1 || true
gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark' >/dev/null 2>&1 || true
gsettings set org.gnome.desktop.wm.preferences theme 'Adwaita-dark' >/dev/null 2>&1 || true
gsettings set org.gnome.desktop.interface icon-theme 'Adwaita' >/dev/null 2>&1 || true
if [ -L ~/.local/share/greyward/current ]; then readlink -f ~/.local/share/greyward/current > ~/.local/share/greyward/previous; fi
ln -sfn "`$release" ~/.local/share/greyward/current.new
mv -Tf ~/.local/share/greyward/current.new ~/.local/share/greyward/current
systemctl --global enable greyward-dms.service
systemctl --user daemon-reload
systemctl --user restart greyward-dms.service
sleep 3
/usr/local/bin/greyward-dms ipc call wallpaper set /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg >/tmp/greyward-wallpaper-set.log 2>&1 || { cat /tmp/greyward-wallpaper-set.log; exit 1; }
labwc --reconfigure >/tmp/greyward-labwc-reconfigure.log 2>&1 || true
sed -i '/^[[:space:]]*exec-once = hyprpaper[[:space:]]*$/d' ~/.config/hypr/hyprland.conf 2>/dev/null || true
pkill -x hyprpaper >/dev/null 2>&1 || true
find ~/.local/share/greyward/releases -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | tail -n +3 | cut -d' ' -f2- | xargs -r rm -rf --
"@
$activate = $activate -replace "`r`n", "`n"
Invoke-GreywardSessionSsh $activate
Write-GreywardResult -Data @{release=$release} -Message 'DEPLOY OK'
