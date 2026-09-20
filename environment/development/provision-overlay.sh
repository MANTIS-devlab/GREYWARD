#!/usr/bin/env bash
set -euo pipefail

# This script is only for GREYWARD-DEV. It must never be called by a future
# production image builder as part of the installed system definition.
test -f /etc/greyward/production-system

install -d -m 0755 /etc/greyward
cat > /etc/greyward/development-overlay <<'EOF'
GREYWARD development overlay
This VM intentionally has developer-only access and tooling.
EOF
chmod 0644 /etc/greyward/development-overlay

mapfile -t development_packages < <(grep -Ev '^[[:space:]]*(#|$)' /tmp/greyward-development-packages.txt)
dnf -y install "${development_packages[@]}"

install -d -m 0755 /etc/sudoers.d
printf '%s\n' 'stendev ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-greyward-dev
chmod 0440 /etc/sudoers.d/90-greyward-dev

systemctl enable sshd hypervkvpd

# The VM-specific renderer and virtual-display settings are intentionally
# applied only to the developer account. Production receives hardware-neutral
# Labwc defaults from environment/production. Packer stages the shared Labwc
# source at /tmp/greyward-production/labwc (the production provisioner then
# consumes that same path), so keep the development overlay on that canonical
# stage path instead of relying on a nested source-tree layout.
if id stendev >/dev/null 2>&1 && [ -d /tmp/greyward-production/labwc ]; then
  user_home=/home/stendev
  install -d -o stendev -g stendev -m 0755 "$user_home/.config/labwc" "$user_home/.config/DankMaterialShell" \
    "$user_home/.config/hypr" "$user_home/.config/greyward" "$user_home/.local/bin"
  install -D -o stendev -g stendev -m 0644 /tmp/greyward-production/labwc/rc.xml /home/stendev/.config/labwc/rc.xml
  install -D -o stendev -g stendev -m 0644 /tmp/greyward-production/labwc/environment /home/stendev/.config/labwc/environment
  install -D -o stendev -g stendev -m 0755 /tmp/greyward-production/labwc/autostart /home/stendev/.config/labwc/autostart
  cp -a /tmp/greyward-production/dankmaterialshell/. "$user_home/.config/DankMaterialShell/"
  install -D -o stendev -g stendev -m 0644 /tmp/greyward-production/branding/source/greyward-symbol.svg "$user_home/.config/DankMaterialShell/greyward-symbol.svg"
  install -D -m 0644 /tmp/greyward-production/dankmaterialshell/greyward-obsidian.json /usr/share/greyward/dms/greyward-obsidian.json
  install -D -m 0644 /tmp/greyward-production/branding/source/greyward-symbol.svg /usr/share/greyward/dms/greyward-symbol.svg
  install -d -o greeter -g greeter -m 2770 /var/cache/dms-greeter
  install -d -m 0755 /usr/share/backgrounds/greyward
  find /tmp/greyward-production/branding/wallpaper -maxdepth 1 -type f -name 'greyward-wallpaper-*.jpg' -exec install -m 0644 {} /usr/share/backgrounds/greyward/ \;
  for wallpaper_file in \
    greyward-wallpaper-black-art-4k.jpg \
    greyward-wallpaper-2109-4k.jpg; do
    test -f "/usr/share/backgrounds/greyward/$wallpaper_file"
  done
  rm -f "$user_home/.config/DankMaterialShell/greyward-wallpaper.png"
  ln -s /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg "$user_home/.config/DankMaterialShell/greyward-wallpaper.png"
  install -D -o greeter -g greeter -m 0644 /tmp/greyward-production/dankmaterialshell/settings.json /var/cache/dms-greeter/settings.json
  install -D -o greeter -g greeter -m 0644 /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg /var/cache/dms-greeter/greeter_wallpaper_override.jpg
  install -D -o greeter -g greeter -m 0644 /dev/null /var/cache/dms-greeter/session.json
  cat > /var/cache/dms-greeter/session.json <<'EOF'
{
  "wallpaperPath": "/usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg",
  "wallpaperFillMode": "PreserveAspectCrop"
}
EOF
  install -D -o stendev -g stendev -m 0644 /tmp/greyward-production/session/hyprland.conf "$user_home/.config/hypr/hyprland.conf"
  install -D -o stendev -g stendev -m 0644 /tmp/greyward-production/session/greyward-decoration.tokens.conf "$user_home/.config/hypr/greyward-decoration.tokens.conf"
  install -D -o stendev -g stendev -m 0755 /tmp/greyward-production/session/greyward-minimize.sh "$user_home/.local/bin/greyward-minimize"
  install -D -o stendev -g stendev -m 0755 /tmp/greyward-production/session/greyward-restore.sh "$user_home/.local/bin/greyward-restore"
  printf '%s\n' 'labwc' > "$user_home/.config/greyward/compositor"
  chown -R stendev:stendev "$user_home/.config" "$user_home/.local"
fi
