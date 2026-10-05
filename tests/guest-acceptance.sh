#!/usr/bin/env bash
set -euo pipefail
runtime="/run/user/$(id -u)"
socket=$(find "$runtime" -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' | sort | head -n1)
signature=$(find "$runtime/hypr" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | head -n1 || true)
test -n "$socket"
export XDG_RUNTIME_DIR="$runtime"
export WAYLAND_DISPLAY="$socket"
if [ -n "$signature" ]; then export HYPRLAND_INSTANCE_SIGNATURE="$signature"; fi
if [ -S "$runtime/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus"; fi
compositor=$(cat "$HOME/.config/greyward/compositor" 2>/dev/null || printf 'hyprland')
sudo -n true
systemctl is-enabled sshd NetworkManager hypervkvpd
systemctl --user is-active greyward-dms.service pipewire.service wireplumber.service
sudo systemctl is-active greetd.service
test -x /usr/bin/dms-greeter
test -s /etc/pam.d/greetd
test "$(systemctl --user is-enabled greyward-dms.service || true)" = enabled
runtime_root=$(/usr/libexec/greyward-dms-verify)
receipt="$runtime_root/release.json"
/usr/local/libexec/greyward-dms-runtime-check
test -x /usr/bin/dsearch
if [ "$compositor" = labwc ]; then
  systemctl --user is-active xdg-desktop-portal.service xdg-desktop-portal-wlr.service
  pgrep -u "$USER" -x labwc >/dev/null
else
  systemctl --user is-active xdg-desktop-portal.service xdg-desktop-portal-hyprland.service
  pgrep -u "$USER" -x Hyprland >/dev/null
fi
rpm -q labwc xdg-desktop-portal-wlr quickshell uwsm hyperv-daemons
if [ "$compositor" != labwc ]; then
  rpm -q hyprland
  test "$(rpm -q --qf '%{VERSION}' hyprland)" = 0.56.2
fi
test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' quickshell)" = "$(jq -r '.compatibility.quickshell' "$receipt")"
if [ "$compositor" = labwc ]; then
  wlr-randr >/dev/null
else
  hyprctl monitors -j | jq -e 'length > 0'
fi
grim /tmp/greyward-acceptance.png
test -s /tmp/greyward-acceptance.png
echo 'RESULT: HEALTHY'
