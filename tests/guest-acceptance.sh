#!/usr/bin/env bash
set -euo pipefail
runtime="/run/user/$(id -u)"
socket=$(find "$runtime" -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' | sort | head -n1)
signature=$(find "$runtime/hypr" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | head -n1)
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
test "$(cat /usr/local/share/greyward-dms/v1.5.3/COMMIT)" = 069ddab041c738236a8910e4c39b65d9628d3018
test -x /usr/bin/dgop
test -x /usr/bin/dsearch
if [ "$compositor" = labwc ]; then
  systemctl --user is-active xdg-desktop-portal.service xdg-desktop-portal-wlr.service
  pgrep -u "$USER" -x labwc >/dev/null
else
  systemctl --user is-active xdg-desktop-portal.service xdg-desktop-portal-hyprland.service
  pgrep -u "$USER" -x Hyprland >/dev/null
fi
rpm -q labwc xdg-desktop-portal-wlr hyprland quickshell uwsm hyperv-daemons
test "$(rpm -q --qf '%{VERSION}' labwc)" = 0.9.6
test "$(rpm -q --qf '%{VERSION}' hyprland)" = 0.56.2
test "$(rpm -q --qf '%{VERSION}' quickshell)" = 0.3.0
if [ "$compositor" = labwc ]; then
  wlr-randr >/dev/null
else
  hyprctl monitors -j | jq -e 'length > 0'
fi
grim /tmp/greyward-acceptance.png
test -s /tmp/greyward-acceptance.png
echo 'RESULT: HEALTHY'
