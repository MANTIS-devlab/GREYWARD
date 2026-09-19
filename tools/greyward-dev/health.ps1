[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'common.ps1')
try { Invoke-GreywardSsh 'true' } catch { Write-Host 'SSH             FAIL'; Write-Host 'RESULT: UNHEALTHY'; exit 1 }
Write-Host 'SSH             OK'

$remote = @'
set -u
ok=1
check() { label="$1"; shift; if "$@" >/dev/null 2>&1; then printf '%-15s OK\n' "$label"; else printf '%-15s FAIL\n' "$label"; ok=0; fi; }
check SSH true
check SUDO sudo -n true
check NETWORK curl -fsS --max-time 8 https://fedoraproject.org
marker=$(cat "$HOME/.config/greyward/compositor" 2>/dev/null || printf 'hyprland')
check UWSM pgrep -u "$USER" -f 'uwsm|labwc|Hyprland'
if [ "$marker" = labwc ]; then
  check LABWC pgrep -u "$USER" -x labwc
else
  check HYPRLAND pgrep -u "$USER" -x Hyprland
fi
check QUICKSHELL pgrep -u "$USER" -f '(^|/)qs( |$)|quickshell'
check USER_SHELL systemctl --user is-active greyward-dms.service
check DMS_PIN bash -lc 'test -x /usr/local/bin/greyward-dms && test "$(cat /usr/local/share/greyward-dms/v1.5.3/COMMIT)" = 069ddab041c738236a8910e4c39b65d9628d3018'
check DMS_MONITOR bash -lc 'test -x /usr/bin/dgop'
check DMS_SEARCH bash -lc 'test -x /usr/bin/dsearch'
check GREETD sudo systemctl is-active greetd.service
check GREETER bash -lc 'test -x /usr/bin/dms-greeter && test -s /etc/greetd/config.toml && test -s /etc/pam.d/greetd'
check NO_AUTOLOGIN bash -lc '! test -e /etc/systemd/system/getty@tty1.service.d/autologin.conf'
if [ "$marker" = labwc ]; then
  check PORTALS pgrep -u "$USER" -f 'xdg-desktop-portal(-wlr)?'
else
  check PORTALS pgrep -u "$USER" -f 'xdg-desktop-portal(-hyprland)?'
fi
check PIPEWIRE pgrep -u "$USER" -x pipewire
runtime="/run/user/$(id -u)"
socket=$(find "$runtime" -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' 2>/dev/null | sort | head -n1)
if [ -n "$socket" ]; then printf '%-15s OK (%s)\n' WAYLAND "$socket"; else printf '%-15s FAIL\n' WAYLAND; ok=0; fi
capture=$(mktemp --suffix=.png /tmp/greyward-health.XXXXXX)
if [ -n "$socket" ] && XDG_RUNTIME_DIR="$runtime" WAYLAND_DISPLAY="$socket" timeout 12s grim "$capture" >/tmp/greyward-health.log 2>&1 && test -s "$capture"; then
  printf '%-15s OK\n' CAPTURE
else
  printf '%-15s FAIL\n' CAPTURE; ok=0
fi
rm -f "$capture" /tmp/greyward-health.log
if [ "$ok" -eq 1 ]; then echo 'RESULT: HEALTHY'; else echo 'RESULT: UNHEALTHY'; exit 1; fi
'@
try { Invoke-GreywardSessionSsh (ConvertTo-BashBase64Command $remote) } catch { Write-Host 'RESULT: UNHEALTHY'; exit 1 }
