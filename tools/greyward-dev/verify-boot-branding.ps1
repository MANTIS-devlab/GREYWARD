[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
$verify = @'
set -euo pipefail
theme=$(plymouth-set-default-theme 2>/dev/null || true)
rpm -q greyward-branding >/dev/null
[ "$theme" = "greyward" ]
test -f /usr/lib/systemd/system/greyward-update-status.service
test -L /usr/lib/systemd/system/system-update.target.wants/greyward-update-status.service
grep -F 'ExecStart=/usr/bin/plymouth change-mode --updates' /usr/lib/systemd/system/greyward-update-status.service >/dev/null
grep -F 'ExecStart=/usr/bin/plymouth display-message "--text=GREYWARD system update in progress"' /usr/lib/systemd/system/greyward-update-status.service >/dev/null
grep -F 'Plymouth.SetSystemUpdateFunction(system_update_callback)' /usr/share/plymouth/themes/greyward/greyward.script >/dev/null
grep -F 'Installing system updates' /usr/share/plymouth/themes/greyward/greyward.script >/dev/null
found=0
listing=$(mktemp)
trap 'rm -f "$listing"' EXIT
for image in /boot/initramfs-*.img; do
  [ -f "$image" ] || continue
  if sudo lsinitrd "$image" >"$listing" 2>/dev/null; then
    if grep -F 'greyward.script' "$listing" >/dev/null; then
      found=1
      break
    fi
  fi
done
[ "$found" -eq 1 ]
printf '{"theme":"%s","initramfs":true}\n' "$theme"
'@
Invoke-GreywardSsh (ConvertTo-BashBase64Command $verify)
Write-GreywardResult -Data @{theme='greyward'; initramfs=$true} -Message 'BOOT BRANDING VERIFIED'
