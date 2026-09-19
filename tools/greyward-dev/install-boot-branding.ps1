[CmdletBinding(SupportsShouldProcess)]
param()
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
$rpm = Get-ChildItem (Join-Path $script:RepoRoot 'build\rpm') -Recurse -Filter 'greyward-branding-*.rpm' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $rpm) { throw 'No branding RPM found. Run tools\build-branding-rpm.ps1.' }
if (-not $PSCmdlet.ShouldProcess($script:GreywardVmName, 'Install branding RPM, select Plymouth theme, and rebuild initramfs')) { return }
Invoke-GreywardScp -Source $rpm.FullName -Destination "$($script:SshAlias):/tmp/greyward-branding.rpm"
$install = @'
set -euo pipefail
if [ ! -e /var/lib/greyward-previous-plymouthd.conf ]; then
  if [ -e /etc/plymouth/plymouthd.conf ]; then
    sudo cp -a /etc/plymouth/plymouthd.conf /var/lib/greyward-previous-plymouthd.conf
  else
    sudo touch /var/lib/greyward-previous-plymouthd.conf
  fi
fi
sudo dnf -y install /tmp/greyward-branding.rpm
sudo plymouth-set-default-theme greyward
sudo dracut --regenerate-all --force
found=0
listing=$(mktemp)
for image in /boot/initramfs-*.img; do
  [ -f "$image" ] || continue
  if sudo lsinitrd "$image" >"$listing" 2>/dev/null; then
    if grep -F 'greyward.script' "$listing" >/dev/null; then
      found=1
      break
    fi
  fi
done
rm -f "$listing"
[ "$found" -eq 1 ]
'@
Invoke-GreywardSsh (ConvertTo-BashBase64Command $install)
Write-GreywardResult -Data @{rpm=$rpm.Name; theme='greyward'} -Message 'BOOT BRANDING INSTALLED'
