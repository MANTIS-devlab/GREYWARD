[CmdletBinding(SupportsShouldProcess)]
param()
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
if (-not $PSCmdlet.ShouldProcess($script:GreywardVmName, 'Restore prior Plymouth theme and uninstall GREYWARD branding')) { return }
$restore = @'
set -euo pipefail
sudo dnf -y remove greyward-branding
if [ -s /var/lib/greyward-previous-plymouthd.conf ]; then
  sudo cp -a /var/lib/greyward-previous-plymouthd.conf /etc/plymouth/plymouthd.conf
else
  sudo rm -f /etc/plymouth/plymouthd.conf
fi
sudo dracut --regenerate-all --force
'@
Invoke-GreywardSsh (ConvertTo-BashBase64Command $restore)
Write-GreywardResult -Data @{restored=$true} -Message 'BOOT BRANDING RESTORED'
