[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')

Repair-GreywardSsh | Out-Null
Invoke-GreywardSessionSsh @'
set -euo pipefail
savepoint=/var/lib/greyward/savepoints/lunasuck/dms-v1.5.3.tar.gz
test -s "$savepoint"
sudo rm -rf /usr/local/share/greyward-dms/v1.5.3
sudo tar -C / -xzf "$savepoint"
systemctl --user restart greyward-dms.service
sleep 5
systemctl --user is-active greyward-dms.service | grep -qx active
'@

Write-GreywardResult -Data @{ savepoint = 'lunasuck' } -Message 'LUNASUCK ROLLBACK OK'
