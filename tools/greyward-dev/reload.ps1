[CmdletBinding()]
param([switch]$Hard)
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
$remote = if ($Hard) {
    'systemctl --user restart greyward-dms.service'
} else {
    'systemctl --user restart greyward-dms.service'
}
Invoke-GreywardSessionSsh $remote
Start-Sleep -Milliseconds 800
Invoke-GreywardSessionSsh "systemctl --user is-active greyward-dms.service"
Write-GreywardResult -Data @{hard=[bool]$Hard} -Message 'RELOAD OK'
