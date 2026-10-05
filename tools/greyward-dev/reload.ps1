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
$readiness = @'
set -eu
deadline=$((SECONDS + 30))
while (( SECONDS < deadline )); do
  if /usr/local/libexec/greyward-dms-runtime-check; then exit 0; fi
  sleep 1
done
echo 'Reload did not establish working backend and shell IPC.' >&2
exit 1
'@
Invoke-GreywardSessionSsh (ConvertTo-BashBase64Command $readiness)
Write-GreywardResult -Data @{hard=[bool]$Hard} -Message 'RELOAD OK'
