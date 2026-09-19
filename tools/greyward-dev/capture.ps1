[CmdletBinding()]
param([string]$Output = 'output\greyward-runtime\current.png')
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
$local = Join-Path $script:RepoRoot $Output
New-Item -ItemType Directory -Force -Path (Split-Path $local) | Out-Null
$remotePath = '/tmp/greyward-current.png'
$remote = @'
set -euo pipefail
runtime="/run/user/$(id -u)"
socket=$(find "$runtime" -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' -quit)
test -n "$socket"
XDG_RUNTIME_DIR="$runtime" WAYLAND_DISPLAY="$socket" timeout 20s grim /tmp/greyward-current.png
test -s /tmp/greyward-current.png
'@
Invoke-GreywardSsh (ConvertTo-BashBase64Command $remote)
Invoke-GreywardScp -Source "$($script:SshAlias):$remotePath" -Destination $local
$bytes = [IO.File]::ReadAllBytes($local)
$png = [byte[]](137,80,78,71,13,10,26,10)
$signatureOk = $bytes.Length -ge $png.Length
for ($i = 0; $signatureOk -and $i -lt $png.Length; $i++) {
    if ($bytes[$i] -ne $png[$i]) { $signatureOk = $false }
}
if ($bytes.Length -lt 1024 -or -not $signatureOk) { throw 'Capture is empty or does not have a PNG signature.' }
$width = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($bytes,16))
$height = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($bytes,20))
if ($width -lt 640 -or $height -lt 480) { throw "Unexpected capture dimensions: ${width}x${height}." }
Write-GreywardResult -Data @{path=$local; width=$width; height=$height; bytes=$bytes.Length} -Message 'CAPTURE OK'
