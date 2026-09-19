[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'common.ps1')
$value = Get-Clipboard -Raw -TextFormatType Text
if ($null -eq $value -or $value.IndexOf([char]0) -ge 0) { throw 'Clipboard is empty or not plain text.' }
Repair-GreywardSsh | Out-Null
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))
Invoke-GreywardSsh "runtime=/run/user/`$(id -u); socket=`$(find `$runtime -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' | head -n1); echo '$encoded' | base64 -d | XDG_RUNTIME_DIR=`$runtime WAYLAND_DISPLAY=`$socket wl-copy"
Write-GreywardResult -Data @{characters=$value.Length} -Message 'CLIPBOARD TO VM OK'

