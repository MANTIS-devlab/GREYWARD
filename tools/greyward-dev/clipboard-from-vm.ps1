[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
$value = Invoke-GreywardSsh "runtime=/run/user/`$(id -u); socket=`$(find `$runtime -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' | head -n1); XDG_RUNTIME_DIR=`$runtime WAYLAND_DISPLAY=`$socket wl-paste --no-newline"
$value | Set-Clipboard
Write-GreywardResult -Data @{characters=($value -join "`n").Length} -Message 'CLIPBOARD FROM VM OK'
