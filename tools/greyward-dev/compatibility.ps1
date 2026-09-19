[CmdletBinding()]
param([ValidateSet(100,125)][int]$ScalePercent = 100)
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
$checks = [ordered]@{}
$commands = [ordered]@{
    portals = 'systemctl --user is-active xdg-desktop-portal.service xdg-desktop-portal-wlr.service'
    audio = 'systemctl --user is-active pipewire.service pipewire-pulse.service wireplumber.service'
    notifications = 'qs ipc call greyward health'
    clipboard = 'printf greyward-compat | wl-copy; test "$(wl-paste)" = greyward-compat'
    xwayland = 'pgrep -x Xwayland >/dev/null'
    network = 'nmcli -t general status'
    fileDialogs = 'busctl --user introspect org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop >/dev/null'
}
foreach ($name in $commands.Keys) {
    try { $output = @(Invoke-GreywardSsh $commands[$name]); $checks[$name] = @{ok=$true; output=$output} }
    catch { $checks[$name] = @{ok=$false; error=$_.Exception.Message} }
}
try {
    Invoke-GreywardSsh 'wlr-randr >/dev/null'
    & (Join-Path $PSScriptRoot 'capture.ps1') -Output "output\greyward-runtime\compat-$ScalePercent.png"
    $checks.scaling = @{ok=$true; percent=$ScalePercent}
} catch { $checks.scaling = @{ok=$false; error=$_.Exception.Message} }
$healthy = -not ($checks.Values | Where-Object { -not $_.ok })
Write-GreywardResult -Data @{healthy=$healthy; scalePercent=$ScalePercent; checks=$checks} -Message $(if ($healthy) {'COMPATIBILITY HEALTHY'} else {'COMPATIBILITY UNHEALTHY'})
if (-not $healthy) { exit 1 }
