[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Labwc','Hyprland')][string]$Compositor,
    [switch]$Restart
)
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null
$value = $Compositor.ToLowerInvariant()
Invoke-GreywardSsh "mkdir -p ~/.config/greyward; printf '%s' '$value' > ~/.config/greyward/compositor"
if ($Restart) {
    Invoke-GreywardSsh 'sudo -n systemctl reboot'
}
Write-GreywardResult -Data @{compositor=$value; restart=[bool]$Restart} -Message 'GREYWARD COMPOSITOR SELECTION UPDATED'
