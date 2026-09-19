[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('enter', 'exit', 'status')]
    [string]$Action = 'status',
    [string]$VmHost = 'greyward-dev',
    [string]$VmUser = 'stendev',
    [string]$Identity = (Join-Path $env:USERPROFILE '.ssh\greyward-dev_ed25519')
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$theme = Join-Path $repo 'spikes\dms-v1.5.3\greyward-obsidian.json'
$settings = Join-Path $repo 'spikes\dms-v1.5.3\settings.json'
$hostSpec = "$VmUser@$VmHost"
$remoteTheme = '/tmp/greyward-obsidian.json'
$remoteSettings = '/tmp/greyward-dms-spike-settings.json'
$remoteState = '~/.local/state/greyward-dms-visual-spike'

function Invoke-Vm([string]$Command) {
    & ssh -i $Identity -o IdentitiesOnly=yes $hostSpec $Command
    if ($LASTEXITCODE -ne 0) { throw "VM command failed ($LASTEXITCODE): $Command" }
}

if ($Action -eq 'status') {
Invoke-Vm "printf '%s\n' 'dms visual spike status'; printf 'theme='; test -f ~/.config/DankMaterialShell/settings.json && grep -o 'greyward-obsidian.json' ~/.config/DankMaterialShell/settings.json || printf 'baseline'; printf '\n'; printf 'dms='; systemctl --user is-active greyward-dms.service"
    exit 0
}

if ($Action -eq 'enter') {
    if (-not $PSCmdlet.ShouldProcess($hostSpec, 'Apply isolated GREYWARD DMS visual theme')) { return }
    & scp -i $Identity -o IdentitiesOnly=yes $theme "$hostSpec`:$remoteTheme"
    if ($LASTEXITCODE -ne 0) { throw 'Could not upload the isolated theme' }
    & scp -i $Identity -o IdentitiesOnly=yes $settings "$hostSpec`:$remoteSettings"
    if ($LASTEXITCODE -ne 0) { throw 'Could not upload the isolated DMS settings' }
    Invoke-Vm "set -eu; mkdir -p $remoteState ~/.config/DankMaterialShell; if [ ! -e $remoteState/settings.json ]; then if [ -e ~/.config/DankMaterialShell/settings.json ]; then cp -p ~/.config/DankMaterialShell/settings.json $remoteState/settings.json; else : > $remoteState/no-settings; fi; fi; install -m 0644 $remoteTheme $remoteState/greyward-obsidian.json; install -m 0644 $remoteSettings ~/.config/DankMaterialShell/settings.json; systemctl --user restart greyward-dms.service; sleep 5; systemctl --user is-active greyward-dms.service | grep -qx active"
    Write-Host 'DMS visual spike entered. Capture the VM, then run -Action exit.'
    exit 0
}

if (-not $PSCmdlet.ShouldProcess($hostSpec, 'Restore canonical DMS visual settings')) { return }
Invoke-Vm "set -eu; if [ -e $remoteState/settings.json ]; then install -m 0644 $remoteState/settings.json ~/.config/DankMaterialShell/settings.json; else rm -f ~/.config/DankMaterialShell/settings.json; fi; rm -f ~/.config/DankMaterialShell/settings.json.tmp; rm -rf $remoteState; systemctl --user restart greyward-dms.service; sleep 5; systemctl --user is-active greyward-dms.service | grep -qx active"
Write-Host 'DMS visual spike exited; canonical DMS settings restored.'
