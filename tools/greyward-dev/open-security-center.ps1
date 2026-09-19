[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')

# Reliable host-side escape hatch: start the known GREYWARD VM and launch the last RPM
# installed in its active graphical session. This does not rebuild the app.
Assert-HyperVAvailable
$vm = Get-VM -Name $script:GreywardVmName -ErrorAction Stop
if ($vm.State -ne 'Running') { Start-VM -VM $vm | Out-Null }
Repair-GreywardSsh -AllowHyperVFallback | Out-Null

$remote = @'
set -euo pipefail
runtime="/run/user/$(id -u)"
socket=$(find "$runtime" -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' -quit)
test -n "$socket"
export XDG_RUNTIME_DIR="$runtime"
export WAYLAND_DISPLAY="$socket"
if [ -S "$runtime/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus"; fi
test -x /usr/bin/greyward-security-center-launch
nohup /usr/bin/greyward-security-center-launch >/tmp/greyward-security-center-launch.log 2>&1 </dev/null &
printf '%s\n' 'GREYWARD SECURITY CENTER OPENED'
'@

Invoke-GreywardSessionSsh (ConvertTo-GreywardSessionCommand -Command $remote)
Write-GreywardResult -Data @{vm=$script:GreywardVmName; launcher='/usr/bin/greyward-security-center-launch'} -Message 'SECURITY CENTER OPEN OK'
