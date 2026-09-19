[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')
& (Join-Path $PSScriptRoot 'health.ps1')
if ($LASTEXITCODE -ne 0) { exit 1 }

$gateDir = Join-Path $script:RepoRoot 'output\graphics-gate'
New-Item -ItemType Directory -Force -Path $gateDir | Out-Null

# This is a VMware diagnostic, not a request to manufacture a missing mode.
# The kernel DRM list and wlroots list must agree before a shell issue can be
# diagnosed. Keep the report even when the requested test resolution is absent.
$report = @'
set -eu
printf '%s\n' '[session]'
printf 'compositor='; pgrep -u "$USER" -x labwc >/dev/null && printf 'labwc\n' || printf 'not-labwc\n'
printf 'renderer='; printf '%s\n' "${WLR_RENDERER:-default}"
printf 'session-type='; printf '%s\n' "${XDG_SESSION_TYPE:-unknown}"
printf '%s\n' '[vmware-tools-packages]'
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 'open-vm-tools*' 2>/dev/null || true
printf '%s\n' '[vmware-tools-system-service]'
systemctl is-enabled vmtoolsd.service 2>/dev/null || true
systemctl is-active vmtoolsd.service 2>/dev/null || true
systemctl status --no-pager --lines=40 vmtoolsd.service 2>&1 || true
printf '%s\n' '[vmware-tools-user-process]'
pgrep -a vmtoolsd 2>/dev/null || true
systemctl --user --no-pager --all list-units 'vmtoolsd*' 'vmware*' 2>&1 || true
printf '%s\n' '[vmware-tools-resolution-plugins]'
for plugin in /usr/lib64/open-vm-tools/plugins/vmsvc/libresolutionKMS.so /usr/lib64/open-vm-tools/plugins/vmusr/libresolutionSet.so; do
  test -e "$plugin" && printf '%s\n' "$plugin"
done
test -r /etc/vmware-tools/tools.conf && sed -n '/^\[resolutionKMS\]/,/^\[/p' /etc/vmware-tools/tools.conf || true
printf '%s\n' '[vmwgfx-kernel]'
journalctl -b -k --no-pager 2>/dev/null | grep -i vmwgfx || true
printf '%s\n' '[wlr-randr]'
wlr-randr || true
printf '%s\n' '[drm-modes]'
for modes in /sys/class/drm/card*-*/modes; do
  test -r "$modes" || continue
  printf '%s\n' "${modes%/modes}"
  cat "$modes"
done
'@
Invoke-GreywardSessionSsh (ConvertTo-BashBase64Command $report) | Set-Content (Join-Path $gateDir 'display-diagnostic.txt')

& (Join-Path $PSScriptRoot 'capture.ps1') -Output 'output\graphics-gate\current-output.png'
if (-not (Test-Path (Join-Path $gateDir 'current-output.png'))) {
    throw 'Graphics gate did not produce a current-output capture.'
}
Write-GreywardResult -Data @{ diagnostic = (Join-Path $gateDir 'display-diagnostic.txt'); capture = (Join-Path $gateDir 'current-output.png') } -Message 'GRAPHICS GATE OK — Labwc/DRM diagnostic captured'
