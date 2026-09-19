[CmdletBinding()]
param(
    [ValidateSet('Python', 'Frontend', 'Rust', 'Dms', 'Service')]
    [string]$Component = 'Python',
    [switch]$Reset
)

. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null

$devRoot = '/home/stendev/.local/share/greyward/dev'
$securityRoot = "$devRoot/security-center"
$cargoTarget = '/home/stendev/.cache/greyward/cargo-target'
$sourceRoot = Join-Path $script:RepoRoot 'security-center'

if ($Reset) {
    Invoke-GreywardSsh "rm -rf '$devRoot' '$cargoTarget'; mkdir -p '$devRoot' '$cargoTarget'"
    Write-GreywardResult -Data @{component='all'; source=$devRoot; cargo_target=$cargoTarget} -Message 'SECURITY CENTER FAST WORKSPACE RESET OK'
    exit 0
}

Invoke-GreywardSsh "mkdir -p '$devRoot' '$securityRoot' '$cargoTarget'"

function Ensure-DevCargoSource {
    try {
        Invoke-GreywardSsh "test -f '$securityRoot/Cargo.toml'"
    } catch {
        Invoke-GreywardScp -Recursive -Source $sourceRoot -Destination "$($script:SshAlias):$devRoot/"
    }
}

switch ($Component) {
    'Python' {
        Invoke-GreywardScp -Recursive -Source (Join-Path $sourceRoot 'security-context') -Destination "$($script:SshAlias):$securityRoot/"
        $override = "[Service]`nEnvironment=PYTHONPATH=$securityRoot/security-context`nExecStart=`nExecStart=/usr/bin/python3 $securityRoot/security-context/greyward_security_context/session10_bus.py`n"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($override))
        $remote = @"
mkdir -p ~/.config/systemd/user/greyward-security-context-user.service.d
printf '%s' '$encoded' | base64 -d > ~/.config/systemd/user/greyward-security-context-user.service.d/development.conf
systemctl --user daemon-reload
systemctl --user restart greyward-security-context-user.service
systemctl --user is-active greyward-security-context-user.service
"@
        Invoke-GreywardSessionSsh ($remote.Trim())
        Write-GreywardResult -Data @{component='python'; source="$securityRoot/security-context"; restart='greyward-security-context-user.service'} -Message 'SECURITY CENTER FAST PYTHON ITERATION OK'
    }
    'Frontend' {
        Ensure-DevCargoSource
        Invoke-GreywardScp -Recursive -Source (Join-Path $sourceRoot 'tauri\frontend') -Destination "$($script:SshAlias):$securityRoot/tauri/"
        $remote = @'
cd __SECURITY_ROOT__
export CARGO_TARGET_DIR=__CARGO_TARGET__
pkill -u "$USER" -f "$CARGO_TARGET_DIR/(debug|release)/greyward-security-center" >/dev/null 2>&1 || true
pkill -u "$USER" -f 'cargo run --locked -p greyward-security-center' >/dev/null 2>&1 || true
pkill -u "$USER" -f '/usr/bin/greyward-security-center( |$)' >/dev/null 2>&1 || true
nohup cargo run --locked -p greyward-security-center --features custom-protocol >/tmp/greyward-security-center-fast.log 2>&1 </dev/null &
for attempt in $(seq 1 120); do
  pgrep -u "$USER" -f "$CARGO_TARGET_DIR/debug/greyward-security-center" >/dev/null && exit 0
  sleep 1
done
tail -n 80 /tmp/greyward-security-center-fast.log
exit 1
'@
        $remote = $remote.Replace('__SECURITY_ROOT__', $securityRoot).Replace('__CARGO_TARGET__', $cargoTarget)
        Invoke-GreywardSessionSsh ($remote.Trim())
        Write-GreywardResult -Data @{component='frontend'; source="$securityRoot/tauri/frontend"; cargo_target=$cargoTarget; mode='incremental cargo run'} -Message 'SECURITY CENTER FAST FRONTEND ITERATION OK'
    }
    'Rust' {
        Ensure-DevCargoSource
        Invoke-GreywardScp -Recursive -Source (Join-Path $sourceRoot 'crates') -Destination "$($script:SshAlias):$securityRoot/"
        Invoke-GreywardScp -Recursive -Source (Join-Path $sourceRoot 'tauri\src-tauri') -Destination "$($script:SshAlias):$securityRoot/tauri/"
        Invoke-GreywardScp -Source (Join-Path $sourceRoot 'Cargo.toml') -Destination "$($script:SshAlias):$securityRoot/Cargo.toml"
        Invoke-GreywardScp -Source (Join-Path $sourceRoot 'Cargo.lock') -Destination "$($script:SshAlias):$securityRoot/Cargo.lock"
        $remote = @'
cd __SECURITY_ROOT__
export CARGO_TARGET_DIR=__CARGO_TARGET__
cargo check --locked -p greyward-security-center --features custom-protocol
'@
        $remote = $remote.Replace('__SECURITY_ROOT__', $securityRoot).Replace('__CARGO_TARGET__', $cargoTarget)
        Invoke-GreywardSessionSsh ($remote.Trim())
        Write-GreywardResult -Data @{component='rust'; source=$securityRoot; cargo_target=$cargoTarget; command='cargo check --locked -p greyward-security-center --features custom-protocol'} -Message 'SECURITY CENTER FAST RUST CHECK OK'
    }
    'Dms' {
        $pluginSource = Join-Path $script:RepoRoot 'environment\session\dankmaterialshell\plugins\greywardSecure'
        Invoke-GreywardSsh "mkdir -p '$devRoot/dankmaterialshell/plugins'"
        Invoke-GreywardScp -Recursive -Source $pluginSource -Destination "$($script:SshAlias):$devRoot/dankmaterialshell/plugins/"
        $remote = @'
mkdir -p ~/.config/DankMaterialShell/plugins/greywardSecure
cp -a __DEV_ROOT__/dankmaterialshell/plugins/greywardSecure/. ~/.config/DankMaterialShell/plugins/greywardSecure/
systemctl --user restart greyward-dms.service
systemctl --user is-active greyward-dms.service
'@
        $remote = $remote.Replace('__DEV_ROOT__', $devRoot)
        Invoke-GreywardSessionSsh ($remote.Trim())
        Write-GreywardResult -Data @{component='dms'; source="$devRoot/dankmaterialshell/plugins/greywardSecure"; restart='greyward-dms.service'} -Message 'SECURITY CENTER FAST DMS ITERATION OK'
    }
    'Service' {
        $systemdSource = Join-Path $sourceRoot 'security-context\systemd'
        Invoke-GreywardSsh "mkdir -p '$securityRoot/security-context'"
        Invoke-GreywardScp -Recursive -Source $systemdSource -Destination "$($script:SshAlias):$securityRoot/security-context/"
        $remote = @'
for unit in greyward-opensnitch-control-plane.service greyward-opensnitch-policy.service greyward-clamav-scan.service greyward-secure-dns.service; do
  if [ -f __SECURITY_ROOT__/security-context/systemd/$unit ]; then sudo install -D -m 0644 __SECURITY_ROOT__/security-context/systemd/$unit /etc/systemd/system/$unit; fi
done
sudo systemctl daemon-reload
sudo systemctl restart greyward-opensnitch-control-plane.service greyward-opensnitch-policy.service greyward-clamav-scan.service greyward-secure-dns.service
'@
        $remote = $remote.Replace('__SECURITY_ROOT__', $securityRoot)
        Invoke-GreywardSessionSsh ($remote.Trim())
        Write-GreywardResult -Data @{component='service'; source="$securityRoot/security-context/systemd"; mode='component synchronization and restart'} -Message 'SECURITY CENTER FAST SERVICE ITERATION OK'
    }
}
