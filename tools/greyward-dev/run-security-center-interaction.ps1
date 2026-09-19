[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null

$devRoot = '/home/stendev/.local/share/greyward/dev'
$securityRoot = "$devRoot/security-center"
$cargoTarget = '/home/stendev/.cache/greyward/cargo-target'
$applicationPath = "$cargoTarget/debug/greyward-security-center"
$sourceRoot = Join-Path $script:RepoRoot 'security-center'
$tauriRoot = Join-Path $sourceRoot 'tauri'

Invoke-GreywardSsh "mkdir -p '$securityRoot/tauri/frontend' '$securityRoot/crates' '$cargoTarget'"
foreach ($frontendFile in @('app.js', 'i18n.js', 'index.html', 'styles.css', 'greyward-symbol.svg', 'interaction.test.mjs')) {
    Invoke-GreywardScp -Source (Join-Path $tauriRoot "frontend\$frontendFile") -Destination "$($script:SshAlias):$securityRoot/tauri/frontend/$frontendFile"
}
foreach ($toolingFile in @('package.json', 'package-lock.json')) {
    Invoke-GreywardScp -Source (Join-Path $tauriRoot $toolingFile) -Destination "$($script:SshAlias):$securityRoot/tauri/$toolingFile"
}
Invoke-GreywardSsh "mkdir -p '$securityRoot/tauri/dev'"
Invoke-GreywardScp -Source (Join-Path $tauriRoot 'dev\privacy-network-watchdog.sh') -Destination "$($script:SshAlias):$securityRoot/tauri/dev/privacy-network-watchdog.sh"
Invoke-GreywardSsh "chmod 0755 '$securityRoot/tauri/dev/privacy-network-watchdog.sh'"
Invoke-GreywardScp -Recursive -Source (Join-Path $sourceRoot 'crates') -Destination "$($script:SshAlias):$securityRoot/"
Invoke-GreywardScp -Recursive -Source (Join-Path $tauriRoot 'src-tauri') -Destination "$($script:SshAlias):$securityRoot/tauri/"
Invoke-GreywardScp -Source (Join-Path $sourceRoot 'Cargo.toml') -Destination "$($script:SshAlias):$securityRoot/Cargo.toml"
Invoke-GreywardScp -Source (Join-Path $sourceRoot 'Cargo.lock') -Destination "$($script:SshAlias):$securityRoot/Cargo.lock"

$buildCommand = @'
set -euo pipefail
test -x "$HOME/.cargo/bin/tauri-driver"
test -x /usr/bin/WebKitWebDriver
cd __SECURITY_ROOT__
export CARGO_TARGET_DIR=__CARGO_TARGET__
for pid in $(pgrep -u "$USER" -f '^/usr/bin/greyward-security-center( |$)' || true); do kill "$pid" || true; done
for pid in $(pgrep -u "$USER" -f 'cargo run --locked -p greyward-security-center' || true); do kill "$pid" || true; done
for pid in $(pgrep -u "$USER" -f '^__APPLICATION_PATH__( |$)' || true); do kill "$pid" || true; done
cargo build --locked -p greyward-security-center --features custom-protocol
test -x __APPLICATION_PATH__
'@
$buildCommand = $buildCommand.Replace('__SECURITY_ROOT__', $securityRoot).Replace('__CARGO_TARGET__', $cargoTarget).Replace('__APPLICATION_PATH__', $applicationPath)
Invoke-GreywardSessionSsh $buildCommand.Trim()

$watchdogPath = "$securityRoot/tauri/dev/privacy-network-watchdog.sh"
$testExitPath = "$securityRoot/tauri/.interaction.exit"
$testLogPath = "$securityRoot/tauri/.interaction.log"
$testCommand = @'
set -euo pipefail
runtime="/run/user/$(id -u)"
socket=$(find "$runtime" -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' -quit)
test -n "$socket"
export XDG_RUNTIME_DIR="$runtime"
export WAYLAND_DISPLAY="$socket"
if [ -S "$runtime/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus"; fi
export GDK_BACKEND=wayland
export GREYWARD_TAURI_WEBDRIVER_URL='http://127.0.0.1:4444/'
export GREYWARD_TAURI_APPLICATION='__APPLICATION_PATH__'
export GREYWARD_INTERACTION_LOCAL=1
export GREYWARD_PRIVACY_WATCHDOG='__WATCHDOG_PATH__'
rm -f '__EXIT_PATH__'
driver_pid=''
cleanup() {
  if [ -n "$driver_pid" ]; then kill "$driver_pid" 2>/dev/null || true; fi
  for pid in $(pgrep -u "$USER" -f '^/usr/bin/WebKitWebDriver' || true); do kill "$pid" || true; done
  for pid in $(pgrep -u "$USER" -f '^__APPLICATION_PATH__( |$)' || true); do kill "$pid" || true; done
}
trap cleanup EXIT
"$HOME/.cargo/bin/tauri-driver" --port 4444 --native-port 4455 --native-driver /usr/bin/WebKitWebDriver >"$HOME/.cache/greyward-tauri-driver.log" 2>&1 &
driver_pid=$!
ready=0
for _ in $(seq 1 60); do
  if (echo > /dev/tcp/127.0.0.1/4444) 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
if [ "$ready" -ne 1 ]; then printf 'driver did not become ready\n' >&2; printf '1\n' > '__EXIT_PATH__'; exit 0; fi
cd '__TAURI_ROOT__'
npm ci --ignore-scripts --no-audit --no-fund
set +e
node --test frontend/interaction.test.mjs
code=$?
set -e
printf '%s\n' "$code" > '__EXIT_PATH__'
'@
$testCommand = $testCommand.Replace('__APPLICATION_PATH__', $applicationPath).Replace('__WATCHDOG_PATH__', $watchdogPath).Replace('__EXIT_PATH__', $testExitPath).Replace('__TAURI_ROOT__', "$securityRoot/tauri")
$launchScript = ConvertTo-BashBase64Command -Script $testCommand.Trim()
$launchCommand = "nohup bash -c '$launchScript' >'$testLogPath' 2>&1 < /dev/null &"

try {
    Invoke-GreywardSessionSsh $launchCommand
    $deadline = (Get-Date).AddSeconds(360)
    $exitCode = $null
    do {
        $poll = & ssh '-F' $script:SshConfigPath '-o' 'BatchMode=yes' '-o' 'ConnectTimeout=3' $script:SshAlias "test -s '$testExitPath' && cat '$testExitPath' || true" 2>$null
        if ($LASTEXITCODE -eq 0 -and $poll -match '^\d+$') { $exitCode = [int]$poll.Trim(); break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if ($null -eq $exitCode) { throw "Guest-local interaction did not publish a result within the bounded recovery window. Inspect $testLogPath on GREYWARD-DEV." }
    $guestLog = Invoke-GreywardSsh "cat '$testLogPath'"
    if ($guestLog) { Write-Host $guestLog }
    if ($exitCode -ne 0) { throw "Real Tauri interaction test failed in the Fedora guest with exit code $exitCode." }
    Write-GreywardResult -Data @{component='tauri-webdriver'; application=$applicationPath; driver='guest-local tauri-driver 2 + WebKitWebDriver'; endpoint='127.0.0.1:4444 inside GREYWARD-DEV'; scenarios='SC-PRV-001,SC-PRV-002,SC-ACT-001,SC-ACT-002,SC-ACT-003,SC-NET-003'} -Message 'SECURITY CENTER REAL TAURI INTERACTION OK'
} finally {
    try {
        $cleanupCommand = 'for pid in $(pgrep -u "$USER" -f "^/home/stendev/.cargo/bin/tauri-driver" || true); do kill "$pid" || true; done; for pid in $(pgrep -u "$USER" -f "^/usr/bin/WebKitWebDriver" || true); do kill "$pid" || true; done; for pid in $(pgrep -u "$USER" -f "^/usr/bin/greyward-security-center( |$)" || true); do kill "$pid" || true; done; for pid in $(pgrep -u "$USER" -f "^__APPLICATION_PATH__( |$)" || true); do kill "$pid" || true; done'.Replace('__APPLICATION_PATH__', $applicationPath)
        if (Test-GreywardSshKeyAccess) { Invoke-GreywardSsh $cleanupCommand }
    } catch { Write-Warning "Unable to clean up the Fedora interaction processes: $($_.Exception.Message)" }
}
