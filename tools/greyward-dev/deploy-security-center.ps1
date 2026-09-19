[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null

$release = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$remoteRoot = "/home/stendev/.local/share/greyward/security-center-releases/$release"
$source = Join-Path $script:RepoRoot 'security-center'

Invoke-GreywardSessionSsh "mkdir -p '$remoteRoot'"
$syncWatch = [Diagnostics.Stopwatch]::StartNew()
# The Rust target tree is disposable build output and can be several GiB.  Do
# not copy it to the VM as part of a source deployment; the Fedora builder
# creates its own target directory through GREYWARD_CARGO_TARGET_DIR.
Invoke-GreywardScp -Source (Join-Path $source 'Cargo.toml') -Destination "$($script:SshAlias):$remoteRoot/"
Invoke-GreywardScp -Source (Join-Path $source 'Cargo.lock') -Destination "$($script:SshAlias):$remoteRoot/"
foreach ($directory in @('crates', 'data', 'file-context', 'nautilus', 'packaging', 'security-context', 'tauri', 'tests', 'vendor')) {
    Invoke-GreywardScp -Recursive -Source (Join-Path $source $directory) -Destination "$($script:SshAlias):$remoteRoot/"
}
Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'environment\production') -Destination "$($script:SshAlias):$remoteRoot/"
Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'environment\development') -Destination "$($script:SshAlias):$remoteRoot/"
$syncWatch.Stop()
$sourceSyncMs = $syncWatch.ElapsedMilliseconds

$remote = @'
set -euo pipefail
release='__REMOTE_ROOT__'
root="$release/security-center"
cd "$root"

cargo_target="${GREYWARD_CARGO_TARGET_DIR:-$HOME/.cache/greyward/package-cargo-target}"
install -d -m 0700 "$cargo_target"

for command in cargo rpmbuild desktop-file-validate pkg-config; do
  command -v "$command" >/dev/null
done
pkg-config --exists webkit2gtk-4.1
test -f Cargo.lock
test -f packaging/greyward-security-center.spec
grep -q 'GREYWARD_LABWC_SERVER_DECORATIONS' data/greyward-security-center-launch
grep -q 'GREYWARD_LABWC_SERVER_DECORATIONS' vendor/tao-0.35.3/src/platform_impl/linux/window.rs

test_started=$SECONDS
CARGO_BUILD_JOBS="${GREYWARD_CARGO_BUILD_JOBS:-1}" CARGO_TARGET_DIR="$cargo_target" cargo test --workspace --locked
printf 'GREYWARD_TIMING stage=rust-tests seconds=%s\n' "$((SECONDS - test_started))"

rm -rf "$HOME/greyward-security-rpms"
rpm_started=$SECONDS
GREYWARD_SECURITY_CENTER_SOURCE="$root" \
GREYWARD_SECURITY_CENTER_OUTPUT="$HOME/greyward-security-rpms" \
GREYWARD_CARGO_TARGET_DIR="$cargo_target" \
CARGO_BUILD_JOBS="${GREYWARD_CARGO_BUILD_JOBS:-1}" \
GREYWARD_SKIP_RUST_TESTS=1 \
bash "$release/development/build-security-center.sh"
printf 'GREYWARD_TIMING stage=package-rpms seconds=%s\n' "$((SECONDS - rpm_started))"
center_rpm=$(find "$HOME/greyward-security-rpms" -type f \
  -name 'greyward-security-center-*.x86_64.rpm' | sort -V | tail -n1)
test -n "$center_rpm"
center_expected=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$center_rpm")

context_rpm=$(find "$HOME/greyward-security-rpms" -type f \
  -name 'greyward-security-context-*.noarch.rpm' | sort -V | tail -n1)
test -n "$context_rpm"
context_expected=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$context_rpm")

install_started=$SECONDS
center_current=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' greyward-security-center 2>/dev/null || true)
context_current=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' greyward-security-context 2>/dev/null || true)
if [ "$center_current" = "$center_expected" ] && \
   [ "$context_current" = "$context_expected" ]; then
  # The development RPM deliberately keeps a stable NEVRA between frontend
  # iterations. Reinstalling is therefore required to put the newly embedded
  # Tauri assets on the device instead of accepting an already-installed RPM.
  sudo dnf reinstall -y "$center_rpm" "$context_rpm"
else
  # Install also performs a normal upgrade when either build advanced its
  # NEVRA; dnf reinstall refuses a local package that is not the installed
  # version and would otherwise leave a mixed Security Center deployment.
  sudo dnf install -y "$center_rpm" "$context_rpm"
fi
printf 'GREYWARD_TIMING stage=rpm-install seconds=%s\n' "$((SECONDS - install_started))"

checks_started=$SECONDS
center_installed=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' greyward-security-center)
context_installed=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' greyward-security-context)
test "$center_installed" = "$center_expected"
test "$context_installed" = "$context_expected"
test -x /usr/libexec/greyward-recovery-point
test -x /usr/libexec/greyward-update-action
test -x /usr/libexec/greyward-backup
test "$(grep -c 'GREYWARD_LABWC_SERVER_DECORATIONS=1' /usr/bin/greyward-security-center-launch)" -eq 1
desktop-file-validate /usr/share/applications/systems.mantis.greyward.securitycenter.desktop
printf 'GREYWARD_TIMING stage=packaged-checks seconds=%s\n' "$((SECONDS - checks_started))"
printf 'GREYWARD SECURITY CENTER AND CONTEXT RPM DEPLOY OK\n'
'@
$remote = $remote.Replace('__REMOTE_ROOT__', $remoteRoot)

Invoke-GreywardSsh (ConvertTo-BashBase64Command -Script $remote)

$launch = @'
set -euo pipefail
launch_started=$SECONDS
test -x /usr/bin/greyward-security-center-launch
pkill -u "$USER" -f '(^|/)greyward-security-center( |$)' || true
nohup /usr/bin/greyward-security-center-launch >/tmp/greyward-security-center-launch.log 2>&1 </dev/null &
sleep 2
pgrep -u "$USER" -f '(^|/)greyward-security-center( |$)' >/dev/null
printf 'GREYWARD_TIMING stage=application-launch seconds=%s\n' "$((SECONDS - launch_started))"
printf 'GREYWARD SECURITY CENTER TAURI LAUNCH OK\n'
'@
Invoke-GreywardSessionSsh (ConvertTo-GreywardSessionCommand -Command $launch)
$healthWatch = [Diagnostics.Stopwatch]::StartNew()
& (Join-Path $PSScriptRoot 'health.ps1')
$healthWatch.Stop()
$healthMs = $healthWatch.ElapsedMilliseconds
Write-GreywardResult -Data @{release=$release; packages=@('greyward-security-center', 'greyward-security-context'); frontend='tauri'; timings=@{source_sync_ms=$sourceSyncMs; health_ms=$healthMs}} -Message 'SECURITY CENTER TAURI DEPLOY OK'
