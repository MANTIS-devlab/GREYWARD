[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'tools\greyward-dev\common.ps1')
& (Join-Path $repo 'tools\validate-branding.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Branding validation failed.' }
foreach ($required in @(
    'branding\generated\boot\greyward-symbol-256.png')) {
    if (-not (Test-Path (Join-Path $repo $required))) { throw "Missing $required; run tools\generate-branding.ps1 first." }
}
Repair-GreywardSsh | Out-Null
$remote = '/tmp/greyward-rpmbuild'
Invoke-GreywardSsh "rm -rf '$remote'; mkdir -p '$remote/SPECS' '$remote/SOURCES' '$remote/RPMS' '$remote/BUILD' '$remote/BUILDROOT' '$remote/SRPMS'"
Invoke-GreywardScp -Recursive -Source (Join-Path $repo 'packaging\greyward-branding\SPECS\.') -Destination "$($script:SshAlias):$remote/SPECS"
Invoke-GreywardScp -Recursive -Source (Join-Path $repo 'packaging\greyward-branding\SOURCES\.') -Destination "$($script:SshAlias):$remote/SOURCES"
Invoke-GreywardScp -Source (Join-Path $repo 'branding\generated\boot\greyward-symbol-256.png') -Destination "$($script:SshAlias):$remote/SOURCES/greyward-symbol-256.png"
Invoke-GreywardScp -Source (Join-Path $repo 'branding\source\greyward-symbol.svg') -Destination "$($script:SshAlias):$remote/SOURCES/greyward-symbol.svg"
Invoke-GreywardSsh "if ! command -v rpmbuild >/dev/null 2>&1; then sudo dnf -y install rpm-build; fi; rpmbuild --define '_topdir $remote' -bb '$remote/SPECS/greyward-branding.spec'"
$out = Join-Path $repo 'build\rpm'
New-Item -ItemType Directory -Force -Path $out | Out-Null
Invoke-GreywardScp -Recursive -Source "$($script:SshAlias):$remote/RPMS/." -Destination $out
@{ok=$true; output=$out; message='Branding RPM built.'} | ConvertTo-Json -Compress
