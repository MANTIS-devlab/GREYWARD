[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$common = Join-Path $root 'tools\greyward-dev\common.ps1'
$probe = Join-Path $env:TEMP ('greyward-ps51-compat-' + $PID)
New-Item -ItemType Directory -Force -Path $probe | Out-Null
$oldProfile = $env:USERPROFILE
try {
    $env:USERPROFILE = $probe
    . $common
    $key = Initialize-GreywardSshKey
    $public = "$key.pub"
    $derived = Get-GreywardValidatedPublicKey -PrivatePath $key -PublicPath $public
    if ([string]::IsNullOrWhiteSpace($derived)) { throw 'OpenSSH key validation returned no public key.' }
    $textPath = Join-Path $probe 'utf8.txt'
    Write-GreywardUtf8NoBom -Path $textPath -Content 'GREYWARD-PS51-UTF8'
    $bytes = [IO.File]::ReadAllBytes($textPath)
    if ($bytes.Length -lt 3 -or $bytes[0] -eq 0xEF -or $bytes[0] -eq 0xFF -or $bytes[0] -eq 0xFE) { throw 'UTF-8 no-BOM writer emitted an unexpected BOM.' }
    if ((Get-Content -Raw -LiteralPath $textPath) -ne 'GREYWARD-PS51-UTF8') { throw 'UTF-8 no-BOM round trip failed.' }
    @{powershell=$PSVersionTable.PSVersion.ToString(); keyLifecycle=$true; utf8NoBom=$true; message='PowerShell compatibility behavior passed.'} | ConvertTo-Json -Compress
} finally {
    $env:USERPROFILE = $oldProfile
    Remove-Item -LiteralPath $probe -Recurse -Force -ErrorAction SilentlyContinue
}
