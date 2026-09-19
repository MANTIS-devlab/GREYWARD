[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$IsoPath,
    [Parameter(Mandatory)][string]$VmxPath,
    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Vmrun {
    $command = Get-Command vmrun.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidate = Join-Path ${env:ProgramFiles} 'VMware\VMware Workstation\vmrun.exe'
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    throw 'vmrun.exe is not installed; VMware candidate execution cannot be controlled safely.'
}

function Resolve-Python {
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command) { return [pscustomobject]@{ Path = $command.Source; Arguments = @() } }
    $command = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($command) { return [pscustomobject]@{ Path = $command.Source; Arguments = @('-3') } }
    throw 'Python 3 is required for direct ISO/Rock Ridge validation.'
}

function Get-VmxValue {
    param([string]$Text, [string]$Key)
    $pattern = '(?m)^' + [regex]::Escape($Key) + '\s*=\s*"([^"]*)"\s*$'
    $match = [regex]::Match($Text, $pattern)
    if ($match.Success) { return $match.Groups[1].Value }
    return $null
}

function Add-Failure {
    param([string]$Message)
    $script:Failures.Add($Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

$Failures = [System.Collections.Generic.List[string]]::new()
$iso = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $IsoPath).Path)
$vmx = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $VmxPath).Path)
$result = [ordered]@{
    schema = 'greyward.vmware-candidate/v1'
    iso = $iso
    isoSha256 = $null
    vmx = $vmx
    checks = [ordered]@{}
    failures = @()
}

try {
    $result.isoSha256 = (Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "ISO SHA256: $($result.isoSha256)"

    $vmxText = Get-Content -Raw -LiteralPath $vmx
    $bootOrder = Get-VmxValue $vmxText 'bios.bootOrder'
    $dvdPath = Get-VmxValue $vmxText 'sata0:1.fileName'
    if ($bootOrder -and $bootOrder -match '(?i)(cdrom|sata0:1)') {
        Add-Failure "VMX keeps the ISO in persistent boot order: $bootOrder"
    } else {
        Write-Host "[PASS] Persistent boot order is disk-first ($bootOrder)" -ForegroundColor Green
    }
    if (-not $dvdPath) { Add-Failure 'VMX has no sata0:1 ISO mapping.' }
    else {
        $vmxIso = [IO.Path]::GetFullPath($dvdPath)
        if ($vmxIso -ine $iso) { Add-Failure "VMX ISO mapping does not match candidate: $vmxIso" }
        else { Write-Host '[PASS] VMX points to the requested candidate ISO' -ForegroundColor Green }
    }
    $result.checks.bootOrder = $bootOrder
    $result.checks.dvdPath = $dvdPath

    $vmrun = Resolve-Vmrun
    $running = (& $vmrun list 2>$null | Select-String -SimpleMatch $vmx)
    if ($running) { Add-Failure 'VMware VM is running; candidate preflight requires it to be powered off.' }
    else { Write-Host '[PASS] VMware VM is powered off' -ForegroundColor Green }

    $python = Resolve-Python
    $isoChecker = Join-Path $PSScriptRoot 'validate-vmware-iso.py'
    $isoOutput = @(& $python.Path @($python.Arguments) $isoChecker --iso $iso 2>&1)
    $isoExit = $LASTEXITCODE
    $isoOutput | ForEach-Object { Write-Host $_ }
    if ($isoExit -ne 0) {
        foreach ($line in $isoOutput | Where-Object { $_ -match '^(ISO production payload is missing|ISO RPM closure|Payload hash mismatch|Manifest file missing|Malformed payload|VMWARE_ISO_VALIDATION=)' }) {
            Add-Failure $line
        }
    } else {
        Write-Host '[PASS] ISO production closure and payload hashes are valid' -ForegroundColor Green
    }
    $result.checks.isoValidationExitCode = $isoExit
}
catch {
    Add-Failure $_.Exception.Message
}
$result.failures = @($Failures)
if ($ReportPath) {
    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($ReportPath))
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

if ($Failures.Count) {
    Write-Host "VMWARE_CANDIDATE=FAIL ($($Failures.Count) failure(s))" -ForegroundColor Red
    exit 1
}
Write-Host 'VMWARE_CANDIDATE=PASS' -ForegroundColor Green
