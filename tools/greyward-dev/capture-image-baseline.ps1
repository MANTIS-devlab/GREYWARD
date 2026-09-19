param([Parameter(Mandatory)][string]$Output)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$destination = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $destination) { throw "Baseline already exists: $destination" }
$captureId = [Guid]::NewGuid().ToString('N')
$temporary = Join-Path ([IO.Path]::GetTempPath()) "greyward-baseline-$captureId"
$remote = "/tmp/greyward-baseline-$captureId"
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $policy = Join-Path $temporary 'policy.json'
    $helper = Join-Path $script:RepoRoot 'environment/image/baseline.py'
    & python $helper policy --repo $script:RepoRoot --output $policy
    if ($LASTEXITCODE -ne 0) { throw 'Baseline policy generation failed.' }
    Invoke-GreywardSsh "mkdir -m 700 '$remote'" | Out-Null
    Invoke-GreywardScp -Source $helper -Destination "$($script:SshAlias):$remote/baseline.py" | Out-Null
    Invoke-GreywardScp -Source $policy -Destination "$($script:SshAlias):$remote/policy.json" | Out-Null
    Invoke-GreywardSessionSsh "python3 '$remote/baseline.py' capture --policy '$remote/policy.json' --output '$remote/baseline.json'" | Out-Null
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Invoke-GreywardScp -Source "$($script:SshAlias):$remote/baseline.json" -Destination (Join-Path $temporary 'baseline.json') | Out-Null
    $captured = Get-Content -Raw (Join-Path $temporary 'baseline.json') | ConvertFrom-Json
    if ($captured.schema -ne 'greyward.runtime-baseline/v1') { throw 'Invalid baseline response.' }
    Copy-Item -LiteralPath (Join-Path $temporary 'baseline.json') -Destination $destination
    Write-Output "Captured runtime baseline: $destination"
    Write-Output "SHA256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash)"
} finally {
    # Exact generated temporary paths only; no guest profile or source cleanup.
    Invoke-GreywardSsh "rm -f '$remote/baseline.py' '$remote/policy.json' '$remote/baseline.json'; rmdir '$remote'" | Out-Null
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($temporary)) -ne [IO.Path]::GetTempPath().TrimEnd('\')) {
        throw 'Unexpected temporary directory; refusing cleanup.'
    }
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
