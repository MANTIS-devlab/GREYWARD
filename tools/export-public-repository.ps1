[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Destination,

    [Parameter(Mandatory)]
    [string]$AuthorName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$AuthorEmail
)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$destinationPath = [IO.Path]::GetFullPath($Destination)
$repoPrefix = $repo.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar

if ($destinationPath -eq $repo -or $destinationPath.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Destination must be outside the private GREYWARD working repository.'
}
if (Test-Path -LiteralPath $destinationPath) {
    if (-not (Get-Item -LiteralPath $destinationPath).PSIsContainer) {
        throw "Destination is not a directory: $destinationPath"
    }
    if (Get-ChildItem -LiteralPath $destinationPath -Force | Select-Object -First 1) {
        throw "Destination must be absent or empty: $destinationPath"
    }
} else {
    New-Item -ItemType Directory -Path $destinationPath | Out-Null
}

& pwsh -NoProfile -File (Join-Path $repo 'tests/static.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Static validation failed; public export was not created.' }
& pwsh -NoProfile -File (Join-Path $repo 'tools/validate-repository.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Repository validation failed; public export was not created.' }

$listed = & git -C $repo ls-files --cached --others --exclude-standard -z
if ($LASTEXITCODE -ne 0) { throw 'Unable to enumerate the publication candidate.' }
$paths = ($listed -join "`n") -split "`0" | Where-Object { $_ }
foreach ($relative in $paths) {
    $source = Join-Path $repo $relative
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
    $target = Join-Path $destinationPath $relative
    $parent = Split-Path $target -Parent
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $source -Destination $target
}

& git -C $destinationPath init --quiet --initial-branch=main
if ($LASTEXITCODE -ne 0) { throw 'Unable to initialize the clean public repository.' }
& git -C $destinationPath config core.autocrlf false
if ($LASTEXITCODE -ne 0) { throw 'Unable to configure byte-preserving line endings.' }
& git -C $destinationPath add --all
if ($LASTEXITCODE -ne 0) { throw 'Unable to stage the public repository.' }

# Copy executable bits from the private index. Git on Windows cannot infer them
# from the filesystem, but Linux image/build entry points must remain executable.
$staged = & git -C $repo ls-files --stage
foreach ($entry in $staged) {
    if ($entry -match '^100755\s+[0-9a-f]+\s+\d+\s+(.+)$') {
        $relative = $Matches[1]
        if (Test-Path -LiteralPath (Join-Path $destinationPath $relative) -PathType Leaf) {
            & git -C $destinationPath update-index --chmod=+x -- $relative
            if ($LASTEXITCODE -ne 0) { throw "Unable to preserve executable mode: $relative" }
        }
    }
}
# A Windows checkout can itself have lost executable index modes. Restore the
# portable contract for every published script that declares an interpreter.
foreach ($relative in (& git -C $destinationPath ls-files)) {
    $path = Join-Path $destinationPath $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $extension = [IO.Path]::GetExtension($path)
    if ($extension -notin @('', '.sh', '.py')) { continue }
    $firstLine = Get-Content -LiteralPath $path -TotalCount 1 -ErrorAction SilentlyContinue
    if ($firstLine -like '#!*') {
        & git -C $destinationPath update-index --chmod=+x -- $relative
        if ($LASTEXITCODE -ne 0) { throw "Unable to mark interpreter script executable: $relative" }
    }
}

& git -C $destinationPath -c "user.name=$AuthorName" -c "user.email=$AuthorEmail" -c commit.gpgsign=false `
    commit --quiet -m 'Initial public release'
if ($LASTEXITCODE -ne 0) { throw 'Unable to create the clean public root commit.' }

$commitCount = [int](& git -C $destinationPath rev-list --all --count)
if ($LASTEXITCODE -ne 0 -or $commitCount -ne 1) {
    throw "Public export must contain exactly one commit; found $commitCount."
}
if (Test-Path -LiteralPath (Join-Path $destinationPath '.git/shallow')) {
    throw 'Public export unexpectedly contains shallow-history metadata.'
}

[pscustomobject]@{
    ok = $true
    destination = $destinationPath
    files = (& git -C $destinationPath ls-files).Count
    commits = $commitCount
    head = (& git -C $destinationPath rev-parse HEAD)
} | ConvertTo-Json -Compress
