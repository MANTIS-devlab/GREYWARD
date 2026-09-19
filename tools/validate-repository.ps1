[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$errors = [Collections.Generic.List[string]]::new()

function Add-RepositoryError([string]$message) { $errors.Add($message) }

function Test-RepositoryPath([string]$path, [string]$source) {
    $clean = $path.Trim().Trim('`').TrimEnd('.', ',', ';', ':')
    if ([string]::IsNullOrWhiteSpace($clean)) { return }
    if ($clean -match '^(https?|mailto):' -or $clean.StartsWith('/') -or $clean.Contains('$')) { return }
    if ($clean -match '\s' -or $clean -match '^(cargo|node|python|pwsh|bash|desktop-file-validate|guest)$') { return }
    $candidate = Join-Path $repo ($clean.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $candidate)) {
        Add-RepositoryError "$source references missing repository path '$clean'."
    }
}

$requiredFiles = @(
    'AGENTS.md',
    'docs/INDEX.md',
    'docs/REPOSITORY_MAP.md',
    'docs/DOCUMENTATION_POLICY.md',
    'docs/STATUS.md',
    'environment/production/manifest.json',
    'environment/development/README.md',
    'security-center/AGENTS.md'
)
foreach ($path in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $repo ($path.Replace('/', '\'))))) {
        Add-RepositoryError "Required repository file is missing: $path."
    }
}

$index = Get-Content -Raw -LiteralPath (Join-Path $repo 'docs\INDEX.md')
$canonicalIndexEntries = @(
    'STATUS.md',
    'REPOSITORY_MAP.md',
    'DOCUMENTATION_POLICY.md',
    'architecture/ARCHITECTURE.md',
    'architecture/PRODUCTION_VS_DEVELOPMENT.md',
    'development/DEVELOPMENT.md',
    'plans/ROADMAP.md',
    'security-center/README.md',
    'security-context/README.md',
    'recovery/README.md'
)
foreach ($entry in $canonicalIndexEntries) {
    if ($index -notmatch [regex]::Escape("($entry)")) {
        Add-RepositoryError "Canonical document '$entry' is not listed in docs/INDEX.md."
    }
}

$mapPath = Join-Path $repo 'docs\REPOSITORY_MAP.md'
$map = Get-Content -Raw -LiteralPath $mapPath
$mapPathTokens = [regex]::Matches($map, '`([^`\r\n]+)`') | ForEach-Object { $_.Groups[1].Value }
foreach ($token in ($mapPathTokens | Sort-Object -Unique)) {
    if ($token -match '^(environment|security-center|packaging|branding|tests|tools|docs|spikes|\.secrets|AGENTS\.md)/') {
        Test-RepositoryPath -path $token -source 'docs/REPOSITORY_MAP.md'
    }
}

$markdownFiles = Get-ChildItem $repo -Recurse -File -Filter '*.md' | Where-Object {
    $_.FullName -notmatch '\\(\.git|build|cache|output|target|packer_cache|node_modules)\\'
}
foreach ($file in $markdownFiles) {
    $relativeSource = $file.FullName.Substring($repo.Length + 1).Replace('\', '/')
    $text = Get-Content -Raw -LiteralPath $file.FullName
    foreach ($match in [regex]::Matches($text, '\[[^\]]+\]\(([^)]+)\)')) {
        $target = $match.Groups[1].Value.Trim()
        if ($target -match '^(https?|mailto):' -or $target.StartsWith('#')) { continue }
        $targetPath = $target.Split('#')[0]
        if ([string]::IsNullOrWhiteSpace($targetPath)) { continue }
        $candidate = Join-Path $file.DirectoryName ($targetPath.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $candidate)) {
            Add-RepositoryError "$relativeSource contains a broken Markdown link to '$target'."
        }
    }
}

$obsoletePatterns = @(
    'greyward/shell/',
    'greyward\\shell\\',
    'greyward-shell.service',
    'greyward-settings',
    'environment/http/greyward-boottest.ks.tmpl',
    'environment/production/build-security-center.sh',
    'tools/greyward-dev/dms-test-guest.sh',
    'security-center/crates/greyward-security-center/'
)
$currentFiles = $markdownFiles | Where-Object { $_.FullName -notmatch '\\docs\\(history|decisions)\\' }
foreach ($file in $currentFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    foreach ($pattern in $obsoletePatterns) {
        if ($text.IndexOf($pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Add-RepositoryError "$($file.FullName.Substring($repo.Length + 1)) contains obsolete reference '$pattern'."
        }
    }
}

$acceptance = Join-Path $repo 'docs\security-center\ACCEPTANCE.md'
if (Test-Path -LiteralPath $acceptance) {
    $ids = [regex]::Matches((Get-Content -Raw -LiteralPath $acceptance), '\*\*(AC-[A-Z]+[0-9]+)\*\*') | ForEach-Object { $_.Groups[1].Value }
    foreach ($group in ($ids | Group-Object)) {
        if ($group.Count -gt 1) { Add-RepositoryError "Acceptance criterion '$($group.Name)' is duplicated." }
    }
}

if ($errors.Count) {
    @{ ok = $false; errors = $errors } | ConvertTo-Json -Depth 5 -Compress
    exit 1
}
@{ ok = $true; message = 'Repository structure and documentation validation passed.' } | ConvertTo-Json -Compress
