[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$manifestPath = Join-Path $repo 'branding\manifest.json'
$identityPath = Join-Path $repo 'branding\identity.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
$errors = [Collections.Generic.List[string]]::new()
foreach ($name in 'symbol','wordmark','lockup') {
    $relative = $manifest.canonical.$name
    if (-not $relative -or -not (Test-Path (Join-Path $repo $relative))) { $errors.Add("Missing canonical $name.") }
}
foreach ($sourceName in $identity.sourceHashes.PSObject.Properties.Name) {
    $sourcePath = Join-Path $repo "branding\source\$sourceName"
    $actual = (Get-FileHash $sourcePath -Algorithm SHA256).Hash
    if ($actual -cne $identity.sourceHashes.$sourceName) { $errors.Add("Stale identity source hash for $sourceName.") }
}
foreach ($entry in $manifest.consumers) {
    foreach ($required in 'surface','consumer','source','outputs','validation') {
        if ($required -eq 'outputs') {
            if ($null -eq $entry.outputs) { $errors.Add("Manifest entry '$($entry.surface)' lacks outputs.") }
        } elseif (-not $entry.$required) {
            $errors.Add("Manifest entry '$($entry.surface)' lacks $required.")
        }
    }
    foreach ($source in ([string]$entry.source -split '\s*\+\s*')) {
        if (-not (Test-Path (Join-Path $repo $source))) { $errors.Add("Missing source: $source") }
    }
    $externalConsumers = @(
        'hyprpaper',
        'DMS wallpaper picker',
        'DMS Greeter via greetd',
        'packaging/greyward-branding via Anaconda GTK custom stylesheet',
        'packaging/greyward-branding via detected Fedora-derived Anaconda profile',
        'packaging/greyward-branding via Cockpit local branding'
    )
    if ($entry.consumer -notin $externalConsumers -and -not (Test-Path (Join-Path $repo $entry.consumer))) { $errors.Add("Missing consumer: $($entry.consumer)") }
    foreach ($output in $entry.outputs) {
        if ($output -like 'branding/generated/*' -and -not (Test-Path (Join-Path $repo $output))) { continue }
        if ($output -like '/usr/share/greyward/*' -or $output -like '/var/cache/dms-greeter/*' -or $output -like '/usr/share/anaconda/*' -or $output -like '/etc/anaconda/*' -or $output -like '/etc/cockpit/*') { continue }
        if (-not (Test-Path (Join-Path $repo $output))) { $errors.Add("Missing output: $output") }
    }
}
$canonicalPath = Join-Path $repo $manifest.canonical.symbol
$canonical = (Get-FileHash $canonicalPath -Algorithm SHA256).Hash
$canonicalText = (Get-Content $canonicalPath -Raw).Replace("`r`n","`n").TrimEnd()
foreach ($consumerPath in @('security-center\data\greyward-symbol.svg','security-center\tauri\frontend\greyward-symbol.svg')) {
    $fullConsumerPath = Join-Path $repo $consumerPath
    if (-not (Test-Path $fullConsumerPath)) {
        $errors.Add("Missing canonical symbol consumer: $consumerPath")
        continue
    }
    $consumerText = (Get-Content $fullConsumerPath -Raw).Replace("`r`n","`n").TrimEnd()
    if ($canonicalText -cne $consumerText) { $errors.Add("Canonical symbol drifted in $consumerPath; copy the canonical source.") }
}
$visualDirectories = @(
    (Join-Path (Join-Path $repo 'branding') 'source')
    (Join-Path (Join-Path $repo 'branding') 'wallpaper')
)
$existingVisualDirectories = @($visualDirectories | Where-Object { Test-Path -LiteralPath $_ -PathType Container })
foreach ($visualDirectory in $visualDirectories) {
    if ($visualDirectory -notin $existingVisualDirectories) {
        $errors.Add("Missing canonical visual asset directory: $visualDirectory")
    }
}
$visualFiles = @(
    foreach ($visualDirectory in $existingVisualDirectories) {
        Get-ChildItem -LiteralPath $visualDirectory -Recurse -File -Include *.qml,*.svg
    }
)
$securitySource = (Get-Content (Join-Path $repo 'branding/source/greyward-security-status.svg') -Raw).Replace("`r`n","`n").TrimEnd()
$securityConsumer = (Get-Content (Join-Path $repo 'security-center/data/greyward-security-status.svg') -Raw).Replace("`r`n","`n").TrimEnd()
if ($securitySource -cne $securityConsumer) { $errors.Add('Security status emblem drifted; run tools/generate-branding.ps1 -SkipRaster.') }
foreach ($file in $visualFiles) {
    if (Select-String -LiteralPath $file.FullName -Pattern 'STENOS|Fedora.logo|GNOME.logo|Hyprland.logo|Quickshell.logo' -Quiet) { $errors.Add("Obsolete owned visual identity in $($file.FullName)") }
    if ($file.Extension -eq '.svg' -and (Select-String -LiteralPath $file.FullName -Pattern '(href|src)\s*=\s*["''](?:https?://|data:)' -Quiet)) { $errors.Add("External resource embedded in $($file.FullName)") }
}
if ($errors.Count) {
    @{ok=$false; errors=$errors} | ConvertTo-Json -Depth 5 -Compress
    exit 1
}
@{ok=$true; consumers=$manifest.consumers.Count; canonicalSha256=$canonical; message='Branding validation passed.'} | ConvertTo-Json -Compress
exit 0
