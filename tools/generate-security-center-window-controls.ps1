param([switch]$Validate)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$source = Join-Path $root 'environment/session/labwc/Greyward'
$destination = Join-Path $root 'security-center/tauri/frontend/assets/window-controls'
if (-not $Validate) { New-Item -ItemType Directory -Force $destination | Out-Null }
foreach ($glyph in @('iconify', 'max', 'close')) {
    foreach ($state in @('active', 'inactive')) {
        foreach ($interaction in @('', '_hover')) {
            $name = "$glyph$interaction-$state.svg"
            $original = Join-Path $source $name
            $copy = Join-Path $destination $name
            if ($Validate) {
                if ((Get-FileHash -LiteralPath $original).Hash -ne (Get-FileHash -LiteralPath $copy).Hash) {
                    throw "Window control differs from canonical Labwc artwork: $name"
                }
            } else { Copy-Item -LiteralPath $original -Destination $copy }
        }
    }
}
