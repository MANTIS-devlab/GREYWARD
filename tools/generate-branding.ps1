[CmdletBinding()]
param([switch]$SkipRaster)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$source = Join-Path $repo 'branding\source\greyward-symbol.svg'
Copy-Item -LiteralPath (Join-Path $repo 'branding\source\greyward-security-status.svg') -Destination (Join-Path $repo 'security-center\data\greyward-security-status.svg')
Copy-Item -LiteralPath (Join-Path $repo 'branding\source\greyward-security-status.svg') -Destination (Join-Path $repo 'security-center\data\greyward-security-center.svg')
Copy-Item -LiteralPath (Join-Path $repo 'branding\source\greyward-security-status.svg') -Destination (Join-Path $repo 'security-center\tauri\frontend\greyward-security-center.svg')
if ($SkipRaster) {
    @{ok=$true; raster=$false; message='Canonical SVG consumer refreshed.'} | ConvertTo-Json -Compress
    exit 0
}
. (Join-Path $repo 'tools\greyward-dev\common.ps1')
Repair-GreywardSsh | Out-Null
$remote = '/tmp/greyward-branding'
Invoke-GreywardSsh "rm -rf '$remote'; mkdir -p '$remote/source' '$remote/output/shell' '$remote/output/boot' '$remote/output/raster'"
Invoke-GreywardScp -Source $source -Destination "$($script:SshAlias):$remote/source/symbol.svg"
Invoke-GreywardScp -Source (Join-Path $repo 'branding/source/greyward-security-status.svg') -Destination "$($script:SshAlias):$remote/source/security.svg"
Invoke-GreywardScp -Source (Join-Path $repo 'branding\wallpaper\greyward-wallpaper.svg') -Destination "$($script:SshAlias):$remote/source/wallpaper.svg"
$render = @'
set -euo pipefail
export SOURCE_DATE_EPOCH=0
root=/tmp/greyward-branding
magick -background none "$root/source/security.svg" -resize 64x64 "$root/source/greyward-security-center.png"
for size in 32 48 64 128 256; do magick -background none "$root/source/symbol.svg" -resize "${size}x${size}" "$root/output/shell/greyward-symbol-${size}.png"; done
magick -background none "$root/source/symbol.svg" -resize 256x256 "$root/output/boot/greyward-symbol-256.png"
for size in 256 512 1024; do magick -background none "$root/source/symbol.svg" -resize "${size}x${size}" "$root/output/raster/greyward-symbol-${size}.png"; done
magick -background none "$root/source/wallpaper.svg" -resize 3840x2160 "$root/output/raster/greyward-wallpaper-3840x2160.png"
find "$root/output" -name '*.png' -exec magick {} -strip -define png:exclude-chunks=date,time -define png:compression-level=9 {} \;
'@
Invoke-GreywardSsh (ConvertTo-BashBase64Command $render)
Invoke-GreywardScp -Source "$($script:SshAlias):$remote/source/greyward-security-center.png" -Destination (Join-Path $repo 'security-center/data/greyward-security-center.png')
$generated = Join-Path $repo 'branding\generated'
if (Test-Path $generated) { Remove-Item -LiteralPath $generated -Recurse -Force }
New-Item -ItemType Directory -Path $generated | Out-Null
Invoke-GreywardScp -Recursive -Source "$($script:SshAlias):$remote/output/." -Destination $generated
@{ok=$true; raster=$true; message='Branding generated deterministically in GREYWARD-DEV.'} | ConvertTo-Json -Compress
