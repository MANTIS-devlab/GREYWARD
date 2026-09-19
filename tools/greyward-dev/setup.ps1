[CmdletBinding()]
param([string]$VmName = 'GREYWARD-DEV')
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-GreywardVmName -Name $VmName -AllowBootTest
$address = Repair-GreywardSsh -VmName $VmName -AllowHyperVFallback
Invoke-GreywardSsh 'true'
Write-GreywardResult -Data @{vm=$VmName; endpoint=$address} -Message 'SSH READY'
