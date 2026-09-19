[CmdletBinding()]
param([string]$Name = 'CLEAN-GREYWARD-DEV')
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-HyperVAvailable
$runtimeVm = Get-VM -Name $script:GreywardVmName -ErrorAction SilentlyContinue
if (-not $runtimeVm) { $runtimeVm = Get-VM -Name "$($script:GreywardVmName)-BUILD" -ErrorAction SilentlyContinue }
if (-not $runtimeVm -or $runtimeVm.Name -notin @($script:GreywardVmName, "$($script:GreywardVmName)-BUILD")) {
    throw 'No GREYWARD-owned runtime VM was found for checkpointing.'
}
if (Get-VMSnapshot -VM $runtimeVm -Name $Name -ErrorAction SilentlyContinue) { throw "Checkpoint '$Name' already exists." }
Checkpoint-VM -VM $runtimeVm -SnapshotName $Name
Write-GreywardResult -Data @{vm=$runtimeVm.Name; checkpoint=$Name} -Message 'CHECKPOINT OK'
