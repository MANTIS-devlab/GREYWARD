[CmdletBinding(SupportsShouldProcess)]
param([string]$Name = 'CLEAN-GREYWARD-DEV')
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-HyperVAvailable
$snapshot = Get-VMSnapshot -VMName $script:GreywardVmName -Name $Name -ErrorAction Stop
if ($PSCmdlet.ShouldProcess($script:GreywardVmName,"restore checkpoint '$Name'")) {
    Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
    Start-VM -Name $script:GreywardVmName -ErrorAction SilentlyContinue | Out-Null
    Repair-GreywardSsh -AllowHyperVFallback | Out-Null
    Write-GreywardResult -Data @{vm=$script:GreywardVmName; checkpoint=$Name} -Message 'REVERT OK'
}
