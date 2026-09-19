[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-HyperVAvailable
$vm = Get-VM -Name $script:GreywardVmName -ErrorAction Stop
# Keep existing development VMs compatible with VMConnect keyboard/pointer
# input, including VMs created before console HID support was enabled.
Enable-VMConsoleSupport -VMName $script:GreywardVmName | Out-Null
if ($vm.State -ne 'Running') { Start-VM -VM $vm | Out-Null }
$address = Repair-GreywardSsh -AllowHyperVFallback
Write-GreywardResult -Data @{vm=$script:GreywardVmName; endpoint=$address} -Message 'VM RUNNING'
