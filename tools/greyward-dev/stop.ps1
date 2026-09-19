[CmdletBinding()]
param([switch]$Force)
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-HyperVAvailable
$vm = Get-VM -Name $script:GreywardVmName -ErrorAction Stop
if ($vm.State -eq 'Running') {
    if ($Force) { Stop-VM -VM $vm -TurnOff -Confirm:$false }
    else {
        Repair-GreywardSsh -AllowHyperVFallback | Out-Null
        try { Invoke-GreywardSsh 'sudo systemctl poweroff' | Out-Null } catch { }
        $vm | Wait-VM -For PowerOff -Timeout 60 -ErrorAction Stop | Out-Null
    }
}
Write-GreywardResult -Data @{vm=$script:GreywardVmName} -Message 'VM STOPPED'
