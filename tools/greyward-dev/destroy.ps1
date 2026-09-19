[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][string]$VmName,
    [Parameter(Mandatory)][string]$ConfirmVmName
)
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-GreywardVmName -Name $VmName
if ($ConfirmVmName -cne $script:GreywardVmName -or $VmName -cne $script:GreywardVmName) { throw 'Both names must exactly equal GREYWARD-DEV.' }
Assert-HyperVAvailable
$vm = Get-VM -Name $VmName -ErrorAction Stop
$paths = @($vm.Path, ($vm.HardDrives | Select-Object -ExpandProperty Path)) | Where-Object { $_ }
foreach ($path in $paths) {
    $resolved = [IO.Path]::GetFullPath($path)
    if ($resolved -notlike '*\Hyper-V\GREYWARD-DEV*') { throw "Refusing unexpected VM path: $resolved" }
}
if ($PSCmdlet.ShouldProcess($VmName,'remove disposable VM registration and GREYWARD-DEV VM directory')) {
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Confirm:$false }
    Remove-VM -VM $vm -Force
    $vmRoot = [IO.Path]::GetFullPath((Join-Path $env:PUBLIC 'Documents\Hyper-V\GREYWARD-DEV'))
    if ($vmRoot -like '*\Hyper-V\GREYWARD-DEV' -and (Test-Path $vmRoot)) { Remove-Item -LiteralPath $vmRoot -Recurse -Force }
    Write-GreywardResult -Data @{vm=$VmName; removed=$paths} -Message 'DESTROY OK'
}

