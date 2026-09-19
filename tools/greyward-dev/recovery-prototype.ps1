[CmdletBinding()]
param(
    [string]$VmName = 'GREYWARD-BOOTTEST',
    [string]$OutputPath = ''
)

. (Join-Path $PSScriptRoot 'common.ps1')

Assert-GreywardVmName -Name $VmName -AllowBootTest
Assert-HyperVAvailable
Initialize-GreywardState

$alias = if ($VmName -eq $script:BootTestVmName) { 'greyward-boottest' } else { $script:SshAlias }
$remote = @'
set -u
printf '%s\n' '=== filesystem ==='
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS / /home /boot /boot/efi 2>&1 || true
printf '%s\n' '=== btrfs subvolumes ==='
sudo btrfs subvolume list / 2>&1 || true
printf '%s\n' '=== btrfs default ==='
sudo btrfs subvolume get-default / 2>&1 || true
printf '%s\n' '=== boot entries ==='
find /boot/loader/entries -maxdepth 1 -type f -name '*.conf' -printf '%f\n' 2>/dev/null | sort || true
printf '%s\n' '=== kernels ==='
find /boot -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null | sort || true
printf '%s\n' '=== boot control ==='
sudo bootctl status 2>&1 || true
sudo grub2-editenv list 2>&1 || true
'@

$result = @(Invoke-GreywardSsh -Alias $alias -Command $remote 2>&1)
$text = ($result | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $script:RepoRoot 'output\recovery-prototype\boot-inventory.txt'
}
$parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
Write-GreywardUtf8NoBom -Path $OutputPath -Content $text
Write-GreywardResult -Data @{ vm = $VmName; alias = $alias; output = $OutputPath; mutation = 'NONE'; prototype = 'BOOT_INVENTORY_ONLY' } -Message 'RECOVERY PROTOTYPE INVENTORY OK'
