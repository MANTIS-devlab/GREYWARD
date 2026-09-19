[CmdletBinding()]
param(
    [switch]$ValidateOnly,
    [switch]$Resume,
    [switch]$SkipGraphicsGate,
    [switch]$BootTest,
    [Security.SecureString]$BootstrapPassword
)
. (Join-Path $PSScriptRoot 'common.ps1')
$targetVmName = if ($BootTest) { $script:BootTestVmName } else { $script:GreywardVmName }
$buildVmName = "$targetVmName-BUILD"
$sshAlias = if ($BootTest) { 'greyward-boottest' } else { $script:SshAlias }
$buildRoot = Join-Path $script:RepoRoot $(if ($BootTest) { 'build\h2-boottest' } else { 'build\h0' })
$packerOutput = Join-Path $buildRoot 'packer-output'
$reuseInterruptedBuild = $false
$greywardBuildHost = 'greyward-build'
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsOriginal = $null

Assert-HyperVAvailable
if (-not $ValidateOnly) {
    if (-not (Test-IsAdministrator)) {
        throw 'GREYWARD factory rebuild requires an elevated PowerShell session because it manages the temporary hosts mapping used by Packer.'
    }
    try { Get-VM -ErrorAction Stop | Out-Null }
    catch { throw 'GREYWARD bootstrap requires an execution account with effective Hyper-V Administrators access. The current execution token cannot perform Hyper-V operations.' }
}
if (-not $ValidateOnly) { Initialize-GreywardState }
$classificationKeyPath = $script:SshKeyPath

$existingVm = Get-VM -Name $targetVmName -ErrorAction SilentlyContinue
if ($existingVm -and $Resume) {
    if ($BootTest) { throw '-Resume is only supported for the existing GREYWARD-DEV H0 VM.' }
    if ($existingVm.State -ne 'Running') {
        Write-Host "Starting existing $targetVmName for resumable bootstrap handoff."
        Start-VM -VM $existingVm | Out-Null
    }
    $address = Get-GreywardEndpoint -VmName $targetVmName
    Initialize-GreywardSshKey | Out-Null
    Set-GreywardSshAlias -Address $address -Alias $sshAlias
    if (-not (Test-GreywardSshKeyAccess -Alias $sshAlias)) {
        Authorize-GreywardSshKey -Address $address -Alias $sshAlias
    }
    Invoke-GreywardSsh 'sudo -n true; systemctl is-enabled sshd' -Alias $sshAlias
    $handoff = [ordered]@{
        vm = $targetVmName
        alias = $sshAlias
        endpoint = $address
        user = 'stendev'
        identity = $script:SshKeyPath
        config = $script:SshConfigPath
        knownHosts = $script:SshKnownHostsPath
        stages = [ordered]@{
            vmExists = $true
            guestNetworking = $true
            authorizedIdentity = $true
            sshConfig = $true
            sshVerified = $true
        }
        status = 'HANDOFF COMPLETE'
        completedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-GreywardUtf8NoBom -Path $script:HandoffStatePath -Content ($handoff | ConvertTo-Json -Depth 8)
    Write-GreywardResult -Data @{vm=$targetVmName; endpoint=$address; alias=$sshAlias; config=$script:SshConfigPath; state=$script:HandoffStatePath} -Message "$targetVmName HANDOFF READY"
    exit 0
}
if ($existingVm) { throw "$targetVmName already exists. Run create.ps1 -Resume to complete its bootstrap handoff; the existing VM will not be recreated." }

function Get-GreywardPackerProcess {
    @(Get-CimInstance Win32_Process -Filter "Name = 'packer.exe'" -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -and ($_.CommandLine -match [regex]::Escape($script:RepoRoot) -or $_.CommandLine -match [regex]::Escape($buildVmName))
    })
}

function Get-GreywardBuildIpv4 {
    $addresses = @(Get-VMNetworkAdapter -VMName $buildVmName -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty IPAddresses |
        Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' })
    if ($addresses.Count -eq 0) {
        $mac = (Get-VMNetworkAdapter -VMName $buildVmName -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty MacAddress)
        if ($mac) {
            $normalizedMac = ($mac -replace '[-:]','').ToUpperInvariant()
            $addresses = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.LinkLayerAddress -and (($_.LinkLayerAddress -replace '[-:]','').ToUpperInvariant() -eq $normalizedMac) } |
                Select-Object -ExpandProperty IPAddress |
                Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' })
        }
    }
    return $addresses
}

function Test-GreywardBuildSsh {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][string]$KeyPath)
    $oldErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & ssh '-i' $KeyPath '-o' 'IdentitiesOnly=yes' '-o' 'BatchMode=yes' '-o' 'ConnectTimeout=8' '-o' 'StrictHostKeyChecking=no' '-o' 'UserKnownHostsFile=NUL' '-o' 'LogLevel=ERROR' "stendev@$Address" 'true' 2>$null | Out-Null
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldErrorAction
    }
    return ($exitCode -eq 0)
}

function Remove-GreywardInterruptedBuild {
    $buildVm = Get-VM -Name $buildVmName -ErrorAction SilentlyContinue
    if ($buildVm) {
        $vmPath = [IO.Path]::GetFullPath($buildVm.Path)
        if ([IO.Path]::GetFileName($vmPath) -cne $buildVmName) { throw "Refusing to remove unexpected GREYWARD build path: $vmPath" }
        if ($buildVm.State -ne 'Off') { Stop-VM -VM $buildVm -TurnOff -Force -ErrorAction Stop }
        Remove-VM -VM $buildVm -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $vmPath) { Remove-Item -LiteralPath $vmPath -Recurse -Force }
    }
    if (Test-Path -LiteralPath $packerOutput) {
        $resolvedOutput = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $packerOutput).Path)
        $resolvedBuild = [IO.Path]::GetFullPath($buildRoot)
        if ($resolvedOutput -notlike "$resolvedBuild\packer-output") { throw "Refusing to remove unexpected Packer output path: $resolvedOutput" }
        Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
    }
}

function Set-GreywardBuildHost {
    param([Parameter(Mandatory)][string]$Address)
    if ($null -eq $script:hostsOriginal) {
        $script:hostsOriginal = if (Test-Path -LiteralPath $hostsPath) { [IO.File]::ReadAllText($hostsPath) } else { '' }
    }
    $current = if (Test-Path -LiteralPath $hostsPath) { [IO.File]::ReadAllText($hostsPath) } else { '' }
    $begin = '# BEGIN GREYWARD BUILD HOST (managed)'
    $end = '# END GREYWARD BUILD HOST (managed)'
    $pattern = '(?ms)^' + [regex]::Escape($begin) + '.*?^' + [regex]::Escape($end) + '\r?\n?'
    $current = [regex]::Replace($current, $pattern, '').TrimEnd()
    $block = "$begin`r`n$Address`t$greywardBuildHost`r`n$end"
    [IO.File]::WriteAllText($hostsPath, $current + "`r`n`r`n" + $block + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
}

function Restore-GreywardBuildHost {
    if ($null -ne $script:hostsOriginal) {
        [IO.File]::WriteAllText($hostsPath, $script:hostsOriginal, (New-Object System.Text.UTF8Encoding($false)))
        $script:hostsOriginal = $null
    }
}

function Invoke-GreywardPackerBuild {
    param([Parameter(Mandatory)][string]$PackerPath, [Parameter(Mandatory)][string]$WorkingDirectory, [Parameter(Mandatory)][string[]]$Arguments)
    $argumentString = ($Arguments | ForEach-Object { ConvertTo-GreywardWindowsProcessArgument $_ }) -join ' '
    $packerProcess = Start-Process -FilePath $PackerPath -WorkingDirectory $WorkingDirectory -ArgumentList $argumentString -PassThru -NoNewWindow
    try {
        do {
            $addresses = @(Get-GreywardBuildIpv4)
            foreach ($address in $addresses) {
                try { Set-GreywardBuildHost -Address $address; break } catch { throw "Unable to update the temporary GREYWARD Packer host mapping: $($_.Exception.Message)" }
            }
            if (-not $packerProcess.HasExited) { Start-Sleep -Seconds 3 }
        } while (-not $packerProcess.HasExited)
        return $packerProcess.ExitCode
    } finally {
        Restore-GreywardBuildHost
    }
}

function Get-GreywardBuildDiskEvidence {
    $disk = Get-VMHardDiskDrive -VMName $buildVmName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $disk -or -not (Test-Path -LiteralPath $disk.Path)) { return $null }
    Get-VHD -Path $disk.Path -ErrorAction SilentlyContinue
}

$existingBuildVm = Get-VM -Name $buildVmName -ErrorAction SilentlyContinue
if ($existingBuildVm) {
    if (-not $Resume) { throw "$buildVmName already exists. Run create.ps1 -Resume to classify and recover the interrupted GREYWARD build." }
    $packerProcesses = @(Get-GreywardPackerProcess)
    $buildIps = @(Get-GreywardBuildIpv4)
    $buildVmxc = Get-ChildItem -Path $packerOutput -Filter *.vmcx -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    $buildDisk = Get-GreywardBuildDiskEvidence
    $installationEvidence = $buildDisk -and $buildDisk.FileSize -ge 1GB
    if ($ValidateOnly) {
        $classification = if ($packerProcesses.Count -gt 0) { 'ACTIVE/RECOVERABLE' } elseif ($buildVmxc -and $buildIps.Count -gt 0) { 'COMPLETED GUEST CANDIDATE' } elseif ($buildIps.Count -gt 0 -or $installationEvidence) { 'INSTALLATION STILL PROGRESSING' } else { 'INSTALLATION FAILED/INCOMPLETE' }
        $diskSize = if ($buildDisk) { $buildDisk.FileSize } else { 0 }
        Write-GreywardResult -Data @{vm=$buildVmName; classification=$classification; ipv4=$buildIps; exportedVmConfiguration=[bool]$buildVmxc; diskFileSizeBytes=$diskSize; packerProcess=[bool]($packerProcesses.Count -gt 0)} -Message "GREYWARD BUILD CLASSIFICATION: $classification"
        exit 0
    }
    $classificationKeyPath = Initialize-GreywardSshKey
    $sshReady = $false
    $sshAddress = $null
    foreach ($buildIp in $buildIps) {
        if (Test-NetConnection -ComputerName $buildIp -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue) {
            if (Test-GreywardBuildSsh -Address $buildIp -KeyPath $classificationKeyPath) { $sshReady = $true; $sshAddress = $buildIp; break }
        }
    }
    if ($packerProcesses.Count -gt 0) {
        Write-Host 'GREYWARD BUILD CLASSIFICATION: ACTIVE/RECOVERABLE (Packer is still running).'
        throw 'The GREYWARD Packer build is still active. Allow it to finish or interrupt it, then rerun create.ps1 -Resume.'
    } elseif ($sshReady -and $buildVmxc) {
        Write-Host "GREYWARD BUILD CLASSIFICATION: COMPLETED GUEST WAITING FOR HANDOFF/IMPORT ($sshAddress)."
        $reuseInterruptedBuild = $true
    } elseif ($buildIps.Count -gt 0 -or $installationEvidence) {
        Write-Host "GREYWARD BUILD CLASSIFICATION: INSTALLATION STILL PROGRESSING (guest IP $($buildIps -join ', '), SSH not ready)."
        if ($installationEvidence) { Write-Host "Installer disk evidence: $([math]::Round($buildDisk.FileSize / 1GB, 2)) GiB written." }
        Write-Host 'Packer internal state is unavailable after interruption; recycling only the disposable GREYWARD build stage.'
        Remove-GreywardInterruptedBuild
    } else {
        Write-Host 'GREYWARD BUILD CLASSIFICATION: INSTALLATION FAILED/INCOMPLETE (no guest IPv4 address and no exported VM configuration).'
        Write-Host 'Packer internal state is unavailable after interruption; recycling only the disposable GREYWARD build stage.'
        Remove-GreywardInterruptedBuild
    }
}
if ($reuseInterruptedBuild -and -not (Test-Path -LiteralPath $packerOutput)) { throw 'A completed GREYWARD build was detected without its Packer output; refusing to guess at an import source.' }
if (Get-VM -Name 'STENOS-DEV' -ErrorAction SilentlyContinue) {
    Write-Host 'STENOS-DEV detected and explicitly excluded from all operations.'
}

$targetVmPath = Join-Path $env:PUBLIC "Documents\Hyper-V\$targetVmName"
if (Test-Path $targetVmPath) { throw "Target VM path already exists: $targetVmPath" }

$packerVersion = $script:Versions.packer.version
$packerRoot = Join-Path $script:RepoRoot "cache\tools\packer-$packerVersion"
$packerExe = Join-Path $packerRoot 'packer.exe'
$packerZip = Join-Path $script:RepoRoot "cache\downloads\packer_${packerVersion}_windows_amd64.zip"
$packerUrl = "https://releases.hashicorp.com/packer/$packerVersion/packer_${packerVersion}_windows_amd64.zip"
$packerHash = '91a378d4e7f9c5363caa196e23fd78717da31d12fc6069c8bb892cdacceb2eb8'
$isoDir = Join-Path $script:RepoRoot 'cache\iso'
$isoPath = Join-Path $isoDir $script:Versions.fedora.iso

$switchName = 'Default Switch'
$networkMode = 'default-switch'
if (-not (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)) {
    throw 'The Hyper-V Default Switch is unavailable; GREYWARD H0 requires the proven host Default Switch path.'
}

$validation = [ordered]@{
    vmName = $targetVmName
    vmNameAvailable = $true
    targetPathAvailable = $true
    hyperV = $true
    networkMode = $networkMode
    switchName = $switchName
    fedoraIso = $script:Versions.fedora.iso
    expectedIsoSha256 = $script:Versions.fedora.sha256
    packer = $packerVersion
}
if ($ValidateOnly) {
    Write-GreywardResult -Data $validation -Message 'VALIDATION OK'
    exit 0
}

New-Item -ItemType Directory -Force -Path (Split-Path $packerZip),$packerRoot,$isoDir | Out-Null
if (-not (Test-Path $packerExe)) {
    if (-not (Test-Path $packerZip)) { Invoke-WebRequest -UseBasicParsing -Uri $packerUrl -OutFile $packerZip }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $packerZip).Hash.ToLowerInvariant() -ne $packerHash) {
        throw 'Portable Packer checksum verification failed.'
    }
    Expand-Archive -LiteralPath $packerZip -DestinationPath $packerRoot -Force
}

if (-not (Test-Path $isoPath)) {
    Invoke-WebRequest -UseBasicParsing -Uri $script:Versions.fedora.url -OutFile $isoPath
}
$checksumPath = Join-Path $isoDir 'Fedora-Everything-44-1.7-x86_64-CHECKSUM'
$certificatePath = Join-Path $isoDir 'fedora.gpg'
function Get-FedoraChecksumFromOfficialMirror {
    param([Parameter(Mandatory)][string]$Destination)
    $mirrorList = (Invoke-WebRequest -UseBasicParsing -Uri $script:Versions.fedora.checksumUrl).Content
    $candidates = @($mirrorList -split "`r?`n" | Where-Object { $_ -match '^https?://' } | ForEach-Object {
        $base = $_.Trim()
        if ($base.EndsWith('/os/')) { $base = $base.Substring(0, $base.Length - 4) + '/iso/' }
        "$base$([IO.Path]::GetFileName($Destination))"
    })
    if ($candidates.Count -eq 0) { throw 'Fedora official mirror list returned no HTTP(S) mirrors.' }
    $temp = "$Destination.download"
    foreach ($candidate in $candidates) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $candidate -OutFile $temp
            $text = Get-Content -Raw -LiteralPath $temp -ErrorAction Stop
            if ($text -match '(?i)<\s*!doctype\s+html|<\s*html\b|within\.website') { throw 'Fedora checksum response is HTML.' }
            if ($text -notmatch '^-----BEGIN PGP SIGNED MESSAGE-----' -or $text -notmatch '(?m)^-----BEGIN PGP SIGNATURE-----' -or $text -notmatch '(?m)^-----END PGP SIGNATURE-----\s*$') { throw 'Fedora checksum response is not a complete clear-signed PGP document.' }
            if ($text -notmatch [regex]::Escape($script:Versions.fedora.sha256)) { throw 'Fedora signed checksum does not contain the pinned ISO digest.' }
            Move-Item -Force -LiteralPath $temp -Destination $Destination
            return $candidate
        } catch {
            Remove-Item -Force -LiteralPath $temp -ErrorAction SilentlyContinue
        }
    }
    throw 'No official Fedora mirror returned a valid clear-signed checksum document.'
}
if (Test-Path $checksumPath) {
    $cachedChecksum = Get-Content -Raw -LiteralPath $checksumPath
    if ($cachedChecksum -match '(?i)<\s*!doctype\s+html|<\s*html\b|within\.website' -or $cachedChecksum -notmatch '^-----BEGIN PGP SIGNED MESSAGE-----') {
        Remove-Item -Force -LiteralPath $checksumPath
    }
}
if (-not (Test-Path $checksumPath)) { $checksumSource = Get-FedoraChecksumFromOfficialMirror -Destination $checksumPath }
if (-not (Test-Path $certificatePath)) { Invoke-WebRequest -UseBasicParsing -Uri $script:Versions.fedora.certificateUrl -OutFile $certificatePath }
$actualIsoHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $isoPath).Hash.ToLowerInvariant()
if ($actualIsoHash -ne $script:Versions.fedora.sha256) { throw 'Fedora ISO checksum verification failed.' }
$checksumContent = Get-Content -Raw -LiteralPath $checksumPath
if ($checksumContent -match '(?i)<\s*!doctype\s+html|<\s*html\b|within\.website' -or $checksumContent -notmatch '^-----BEGIN PGP SIGNED MESSAGE-----' -or $checksumContent -notmatch '(?m)^-----BEGIN PGP SIGNATURE-----' -or $checksumContent -notmatch '(?m)^-----END PGP SIGNATURE-----\s*$') { throw 'The Fedora checksum artifact is invalid or not PGP clear-signed.' }
if ($checksumContent -notmatch [regex]::Escape($actualIsoHash)) { throw 'The pinned ISO digest is absent from the downloaded Fedora checksum document.' }

$keyPath = Initialize-GreywardSshKey
$publicKey = (Get-Content -Raw -LiteralPath "$keyPath.pub").Trim()
$networkConfiguration = '--device=link --bootproto=dhcp'

$httpRoot = Join-Path $buildRoot 'http'
if (-not $reuseInterruptedBuild) {
    if (-not $BootstrapPassword) {
        $BootstrapPassword = Read-Host 'Enter a disposable GREYWARD development bootstrap password (16+ letters, digits, dot, underscore, or hyphen)' -AsSecureString
    }
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BootstrapPassword)
    try {
        $bootstrapPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
    if ($bootstrapPasswordPlain -notmatch '^[A-Za-z0-9._-]{16,128}$') {
        throw 'The bootstrap password must contain 16-128 letters, digits, dots, underscores, or hyphens so Kickstart can consume it without quoting ambiguity.'
    }

    New-Item -ItemType Directory -Force -Path $httpRoot | Out-Null
    $ksTemplateFile = if ($BootTest) { 'greyward-dev-boottest.ks.tmpl' } else { 'greyward-dev-bootstrap.ks.tmpl' }
    $ksTemplate = Get-Content -Raw -LiteralPath (Join-Path $script:RepoRoot "environment\http\$ksTemplateFile")
    $ks = $ksTemplate.Replace('__SSH_PUBLIC_KEY__',$publicKey).Replace('__NETWORK_CONFIGURATION__',$networkConfiguration).Replace('__BOOTSTRAP_PASSWORD__',$bootstrapPasswordPlain)
    Write-GreywardUtf8NoBom -Path (Join-Path $httpRoot 'greyward.ks') -Content $ks
}

if (-not $reuseInterruptedBuild) {
    $oldPackerLog = $env:PACKER_LOG
    $oldPackerLogPath = $env:PACKER_LOG_PATH
    $oldPackerBootstrapPassword = $env:PKR_VAR_bootstrap_password
    $env:PACKER_LOG = '1'
    $env:PACKER_LOG_PATH = Join-Path $script:StateDir $(if ($BootTest) { 'packer-boottest.log' } else { 'packer-h0.log' })
    $env:PKR_VAR_bootstrap_password = $bootstrapPasswordPlain
    Push-Location (Join-Path $script:RepoRoot 'environment')
    try {
        & $packerExe init .
        if ($LASTEXITCODE -ne 0) { throw 'packer init failed.' }
        & $packerExe validate `
            -var "iso_path=$isoPath" -var "iso_checksum=$($script:Versions.fedora.sha256)" `
            -var "switch_name=$switchName" -var "ssh_private_key_file=$keyPath" `
            -var "http_directory=$httpRoot" -var "output_directory=$packerOutput" -var "vm_name=$buildVmName" -var "ssh_host=$greywardBuildHost" .
        if ($LASTEXITCODE -ne 0) { throw 'packer validate failed.' }
        $buildExit = Invoke-GreywardPackerBuild -PackerPath $packerExe -WorkingDirectory (Join-Path $script:RepoRoot 'environment') -Arguments @(
            'build','-force','-on-error=abort',
            '-var',"iso_path=$isoPath",'-var',"iso_checksum=$($script:Versions.fedora.sha256)",
            '-var',"switch_name=$switchName",'-var',"ssh_private_key_file=$keyPath",
            '-var',"http_directory=$httpRoot",'-var',"output_directory=$packerOutput",'-var',"vm_name=$buildVmName",'-var',"ssh_host=$greywardBuildHost",'.'
        )
        if ($buildExit -ne 0) { throw "packer build failed with exit code $buildExit." }
    } finally {
        Pop-Location
        $env:PACKER_LOG = $oldPackerLog
        $env:PACKER_LOG_PATH = $oldPackerLogPath
        $env:PKR_VAR_bootstrap_password = $oldPackerBootstrapPassword
        $bootstrapPasswordPlain = $null
    }
}

$vmcx = Get-ChildItem -Path $packerOutput -Filter *.vmcx -Recurse | Select-Object -First 1
if (-not $vmcx) { throw 'Packer completed without an exported Hyper-V configuration.' }
$imported = Import-VM -Path $vmcx.FullName -Copy -GenerateNewId -VirtualMachinePath $targetVmPath -VhdDestinationPath (Join-Path $targetVmPath 'Virtual Hard Disks')
Rename-VM -VM $imported -NewName $targetVmName
Set-VM -Name $targetVmName -ProcessorCount 4 -MemoryStartupBytes 8GB -DynamicMemory:$false -CheckpointType Standard -AutomaticStopAction ShutDown
Set-VMFirmware -VMName $targetVmName -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
# VMConnect needs Hyper-V's console HID devices explicitly enabled for reliable
# keyboard and pointer delivery to the Linux guest.
Enable-VMConsoleSupport -VMName $targetVmName | Out-Null
Start-VM -Name $targetVmName | Out-Null

$address = Repair-GreywardSsh -VmName $targetVmName -Alias $sshAlias -AllowHyperVFallback
Invoke-GreywardSsh 'sudo -n true; systemctl is-enabled sshd; rpm -q hyprland quickshell uwsm' -Alias $sshAlias
$nevras = @(Invoke-GreywardSsh 'cat /etc/greyward-installed-nevras.txt' -Alias $sshAlias)
$repositories = @(Invoke-GreywardSsh 'cat /etc/greyward-enabled-repositories.txt' -Alias $sshAlias)

$metadata = [ordered]@{
    fedora = [ordered]@{ release=44; compose='1.7'; iso=$script:Versions.fedora.iso; sourceUrl=$script:Versions.fedora.url; checksumUrl=$script:Versions.fedora.checksumUrl; sha256=$actualIsoHash; signingFingerprint=$script:Versions.fedora.signingFingerprint; downloadedAt=(Get-Item $isoPath).LastWriteTimeUtc.ToString('o') }
    packer = [ordered]@{ version=$packerVersion; hypervPlugin=$script:Versions.packer.hypervPlugin }
    network = [ordered]@{ mode=$networkMode; switchName=$switchName; endpoint=$address }
    builtAt = (Get-Date).ToUniversalTime().ToString('o')
    installedNevras = $nevras
    enabledRepositories = $repositories
}
$metadataName = if ($BootTest) { 'boottest-build-metadata.json' } else { 'build-metadata.json' }
$metadataJson = $metadata | ConvertTo-Json -Depth 8
Write-GreywardUtf8NoBom -Path (Join-Path $script:StateDir $metadataName) -Content $metadataJson

if (-not $SkipGraphicsGate -and -not $BootTest) {
    & (Join-Path $PSScriptRoot 'graphics-gate.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Hyper-V graphics gate failed; do not continue shell development.' }
}

$checkpoint = if ($BootTest) { 'GREYWARD-BOOTTEST-READY' } else { 'CLEAN-GREYWARD-DEV' }
Checkpoint-VM -Name $targetVmName -SnapshotName $checkpoint
Write-GreywardResult -Data @{vm=$targetVmName; endpoint=$address; checkpoint=$checkpoint; encrypted=[bool]$BootTest} -Message "$targetVmName READY"
