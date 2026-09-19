Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GreywardVmName = 'GREYWARD-DEV'
$script:BootTestVmName = 'GREYWARD-BOOTTEST'
$script:SshAlias = 'greyward-dev'
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:StateDir = Join-Path $PSScriptRoot 'state'
$script:SshDir = Join-Path $script:RepoRoot '.secrets\ssh'
$script:SshKeyPath = Join-Path (Join-Path $env:USERPROFILE '.ssh') 'greyward-dev_ed25519'
$script:SshConfigPath = Join-Path $script:SshDir 'config'
$script:SshKnownHostsPath = Join-Path $script:SshDir 'known_hosts'
$script:HandoffStatePath = Join-Path $script:StateDir 'handoff.json'
$script:Versions = Get-Content -Raw -LiteralPath (Join-Path $script:RepoRoot 'versions.json') | ConvertFrom-Json

function Assert-GreywardVmName {
    param([Parameter(Mandatory)][string]$Name, [switch]$AllowBootTest)
    $allowed = @($script:GreywardVmName)
    if ($AllowBootTest) { $allowed += $script:BootTestVmName }
    if ($Name -notin $allowed -or $Name -like 'STENOS*') {
        throw "Refusing VM target '$Name'. Allowed: $($allowed -join ', ')."
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-HyperVAvailable {
    if (-not (Get-Module -ListAvailable -Name Hyper-V)) { throw 'The Hyper-V PowerShell module is unavailable.' }
    Import-Module Hyper-V -ErrorAction Stop
}

function Initialize-GreywardState {
    New-Item -ItemType Directory -Force -Path $script:StateDir | Out-Null
}

function Write-GreywardUtf8NoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-GreywardEndpoint {
    param([string]$VmName = $script:GreywardVmName, [int]$TimeoutSeconds = 90)
    Assert-GreywardVmName -Name $VmName -AllowBootTest
    Assert-HyperVAvailable
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $addresses = @(Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty IPAddresses |
            Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' })
        if ($addresses.Count -eq 0) {
            $mac = (Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty MacAddress)
            if ($mac) {
                $normalizedMac = ($mac -replace '[-:]','').ToUpperInvariant()
                $addresses = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.LinkLayerAddress -and (($_.LinkLayerAddress -replace '[-:]','').ToUpperInvariant() -eq $normalizedMac) } |
                    Select-Object -ExpandProperty IPAddress |
                    Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' })
            }
        }
        foreach ($candidate in @($addresses | Select-Object -Unique)) {
            if (Test-NetConnection -ComputerName $candidate -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue) {
                return $candidate
            }
        }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    throw "No SSH endpoint was discovered for $VmName within $TimeoutSeconds seconds."
}

function ConvertTo-GreywardWindowsProcessArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value.Length -eq 0) { return '""' }
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Invoke-GreywardSshKeygen {
    param([Parameter(Mandatory)][AllowEmptyString()][string[]]$Arguments)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ([Diagnostics.ProcessStartInfo].GetProperty('ArgumentList')) {
        $Arguments | ForEach-Object { [void]$start.ArgumentList.Add($_) }
    } else {
        $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-GreywardWindowsProcessArgument $_ }) -join ' ')
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Unable to start ssh-keygen for GREYWARD.' }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout; Stderr = $stderr }
}

function Get-GreywardValidatedPublicKey {
    param([Parameter(Mandatory)][string]$PrivatePath, [Parameter(Mandatory)][string]$PublicPath)
    $derived = Invoke-GreywardSshKeygen @('-y', '-f', $PrivatePath)
    if ($derived.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($derived.Stdout)) {
        throw "The GREYWARD SSH private key is corrupt: $PrivatePath"
    }
    $publicValidation = Invoke-GreywardSshKeygen @('-lf', $PublicPath)
    if ($publicValidation.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($publicValidation.Stdout)) {
        throw "The GREYWARD SSH public key is corrupt: $PublicPath"
    }
    $derivedFields = [regex]::Split($derived.Stdout.Trim(), '\s+')
    $storedFields = [regex]::Split((Get-Content -Raw -LiteralPath $PublicPath).Trim(), '\s+')
    if ($derivedFields.Count -lt 2 -or $storedFields.Count -lt 2 -or $derivedFields[0] -ne $storedFields[0] -or $derivedFields[1] -ne $storedFields[1]) {
        throw "The GREYWARD SSH key pair does not match: $PrivatePath"
    }
    return $derived.Stdout.Trim()
}

function Initialize-GreywardSshKey {
    Initialize-GreywardState
    $keyPath = $script:SshKeyPath
    $sshDir = Split-Path -Parent $keyPath
    $publicPath = "$keyPath.pub"
    New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
    $privateExists = Test-Path -LiteralPath $keyPath -PathType Leaf
    $publicExists = Test-Path -LiteralPath $publicPath -PathType Leaf
    if (-not $privateExists -and $publicExists) { throw "The GREYWARD SSH key state is partial: public key exists without private key ($publicPath)." }
    if ($privateExists -and $publicExists) { [void](Get-GreywardValidatedPublicKey -PrivatePath $keyPath -PublicPath $publicPath); return $keyPath }
    if ($privateExists -and -not $publicExists) {
        $derived = Invoke-GreywardSshKeygen @('-y', '-f', $keyPath)
        if ($derived.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($derived.Stdout)) { throw "The GREYWARD SSH private key is corrupt: $keyPath" }
        [IO.File]::WriteAllText($publicPath, $derived.Stdout.Trim() + [Environment]::NewLine, [Text.Encoding]::ASCII)
        [void](Get-GreywardValidatedPublicKey -PrivatePath $keyPath -PublicPath $publicPath)
        return $keyPath
    }
    $generated = Invoke-GreywardSshKeygen @('-q', '-t', 'ed25519', '-f', $keyPath, '-N', [string]::Empty, '-C', 'greyward-dev@windows-host')
    if ($generated.ExitCode -ne 0) { throw "Unable to create the GREYWARD SSH key: $($generated.Stderr.Trim())" }
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf) -or -not (Test-Path -LiteralPath $publicPath -PathType Leaf)) { throw 'GREYWARD SSH key generation completed without both key files.' }
    [void](Get-GreywardValidatedPublicKey -PrivatePath $keyPath -PublicPath $publicPath)
    return $keyPath
}

function Set-GreywardSshAlias {
    param([Parameter(Mandatory)][string]$Address, [string]$Alias = $script:SshAlias)
    $keyPath = Initialize-GreywardSshKey
    $sshDir = $script:SshDir
    $configPath = $script:SshConfigPath
    $knownHosts = $script:SshKnownHostsPath
    New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
    if (-not (Test-Path $knownHosts)) { New-Item -ItemType File -Path $knownHosts | Out-Null }
    $begin = '# BEGIN GREYWARD-DEV (managed)'
    $end = '# END GREYWARD-DEV (managed)'
    $block = @"
$begin
Host $Alias
    HostName $Address
    User stendev
    IdentityFile $keyPath
    IdentitiesOnly yes
    HostKeyAlias $Alias
    UserKnownHostsFile $knownHosts
    StrictHostKeyChecking accept-new
    ServerAliveInterval 15
    ServerAliveCountMax 3
$end
"@
    $existing = if (Test-Path $configPath) { Get-Content -Raw $configPath } else { '' }
    $pattern = '(?ms)^' + [regex]::Escape($begin) + '.*?^' + [regex]::Escape($end) + '\r?\n?'
    $existing = [regex]::Replace($existing, $pattern, '').TrimEnd()
    Write-GreywardUtf8NoBom -Path $configPath -Content ($existing + "`r`n`r`n" + $block.Trim() + "`r`n")
}

function Repair-GreywardSsh {
    param([string]$VmName = $script:GreywardVmName, [string]$Alias = $script:SshAlias, [switch]$AllowHyperVFallback)
    $configured = & ssh -F $script:SshConfigPath -G $Alias 2>$null | Where-Object { $_ -match '^hostname\s+(.+)$' } | Select-Object -First 1
    if ($configured -and $configured -match '^hostname\s+(.+)$') {
        $configuredAddress = $Matches[1].Trim()
        # Use the managed SSH path for the reachability probe.  Test-NetConnection
        # can remain in its TCP probe state on this Fedora/Hyper-V route even
        # while OpenSSH is immediately usable, which blocks every deployment.
        & ssh '-F' $script:SshConfigPath '-o' 'BatchMode=yes' '-o' 'ConnectTimeout=3' $Alias 'true' 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $configuredAddress
        }
    }
    if (-not $AllowHyperVFallback) { throw "SSH alias '$Alias' is not reachable. Hyper-V fallback is disabled for routine SSH operations; run the authorized lifecycle/bootstrap operation first." }
    $address = Get-GreywardEndpoint -VmName $VmName
    Set-GreywardSshAlias -Address $address -Alias $Alias
    return $address
}

function Invoke-GreywardSsh {
    param([Parameter(Mandatory)][string]$Command, [switch]$AllocateTty, [string]$Alias = $script:SshAlias)
    $arguments = @('-F',$script:SshConfigPath,'-o','BatchMode=yes')
    if ($AllocateTty) { $arguments += '-tt' }
    $arguments += @($Alias, $Command)
    & ssh @arguments
    if ($LASTEXITCODE -ne 0) { throw "SSH command failed with exit code $LASTEXITCODE." }
}

function ConvertTo-GreywardSessionCommand {
    param([Parameter(Mandatory)][string]$Command)
    $session = @'
set -euo pipefail
runtime="/run/user/$(id -u)"
socket=$(find "$runtime" -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' -quit)
signature=$(find "$runtime/hypr" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' -quit 2>/dev/null || true)
test -n "$socket"
export XDG_RUNTIME_DIR="$runtime"
export WAYLAND_DISPLAY="$socket"
if [ -n "$signature" ]; then export HYPRLAND_INSTANCE_SIGNATURE="$signature"; fi
if [ -S "$runtime/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus"; fi
'@
    $session += "`n$Command`n"
    return ConvertTo-BashBase64Command -Script $session
}

function Invoke-GreywardSessionSsh {
    param([Parameter(Mandatory)][string]$Command, [string]$Alias = $script:SshAlias)
    Invoke-GreywardSsh (ConvertTo-GreywardSessionCommand -Command $Command) -Alias $Alias
}

function Test-GreywardSshKeyAccess {
    param([string]$Alias = $script:SshAlias)
    & ssh '-F' $script:SshConfigPath '-o' 'BatchMode=yes' '-o' 'ConnectTimeout=10' $Alias 'true' 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Authorize-GreywardSshKey {
    param([Parameter(Mandatory)][string]$Address, [string]$Alias = $script:SshAlias)
    $keyPath = Initialize-GreywardSshKey
    $publicKey = (Get-Content -Raw -LiteralPath "$keyPath.pub").Trim()
    $encodedKey = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($publicKey))
    $remoteCommand = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; printf '%s' '$encodedKey' | base64 -d > /tmp/greyward-key; grep -Fqx -f /tmp/greyward-key ~/.ssh/authorized_keys || cat /tmp/greyward-key >> ~/.ssh/authorized_keys; rm -f /tmp/greyward-key; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"
    Write-Host "GREYWARD SSH key access is not available; enter the disposable password chosen when this development VM was created to repair authorized_keys."
    & ssh '-o' 'PubkeyAuthentication=no' '-o' 'PreferredAuthentications=password' '-o' 'NumberOfPasswordPrompts=1' '-o' 'ConnectTimeout=15' "stendev@$Address" $remoteCommand
    if ($LASTEXITCODE -ne 0) { throw 'Unable to authorize the GREYWARD SSH identity with the stendev bootstrap account.' }
    Set-GreywardSshAlias -Address $Address -Alias $Alias
    if (-not (Test-GreywardSshKeyAccess -Alias $Alias)) { throw 'The GREYWARD SSH identity was not accepted after authorized_keys repair.' }
}

function Invoke-GreywardScp {
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination, [switch]$Recursive)
    $arguments = @('-F',$script:SshConfigPath)
    if ($Recursive) { $arguments += '-r' }
    $arguments += @($Source, $Destination)
    & scp @arguments
    if ($LASTEXITCODE -ne 0) { throw "SCP failed with exit code $LASTEXITCODE." }
}

function ConvertTo-BashBase64Command {
    param([Parameter(Mandatory)][string]$Script)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script))
    return "echo $encoded | base64 -d | bash"
}

function Write-GreywardResult {
    param([Parameter(Mandatory)][hashtable]$Data, [Parameter(Mandatory)][string]$Message)
    $Data.message = $Message
    $Data.timestamp = (Get-Date).ToUniversalTime().ToString('o')
    $Data | ConvertTo-Json -Depth 8 -Compress
    Write-Host $Message
}
