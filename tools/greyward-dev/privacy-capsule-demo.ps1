[CmdletBinding()]
param(
    [ValidateSet('Normal', 'Microphone', 'Camera', 'Clipboard', 'Usb', 'ProtectionDegraded', 'Multiple', 'Stale', 'Unavailable', 'Deferred')]
    [string]$Scenario = 'Normal',
    [switch]$Stop
)

# Development-only visual fixture. It is opt-in, lives in /tmp on the guest,
# and is removed by -Stop. It never changes the production configuration.
. (Join-Path $PSScriptRoot 'common.ps1')
Repair-GreywardSsh | Out-Null

$devRoot = '/home/stendev/.local/share/greyward/dev'
$securityRoot = "$devRoot/security-center"
$fixturePath = '/tmp/greyward-privacy-capsule-fixture.json'
$overridePath = '/home/stendev/.config/systemd/user/greyward-security-context-user.service.d/privacy-demo.conf'

if ($Stop) {
    Invoke-GreywardSessionSsh "rm -f '$fixturePath' '$overridePath'; systemctl --user daemon-reload; systemctl --user restart greyward-security-context-user.service; systemctl --user is-active greyward-security-context-user.service"
    Write-GreywardResult -Data @{component='privacy-capsule-demo'; state='stopped'} -Message 'PRIVACY CAPSULE DEMO STOPPED'
    exit 0
}

Invoke-GreywardScp -Recursive -Source (Join-Path $script:RepoRoot 'security-center\security-context') -Destination "$($script:SshAlias):$securityRoot/"
$override = @"
[Service]
Environment=GREYWARD_PRIVACY_CAPSULE_FIXTURE=$fixturePath
Environment=PYTHONPATH=$securityRoot/security-context
ExecStart=
ExecStart=/usr/bin/python3 $securityRoot/security-context/greyward_security_context/session10_bus.py
"@
$overrideEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($override))
$remoteSetup = @"
if [ ! -f '$overridePath' ]; then
    mkdir -p ~/.config/systemd/user/greyward-security-context-user.service.d
    printf '%s' '$overrideEncoded' | base64 -d > '$overridePath'
    systemctl --user daemon-reload
    systemctl --user restart greyward-security-context-user.service
fi
"@
Invoke-GreywardSessionSsh ($remoteSetup.Trim())

$inactive = @(
    @{ signal_id='microphone'; category='ACTIVE_SENSOR'; capability='SUPPORTED'; state='INACTIVE'; title='Microphone inactive' },
    @{ signal_id='camera'; category='ACTIVE_SENSOR'; capability='SUPPORTED'; state='INACTIVE'; title='Camera inactive' },
    @{ signal_id='screen-share'; category='SCREEN_SHARE'; capability='UNAVAILABLE'; state='UNAVAILABLE'; title='Screen sharing unavailable'; reason='REQUIRES_ACTIVE_PORTAL_SESSION_OBSERVER' },
    @{ signal_id='clipboard'; category='SENSITIVE_DATA'; capability='SUPPORTED'; state='INACTIVE'; title='Sensitive clipboard inactive' },
    @{ signal_id='usb'; category='USB_DEVICE'; capability='SUPPORTED'; state='INACTIVE'; title='No new USB device' },
    @{ signal_id='secure-dns'; category='DEGRADED_PROTECTION'; capability='SUPPORTED'; state='INACTIVE'; title='Secure DNS operating' },
    @{ signal_id='network-load'; category='UNUSUAL_ACTIVITY'; capability='DEFERRED'; state='DEFERRED'; title='Network load unavailable'; reason='REQUIRES_DEDICATED_NETWORK_ACCOUNTING' }
)
$scenarios = @{
    Normal = $inactive
    Microphone = @($inactive[0].Clone(); @{ signal_id='microphone:demo'; category='ACTIVE_SENSOR'; capability='SUPPORTED'; state='ACTIVE'; title='Microphone in use'; detail='Demo Recorder is using your microphone.'; application='Demo Recorder'; actions=@('open_privacy') })
    Camera = @($inactive[1].Clone(); @{ signal_id='camera:demo'; category='ACTIVE_SENSOR'; capability='SUPPORTED'; state='ACTIVE'; title='Camera in use'; detail='Demo Camera is using your camera.'; application='Demo Camera'; device='Virtual Camera'; actions=@('open_privacy') })
    Clipboard = @($inactive[3].Clone(); @{ signal_id='clipboard'; category='SENSITIVE_DATA'; capability='SUPPORTED'; state='ACTIVE'; title='Sensitive clipboard detected'; detail='Category: API token.'; actions=@('clear_clipboard','open_privacy') })
    Usb = @($inactive[4].Clone(); @{ signal_id='usb:demo'; category='USB_DEVICE'; capability='SUPPORTED'; state='INFO'; title='USB device connected'; detail='Demo USB storage'; device='Demo USB storage'; actions=@('open_devices') })
    ProtectionDegraded = @($inactive[5].Clone(); @{ signal_id='secure-dns'; category='DEGRADED_PROTECTION'; capability='SUPPORTED'; state='DEGRADED'; title='Secure DNS degraded'; detail='Effective state: CompatibilityFallback.'; reason='Demo fallback'; actions=@('open_network') })
    Multiple = @(
        @{ signal_id='microphone:demo'; category='ACTIVE_SENSOR'; capability='SUPPORTED'; state='ACTIVE'; title='Microphone in use'; detail='Demo Recorder is using your microphone.'; application='Demo Recorder'; actions=@('open_privacy') },
        @{ signal_id='camera:demo'; category='ACTIVE_SENSOR'; capability='SUPPORTED'; state='ACTIVE'; title='Camera in use'; detail='Demo Camera is using your camera.'; application='Demo Camera'; device='Virtual Camera'; actions=@('open_privacy') },
        @{ signal_id='clipboard'; category='SENSITIVE_DATA'; capability='SUPPORTED'; state='ACTIVE'; title='Sensitive clipboard detected'; detail='Category: API token.'; actions=@('clear_clipboard','open_privacy') },
        @{ signal_id='secure-dns'; category='DEGRADED_PROTECTION'; capability='SUPPORTED'; state='DEGRADED'; title='Secure DNS degraded'; detail='Effective state: CompatibilityFallback.'; reason='Demo fallback'; actions=@('open_network') }
    )
    Stale = @(@{ signal_id='microphone'; category='ACTIVE_SENSOR'; capability='SUPPORTED'; state='STALE'; title='Microphone state stale'; reason='Demo freshness timeout'; fresh_seconds=1 })
    Unavailable = @(@{ signal_id='camera'; category='ACTIVE_SENSOR'; capability='SUPPORTED'; state='UNAVAILABLE'; title='Camera unavailable'; reason='Demo source unavailable' })
    Deferred = @(@{ signal_id='network-load'; category='UNUSUAL_ACTIVITY'; capability='DEFERRED'; state='DEFERRED'; title='Network load deferred'; reason='REQUIRES_DEDICATED_NETWORK_ACCOUNTING' })
}

$payload = @{ signals = $scenarios[$Scenario] } | ConvertTo-Json -Depth 8 -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
$remoteFixture = "printf '%s' '$encoded' | base64 -d > '$fixturePath'"
Invoke-GreywardSessionSsh $remoteFixture
Write-GreywardResult -Data @{component='privacy-capsule-demo'; state=$Scenario; fixture=$fixturePath} -Message "PRIVACY CAPSULE DEMO ACTIVE: $Scenario"
