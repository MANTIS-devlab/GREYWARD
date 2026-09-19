[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$errors = [Collections.Generic.List[string]]::new()
Get-ChildItem $repo -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '\\(\.git|build|cache|output|target|packer_cache|node_modules)\\' } | ForEach-Object {
    $tokens = $null; $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$parseErrors) | Out-Null
    foreach ($error in $parseErrors) { $errors.Add("$($_.FullName):$($error.Extent.StartLineNumber): $($error.Message)") }
}
Get-ChildItem $repo -Recurse -Filter *.json | Where-Object { $_.FullName -notmatch '\\(\.git|build|cache|output|target|packer_cache|node_modules)\\' } | ForEach-Object {
    try { $document = [System.Text.Json.JsonDocument]::Parse((Get-Content $_.FullName -Raw)); $document.Dispose() } catch { $errors.Add("Invalid JSON $($_.FullName): $($_.Exception.Message)") }
}
Get-ChildItem (Join-Path $repo 'branding') -Recurse -Filter *.svg | ForEach-Object {
    try { [xml](Get-Content $_.FullName -Raw) | Out-Null } catch { $errors.Add("Invalid SVG $($_.FullName): $($_.Exception.Message)") }
}
& (Join-Path $repo 'tools\validate-branding.ps1') | Out-Host
if ($LASTEXITCODE -ne 0) { $errors.Add('Branding validation failed.') }
& (Join-Path $repo 'tools\validate-repository.ps1') | Out-Host
if ($LASTEXITCODE -ne 0) { $errors.Add('Repository structure/documentation validation failed.') }

$defaultAppsPath = Join-Path $repo 'environment\flatpak\default-applications.list'
$mimeAppsPath = Join-Path $repo 'environment\flatpak\mimeapps.list'
$braveFlagsPath = Join-Path $repo 'environment\flatpak\brave-flags.conf'
$softwareWrapperPath = Join-Path $repo 'environment\flatpak\greyward-software'
$softwareDesktopPath = Join-Path $repo 'environment\flatpak\software.desktop'
$softwareRuntimeDesktopPath = Join-Path $repo 'environment\flatpak\software-runtime.desktop'
$productionProvisionPath = Join-Path $repo 'environment\production\provision.sh'
$productionManifestPath = Join-Path $repo 'environment\production\manifest.json'
$productionAcceptancePath = Join-Path $repo 'tests\production-acceptance.sh'
$productionAcceptanceImplementationPath = Join-Path $repo 'environment\production\production-acceptance.sh'
$developmentOverlayPath = Join-Path $repo 'environment\development\provision-overlay.sh'
$imageEntryPoint = Join-Path $repo 'environment\image\build.sh'
$imageIsoEntryPoint = Join-Path $repo 'environment\image\build-iso.sh'
$imageKickstartPath = Join-Path $repo 'environment\image\installer.ks.tmpl'
$firstbootScriptPath = Join-Path $repo 'environment\production\provision-firstboot.sh'
$firstbootServicePath = Join-Path $repo 'environment\production\provision-firstboot.service'
$firstbootStatusScriptPath = Join-Path $repo 'environment\production\firstboot-status.sh'
$firstbootStatusServicePath = Join-Path $repo 'environment\production\firstboot-status.service'
$greeterWallpaperSyncPath = Join-Path $repo 'environment\production\greyward-sync-greeter-wallpaper'
$autoUpdateScriptPath = Join-Path $repo 'security-center\security-context\bin\greyward-auto-update'
$autoUpdateServicePath = Join-Path $repo 'security-center\security-context\systemd\greyward-auto-update.service'
$autoUpdateTimerPath = Join-Path $repo 'security-center\security-context\systemd\greyward-auto-update.timer'
$labwcEnvironmentPath = Join-Path $repo 'environment\production\labwc-environment'
$sessionDesktopPath = Join-Path $repo 'environment\session\greyward-labwc.desktop'
$labwcSessionLauncherPath = Join-Path $repo 'environment\production\greyward-start-labwc'
$dmsServicePath = Join-Path $repo 'environment\session\greyward-dms.service'
$artifactPolicyPath = Join-Path $repo 'environment\production\artifact-policy.json'
$dmsSettingsPath = Join-Path $repo 'environment\session\dankmaterialshell\settings.json'
$dmsSessionMigratePath = Join-Path $repo 'environment\session\greyward-dms-session-migrate'
$dmsPluginSettingsPath = Join-Path $repo 'environment\session\dankmaterialshell\plugin_settings.json'
$dmsThemePath = Join-Path $repo 'environment\session\dankmaterialshell\greyward-obsidian.json'
$labwcThemePath = Join-Path $repo 'environment\session\labwc\Greyward\themerc'
$securityCenterStylesPath = Join-Path $repo 'security-center\tauri\frontend\styles.css'
$developmentPackagesPath = Join-Path $repo 'environment\development\packages.txt'
$productionPackagesPath = Join-Path $repo 'environment\production\packages.txt'
$cryptoPolicyDocPath = Join-Path $repo 'docs\security\crypto-policy.md'
$cryptoPolicyModulePath = Join-Path $repo 'environment\production\crypto-policy\GREYWARD.pmod'
$securityCenterRoutePath = Join-Path $repo 'security-center\data\greyward-security-center-route'
$securePluginManifestPath = Join-Path $repo 'environment\session\dankmaterialshell\plugins\greywardSecure\plugin.json'
$securePluginWidgetPath = Join-Path $repo 'environment\session\dankmaterialshell\plugins\greywardSecure\SecureWidget.qml'
$networkTrafficPluginDirectory = Join-Path $repo 'environment\session\dankmaterialshell\plugins\greywardNetworkTraffic'
$networkTrafficPluginManifestPath = Join-Path $networkTrafficPluginDirectory 'plugin.json'
$networkTrafficPluginWidgetPath = Join-Path $networkTrafficPluginDirectory 'NetworkTrafficWidget.qml'
$networkTrafficPluginModelPath = Join-Path $networkTrafficPluginDirectory 'NetworkTrafficModel.qml'
$networkTrafficPluginMathPath = Join-Path $networkTrafficPluginDirectory 'NetworkTrafficMath.js'
$publicIpPluginDirectory = Join-Path $repo 'environment\session\dankmaterialshell\plugins\greywardPublicIp'
$publicIpPluginManifestPath = Join-Path $publicIpPluginDirectory 'plugin.json'
$publicIpPluginWidgetPath = Join-Path $publicIpPluginDirectory 'PublicIpWidget.qml'
$factoryPath = Join-Path $repo 'environment\greyward.pkr.hcl'
$rootLicensePath = Join-Path $repo 'LICENSE'
$licensingPath = Join-Path $repo 'LICENSING.md'
$securityWorkspaceManifestPath = Join-Path $repo 'security-center\Cargo.toml'
$securityCenterSpecPath = Join-Path $repo 'security-center\packaging\greyward-security-center.spec'
$securityContextSpecPath = Join-Path $repo 'security-center\packaging\greyward-security-context.spec'
$brandingSpecPath = Join-Path $repo 'packaging\greyward-branding\SPECS\greyward-branding.spec'
$brandingProvenancePath = Join-Path $repo 'branding\PROVENANCE.md'
$brandingLicensePath = Join-Path $repo 'branding\LICENSE'
$thirdPartyNoticesPath = Join-Path $repo 'security-center\THIRD_PARTY_NOTICES.md'
$interFontPath = Join-Path $repo 'security-center\data\fonts\InterVariable.ttf'
$materialFontPath = Join-Path $repo 'security-center\data\fonts\MaterialSymbolsRounded.ttf'
$interLicensePath = Join-Path $repo 'security-center\data\fonts\Inter-OFL-1.1.txt'
$materialLicensePath = Join-Path $repo 'security-center\data\fonts\Material-Symbols-Apache-2.0.txt'
$publicExportPath = Join-Path $repo 'tools\export-public-repository.ps1'
$factoryCreatePath = Join-Path $repo 'tools\greyward-dev\create.ps1'
$developmentKickstartPaths = @(
    (Join-Path $repo 'environment\http\greyward-dev-bootstrap.ks.tmpl'),
    (Join-Path $repo 'environment\http\greyward-dev-boottest.ks.tmpl')
)
$wallpaperDirectory = Join-Path $repo 'branding\wallpaper'
$retiredGreeterWallpaperPath = Join-Path $repo 'branding\greeter\greyward-greeter-28963.jpg'
$session10ReportPath = Join-Path $repo 'docs\security-center\SESSION_10_REPORT.md'
$session10GatePath = Join-Path $repo 'security-center\tests\session10-gate.sh'
$interactionTestPath = Join-Path $repo 'security-center\tauri\frontend\interaction.test.mjs'
$portalConfigPath = Join-Path $repo 'environment\flatpak\labwc-portals.conf'
$rygelOverridePath = Join-Path $repo 'environment\production\desktop-entry-overrides\rygel-preferences.desktop'
$blackboxDesktopOverridePath = Join-Path $repo 'environment\production\desktop-entry-overrides\com.raggesilver.BlackBox.desktop'
$terminalOverridePath = $blackboxDesktopOverridePath
$blackboxSchemePath = Join-Path $repo 'environment\production\blackbox\schemes\greyward-obsidian.json'
$blackboxDarkPastelSchemePath = Join-Path $repo 'environment\production\blackbox\schemes\dark-pastel.json'
$blackboxParaisoSchemePath = Join-Path $repo 'environment\production\blackbox\schemes\paraiso-dark.json'
$blackboxSetiSchemePath = Join-Path $repo 'environment\production\blackbox\schemes\seti.json'
$blackboxVibrantInkSchemePath = Join-Path $repo 'environment\production\blackbox\schemes\vibrant-ink.json'
$blackboxDconfPath = Join-Path $repo 'environment\production\dconf\50-greyward-blackbox'
$terminalIconPath = Join-Path $repo 'branding\source\greyward-terminal.svg'
$zshConfiguratorPath = Join-Path $repo 'environment\production\configure-zsh.sh'
$zshSourcesPath = Join-Path $repo 'environment\production\zsh\sources.env'
$zshrcPath = Join-Path $repo 'environment\production\zsh\zshrc'
$p10kPath = Join-Path $repo 'environment\production\zsh\p10k.zsh'
$terminalBriefPath = Join-Path $repo 'environment\production\zsh\greyward-terminal-brief.py'
$terminalBriefTestPath = Join-Path $repo 'security-center\security-context\tests\test_terminal_brief.py'
$auditRulesPath = Join-Path $repo 'environment\production\audit\greyward.rules'
$greeterSelinuxPath = Join-Path $repo 'environment\production\selinux\greyward-dms-greeter.cil'
$uwsmLabwcPatchPath = Join-Path $repo 'environment\production\patch-uwsm-labwc.sh'
$devDeployPath = Join-Path $repo 'tools\greyward-dev\deploy.ps1'
$dmsSettingsPatchPath = Join-Path $repo 'environment\patches\dms\greyward-settings-curation.patch'
$dmsLabwcRuntimePatchPath = Join-Path $repo 'environment\patches\dms\greyward-labwc-runtime.patch'
$dmsLauncherHitboxPatchPath = Join-Path $repo 'environment\patches\dms\launcher-canonical-hitbox.patch'
$dmsAppsDockLabelsPatchPath = Join-Path $repo 'environment\patches\dms\apps-dock-taskbar-labels.patch'
$dmsAppsDockToggleMinimizePatchPath = Join-Path $repo 'environment\patches\dms\apps-dock-toggle-minimize.patch'
$dmsAppsDockSpacingPatchPath = Join-Path $repo 'environment\patches\dms\apps-dock-spacing.patch'
$dmsDisableChangelogPatchPath = Join-Path $repo 'environment\patches\dms\disable-changelog.patch'
$dmsFlatpakIconResolutionPatchPath = Join-Path $repo 'environment\patches\dms\greyward-flatpak-icon-resolution.patch'
$dmsTrayIconFallbackPatchPath = Join-Path $repo 'environment\patches\dms\greyward-tray-icon-fallback.patch'
$securityContractPath = Join-Path $repo 'environment\production\security-center-contract.tsv'
$anacondaCssPath = Join-Path $repo 'packaging\greyward-branding\SOURCES\greyward-anaconda.css'
$anacondaConfPath = Join-Path $repo 'packaging\greyward-branding\SOURCES\greyward-anaconda.conf'
foreach ($required in @($defaultAppsPath, $mimeAppsPath, $braveFlagsPath, $softwareWrapperPath, $softwareDesktopPath, $softwareRuntimeDesktopPath, $productionProvisionPath, $productionManifestPath, $productionAcceptancePath, $productionAcceptanceImplementationPath, $imageEntryPoint, $imageIsoEntryPoint, $imageKickstartPath, $firstbootScriptPath, $firstbootServicePath, $greeterWallpaperSyncPath, $autoUpdateScriptPath, $autoUpdateServicePath, $autoUpdateTimerPath, $labwcEnvironmentPath, $sessionDesktopPath, $labwcSessionLauncherPath, $dmsServicePath, $artifactPolicyPath, $auditRulesPath, $greeterSelinuxPath, $uwsmLabwcPatchPath, $dmsSettingsPatchPath, $dmsLabwcRuntimePatchPath, $dmsLauncherHitboxPatchPath, $dmsSettingsPath, $securityCenterRoutePath, $securePluginManifestPath, $securePluginWidgetPath, $networkTrafficPluginManifestPath, $networkTrafficPluginWidgetPath, $networkTrafficPluginModelPath, $networkTrafficPluginMathPath, $publicIpPluginManifestPath, $publicIpPluginWidgetPath, $session10ReportPath, $session10GatePath, $interactionTestPath, $portalConfigPath, $rygelOverridePath, $blackboxDesktopOverridePath, $blackboxSchemePath, $blackboxDarkPastelSchemePath, $blackboxParaisoSchemePath, $blackboxSetiSchemePath, $blackboxVibrantInkSchemePath, $blackboxDconfPath, $terminalIconPath, $zshConfiguratorPath, $zshSourcesPath, $zshrcPath, $p10kPath, $terminalBriefPath, $terminalBriefTestPath, $devDeployPath, $cryptoPolicyDocPath, $cryptoPolicyModulePath, $dmsAppsDockSpacingPatchPath, $dmsDisableChangelogPatchPath, $dmsFlatpakIconResolutionPatchPath, $dmsTrayIconFallbackPatchPath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        $errors.Add("Flatpak default application input is missing: $required")
    }
}

foreach ($requiredFirstbootStatus in @($firstbootStatusScriptPath, $firstbootStatusServicePath)) {
    if (-not (Test-Path -LiteralPath $requiredFirstbootStatus)) {
        $errors.Add("First-boot status input is missing: $requiredFirstbootStatus")
    }
}

if (Test-Path -LiteralPath $dmsDisableChangelogPatchPath) {
    $dmsDisableChangelogPatch = Get-Content -Raw -LiteralPath $dmsDisableChangelogPatchPath
    if ($dmsDisableChangelogPatch -notmatch 'quickshell/dms/Services/ChangelogService\.qml' -or
        $dmsDisableChangelogPatch -notmatch 'changelogEnabled: false') {
        $errors.Add("The production DMS patch must disable the first-boot What's New changelog popup at its source.")
    }
}

$autoUpdateScript = Get-Content -Raw -LiteralPath $autoUpdateScriptPath
$autoUpdateService = Get-Content -Raw -LiteralPath $autoUpdateServicePath
$autoUpdateTimer = Get-Content -Raw -LiteralPath $autoUpdateTimerPath
if ($autoUpdateScript -notmatch 'check-upgrade.*--json' -or
    $autoUpdateScript -notmatch 'UPDATE_HELPER' -or
    $autoUpdateScript -notmatch '"apply", "--operation-id"' -or
    $autoUpdateScript -notmatch 'operation_id = f"dnf5-' -or
    $autoUpdateScript -match 'pkexec|sudo|shell=True' -or
    $autoUpdateScript -notmatch 'notify-send' -or
    $autoUpdateService -notmatch '(?m)^User=root\s*$' -or
    $autoUpdateService -notmatch '(?m)^NoNewPrivileges=yes\s*$' -or
    $autoUpdateService -notmatch 'ProtectHome=read-only' -or
    $autoUpdateTimer -notmatch '(?m)^OnUnitActiveSec=2d\s*$' -or
    $autoUpdateTimer -notmatch '(?m)^Persistent=true\s*$') {
    $errors.Add('Automatic system updates must use the fixed root helper, no shell/pkexec path, hardened service settings, a two-day timer, and desktop notification.')
}

if (Test-Path -LiteralPath $securePluginWidgetPath) {
    $securePluginWidget = Get-Content -Raw -LiteralPath $securePluginWidgetPath
    if ($securePluginWidget -match '(?m)^\s*ToolTip\.(visible|delay|text)\s*:') {
        $errors.Add('The Security Center taskbar widget must not display a hover tooltip.')
    }
}

if (Test-Path -LiteralPath $dmsLauncherHitboxPatchPath) {
    $dmsLauncherHitboxPatch = Get-Content -Raw -LiteralPath $dmsLauncherHitboxPatchPath
    if ($dmsLauncherHitboxPatch -notmatch 'quickshell/dms/Modules/Plugins/BasePill\.qml' -or $dmsLauncherHitboxPatch -notmatch 'quickshell/dms/Modules/DankBar/Widgets/LauncherButton\.qml' -or $dmsLauncherHitboxPatch -notmatch 'quickshell/dms/Modules/DankBar/BarCanvas\.qml') {
        $errors.Add('The DMS launcher hitbox patch must cover the shared BasePill, launcher opt-in, and redundant bar overlay.')
    }
    if ($dmsLauncherHitboxPatch -notmatch 'property bool extendHitboxToBarEdge: true' -or $dmsLauncherHitboxPatch -notmatch 'property real hitboxWidth: width' -or $dmsLauncherHitboxPatch -notmatch 'property real hitboxHeight: height') {
        $errors.Add('The shared DMS BasePill hitbox must preserve its existing default geometry.')
    }
    if ($dmsLauncherHitboxPatch -notmatch 'root\.hitboxWidth\) / 2' -or $dmsLauncherHitboxPatch -notmatch 'root\.hitboxHeight\) / 2' -or $dmsLauncherHitboxPatch -notmatch 'extendHitboxToBarEdge \?') {
        $errors.Add('The DMS launcher hitbox must be centered independently from the bar-edge extension.')
    }
    if ($dmsLauncherHitboxPatch -notmatch 'extendHitboxToBarEdge: false' -or $dmsLauncherHitboxPatch -notmatch 'launcherVisualSize' -or $dmsLauncherHitboxPatch -notmatch 'hitboxWidth: Math\.max\(visualWidth, launcherVisualSize\)' -or $dmsLauncherHitboxPatch -notmatch 'hitboxHeight: Math\.max\(visualHeight, launcherVisualSize\)') {
        $errors.Add('The DMS launcher must use one centered hitbox covering the full rendered logo.')
    }
    if ($dmsLauncherHitboxPatch -match '(?m)^\+Item \{' -or $dmsLauncherHitboxPatch -match 'hitboxExtension') {
        $errors.Add('The DMS launcher hitbox patch must not replace or resize the launcher visual component.')
    }
    if ($dmsLauncherHitboxPatch -notmatch '(?m)^--- a/quickshell/dms/Modules/DankBar/BarCanvas\.qml$' -or $dmsLauncherHitboxPatch -notmatch '(?m)^@@ -170,18 \+170,0') {
        $errors.Add('The redundant full-bar BarCanvas click area must remain removed.')
    }
}

if ((Test-Path -LiteralPath $productionProvisionPath) -and (Test-Path -LiteralPath $productionAcceptanceImplementationPath)) {
    $productionProvision = Get-Content -Raw -LiteralPath $productionProvisionPath
    $productionPackages = Get-Content -Raw -LiteralPath $productionPackagesPath
    $firstbootScript = Get-Content -Raw -LiteralPath $firstbootScriptPath
    $firstbootService = Get-Content -Raw -LiteralPath $firstbootServicePath
    $productionAcceptance = Get-Content -Raw -LiteralPath $productionAcceptanceImplementationPath
    if ($productionProvision -notmatch 'crypto-policy/GREYWARD\.pmod' -or
        $productionProvision -notmatch 'update-crypto-policies --set DEFAULT:GREYWARD' -or
        $productionProvision -notmatch 'update-crypto-policies --show' -or
        $productionProvision -notmatch 'update-crypto-policies --is-applied' -or
        $productionPackages -notmatch '(?m)^crypto-policies\s*$' -or
        $productionPackages -notmatch '(?m)^crypto-policies-scripts\s*$' -or
        $productionPackages -notmatch '(?m)^gnome-text-editor\s*$' -or
        $productionPackages -notmatch '(?m)^NetworkManager-openvpn\s*$' -or
        $productionPackages -notmatch '(?m)^net-tools\s*$') {
        $errors.Add('Production must explicitly install and apply DEFAULT:GREYWARD crypto policy.')
    }
    if ($productionProvision -match 'printf.*greyward-production-complete' -or $productionProvision -notmatch 'rm -f /etc/greyward-production-complete') {
        $errors.Add('Production provisioning must not create the completion marker before installed-root acceptance.')
    }
    if ($productionProvision -notmatch 'HYPRLAND_INSTANCE_SIGNATURE' -or $productionProvision -notmatch 'XDG_CURRENT_DESKTOP=GNOME') {
        $errors.Add('Production provisioning does not scope competing Polkit and GNOME portal services to their owning sessions.')
    }
    if ($productionProvision -notmatch 'audit/greyward\.rules' -or
        $productionProvision -notmatch 'augenrules --load' -or
        $productionProvision -notmatch 'selinux/greyward-dms-greeter\.cil' -or
        $productionProvision -notmatch 'patch-uwsm-labwc\.sh') {
        $errors.Add('Production provisioning does not install and activate the audit, SELinux, and UWSM fixes.')
    }
    if ($productionProvision -notmatch 'production_users' -or
        $productionProvision -notmatch 'production_home.*DankMaterialShell/settings\.json' -or
        $productionProvision -notmatch 'production_home.*labwc/rc\.xml' -or
        $productionProvision -notmatch 'greyward-wallpaper-black-art-4k\.jpg' -or
        $productionProvision -notmatch 'greyward-labwc\.desktop' -or
        $productionProvision -notmatch '3 >= 1000 && \$6 ~ /\^\\/home\\//' -or
        (Get-Content -Raw -LiteralPath (Join-Path $repo 'environment\production\labwc-autostart')) -notmatch 'greyward-security-context-user\.service') {
        $errors.Add('Production provisioning must seed the Anaconda-created user home and start Security Context at the Labwc session boundary.')
    }
    if ($productionAcceptance -notmatch 'greyward-production-complete' -or $productionAcceptance -notmatch '--pre-marker') {
        $errors.Add('The production acceptance contract must distinguish the pre-marker finalization check.')
    }
    if ($firstbootScript -match 'account-contract|account-handoff|greyward-live' -or
        $firstbootScript -notmatch 'systemctl mask "\$unit"' -or
        $firstbootScript -notmatch 'systemctl --global mask' -or
        $firstbootScript -notmatch 'production-acceptance --pre-marker' -or
        $firstbootScript -notmatch 'production-ready' -or
        $firstbootScript -notmatch 'production-pending') {
        $errors.Add('The first-boot finalizer must be a single retryable production gate with no live-account hand-off.')
    }
    if ($firstbootService -notmatch 'Before=initial-setup\.service display-manager\.service greetd\.service graphical\.target' -or
        $firstbootService -notmatch 'Type=exec' -or
        $firstbootService -notmatch 'Restart=on-failure' -or
        $firstbootService -match 'network-online\.target' -or
        $firstbootService -match 'live-install') {
        $errors.Add('The first-boot service must gate the display manager and retry without live-install conditions.')
    }
    if ($firstbootScript -notmatch 'reset-failed greetd\.service' -or
        $firstbootScript -notmatch 'systemctl start greetd\.service' -or
        $firstbootScript -notmatch 'is-active --quiet greetd\.service' -or
        $firstbootScript -notmatch 'pgrep -u greeter -x dms-greeter' -or
        $firstbootScript -notmatch 'pgrep -u greeter -x labwc' -or
        $firstbootScript -notmatch 'greetd-failure\.txt') {
        $errors.Add('First-boot finalization must verify the actual DMS Greeter/Labwc hand-off after acceptance succeeds.')
    }
    if ($productionProvision.Contains('cp -a "$stage/offline/gitstatus/." /usr/share/greyward/zsh/gitstatus/') -or
        $productionProvision -notmatch 'gitstatus_stage=\$\(mktemp -d' -or
        $productionProvision -notmatch 'mv -f -- "\$staged_file" "\$target_file"' -or
        $productionProvision -match 'rmdir "\$gitstatus_stage"') {
        $errors.Add('Offline gitstatus provisioning must stage files, rename them into place, and let find clean the temporary tree without a second root-directory removal.')
    }
}

$firstbootStatusScript = Get-Content -Raw -LiteralPath $firstbootStatusScriptPath
$firstbootStatusService = Get-Content -Raw -LiteralPath $firstbootStatusServicePath
if ($firstbootStatusScript -notmatch '/dev/tty1' -or
    $firstbootStatusScript -notmatch 'do not turn off the computer' -or
    $firstbootStatusScript -notmatch 'production-pending' -or
    $firstbootStatusScript -notmatch 'plymouth display-message' -or
    $firstbootStatusScript -notmatch 'provision-current-phase\.txt' -or
    $firstbootStatusScript -notmatch 'provision-failure\.txt' -or
    $firstbootStatusScript -notmatch 'tail -n 20') {
    $errors.Add('First-boot status must show a persistent wait message on tty1 while production-pending exists.')
}
if ($firstbootStatusService -notmatch 'ConditionPathExists=/var/lib/greyward/installer/production-pending' -or
    $firstbootStatusService -notmatch 'Before=greyward-production-firstboot\.service' -or
    $firstbootStatusService -notmatch 'Restart=always') {
    $errors.Add('First-boot status service must run before provisioning and remain available during retries.')
}
$labwcEnvironment = Get-Content -Raw -LiteralPath $labwcEnvironmentPath
$sessionDesktop = Get-Content -Raw -LiteralPath $sessionDesktopPath
$labwcSessionLauncher = Get-Content -Raw -LiteralPath $labwcSessionLauncherPath
if ($productionProvision -notmatch '/usr/bin/env WLR_RENDERER=pixman' -or
    $productionProvision -match 'WLR_DRM_DEVICES=' -or
    $productionProvision -notmatch 'WLR_RENDERER_ALLOW_SOFTWARE=1' -or
    $productionProvision -notmatch 'QT_QUICK_BACKEND=software' -or
    $productionProvision -notmatch 'XDG_CONFIG_HOME=/var/cache/dms-greeter/\.config' -or
    $productionProvision -notmatch 'only into that greeter process' -or
    $labwcEnvironment -match '(?m)^WLR_RENDERER=pixman\s*$' -or
    $sessionDesktop -notmatch '(?m)^Exec=/usr/local/libexec/greyward-start-labwc\s*$' -or
    $labwcSessionLauncher -notmatch '/sys/class/dmi/id/sys_vendor' -or
    $labwcSessionLauncher -notmatch 'vmware|hyper-?v|virtual machine' -or
    $labwcSessionLauncher -notmatch '\(0x\)\?\(15ad\|1414\)' -or
    $labwcSessionLauncher -notmatch '/dev/dri/renderD\*' -or
    $labwcSessionLauncher -notmatch 'export WLR_RENDERER=pixman' -or
    $labwcSessionLauncher -notmatch 'exec uwsm start -D Labwc:GREYWARD labwc') {
    $errors.Add('The greeter must keep its software fallback, while the installed Labwc session must select Pixman only for unsupported virtual/no-render-node graphics and retain hardware rendering on capable bare metal.')
}
$greeterCheckIndex = $firstbootScript.IndexOf('if [[ "$greeter_ready" != true ]]')
$cleanupMarkerIndex = $firstbootScript.IndexOf('rm -f "$pending"')
$cleanupStageIndex = $firstbootScript.IndexOf('rm -rf "$stage"')
if ($greeterCheckIndex -lt 0 -or
    $cleanupMarkerIndex -le $greeterCheckIndex -or
    $cleanupStageIndex -le $greeterCheckIndex) {
    $errors.Add('The first-boot finalizer must retain its retry marker and payload stage until the GREYWARD login boundary is verified.')
}

$auditRules = Get-Content -Raw -LiteralPath $auditRulesPath
if ($auditRules -notmatch '(?m)^--loginuid-immutable\s*$' -or
    $auditRules -notmatch '(?m)^-w /etc/passwd .* -k identity$' -or
    $auditRules -notmatch 'key=module-load' -or
    $auditRules -notmatch 'key=software-installer' -or
    $auditRules -notmatch '(?m)^-e 2\s*$' -or
    $auditRules -match 'task,never') {
    $errors.Add('GREYWARD audit policy is not the intended moderate, enabled ruleset.')
}
$greeterSelinux = Get-Content -Raw -LiteralPath $greeterSelinuxPath
if ($greeterSelinux -notmatch 'allow xdm_t systemd_unit_file_t \(service \(status\)\)' -or
    $greeterSelinux -notmatch 'dontaudit xdm_t root_t \(dir \(watch\)\)' -or
    $greeterSelinux -notmatch 'dontaudit xdm_t var_t \(dir \(watch\)\)') {
    $errors.Add('GREYWARD DMS Greeter SELinux policy is not narrowly scoped.')
}
$uwsmLabwcPatch = Get-Content -Raw -LiteralPath $uwsmLabwcPatchPath
if ($uwsmLabwcPatch -notmatch 'TEMP_DROPIN_DIR' -or
    $uwsmLabwcPatch -notmatch 'install -d -m 0755' -or
    $uwsmLabwcPatch -notmatch 'GREYWARD_UWSM_LABWC_DROPIN_DIRECTORY') {
    $errors.Add('GREYWARD UWSM Labwc patch does not create the reload drop-in directory safely.')
}

if (Test-Path -LiteralPath $portalConfigPath) {
    $portalConfig = Get-Content -Raw -LiteralPath $portalConfigPath
    foreach ($requiredPortalMapping in @('default=gtk', 'ScreenCast=wlr', 'Screenshot=wlr', 'RemoteDesktop=none', 'GlobalShortcuts=none')) {
        if ($portalConfig -notmatch [regex]::Escape($requiredPortalMapping)) {
            $errors.Add("Labwc portal routing is missing: $requiredPortalMapping")
        }
    }
}

if (Test-Path -LiteralPath $rygelOverridePath) {
    $rygelOverride = Get-Content -Raw -LiteralPath $rygelOverridePath
    if ($rygelOverride -notmatch '(?m)^Name=Rygel Preferences$' -or $rygelOverride -notmatch '(?m)^Hidden=true$' -or $rygelOverride -notmatch '(?m)^NoDisplay=true$') {
        $errors.Add('Rygel Preferences must be hidden through a complete standards-compliant desktop-entry override.')
    }
}

if (Test-Path -LiteralPath $terminalOverridePath) {
    $terminalOverride = Get-Content -Raw -LiteralPath $terminalOverridePath
    foreach ($requiredTerminalEntry in @(
        '[Desktop Entry]',
        'Type=Application',
        'Name=Terminal',
        'Comment=Open a GREYWARD terminal for shell, console and command line work',
        'Exec=/usr/bin/env GREYWARD_TERMINAL_BRIEF=1 SHELL=/usr/bin/zsh blackbox-terminal',
        'Terminal=false',
        'Icon=greyward-terminal',
        'StartupWMClass=com.raggesilver.BlackBox',
        'Categories=Utility;TerminalEmulator;',
        'Keywords=terminal;console;shell;command;command line;'
    )) {
        if ($terminalOverride -notmatch [regex]::Escape($requiredTerminalEntry)) {
            $errors.Add("GREYWARD Terminal desktop entry is missing: $requiredTerminalEntry")
        }
    }
    foreach ($sessionLauncher in @(
        (Join-Path $repo 'environment/session/labwc/rc.xml'),
        (Join-Path $repo 'environment/session/hyprland.conf')
    )) {
        if ((Test-Path -LiteralPath $sessionLauncher) -and (Get-Content -Raw -LiteralPath $sessionLauncher) -notmatch 'blackbox-terminal') {
            $errors.Add("Canonical session launcher must use GREYWARD Terminal: $sessionLauncher")
        }
    }
    if ((Get-Content -Raw -LiteralPath $productionProvisionPath) -notmatch 'desktop-entry-overrides/com\.raggesilver\.BlackBox\.desktop' -or
        (Get-Content -Raw -LiteralPath $imageEntryPoint) -notmatch 'desktop-entry-overrides/com\.raggesilver\.BlackBox\.desktop' -or
        (Get-Content -Raw -LiteralPath $devDeployPath) -notmatch 'desktop-entry-overrides/com\.raggesilver\.BlackBox\.desktop' -or
        (Get-Content -Raw -LiteralPath $devDeployPath) -notmatch 'launcher_cache\.json') {
        $errors.Add('Production/image/development deployment does not install Black Box as GREYWARD Terminal and invalidate the DMS launcher cache.')
    }
}

$blackboxDesktopOverride = Get-Content -Raw -LiteralPath $blackboxDesktopOverridePath
foreach ($requiredBlackboxEntry in @(
    'Exec=/usr/bin/env GREYWARD_TERMINAL_BRIEF=1 SHELL=/usr/bin/zsh blackbox-terminal',
    'Name=Terminal',
    'Icon=greyward-terminal',
    'StartupWMClass=com.raggesilver.BlackBox'
)) {
    if ($blackboxDesktopOverride -notmatch [regex]::Escape($requiredBlackboxEntry)) {
        $errors.Add("GREYWARD Black Box desktop entry is missing: $requiredBlackboxEntry")
    }
}
$blackboxDconf = Get-Content -Raw -LiteralPath $blackboxDconfPath
foreach ($requiredBlackboxSetting in @('command-as-login-shell=true', 'font=', 'style-preference=', 'terminal-bell=false', 'theme-dark=', 'terminal-padding=')) {
    if ($blackboxDconf -notmatch [regex]::Escape($requiredBlackboxSetting)) {
        $errors.Add("GREYWARD Black Box defaults are missing: $requiredBlackboxSetting")
    }
}
foreach ($capturedBlackboxSetting in @(
    "font='Cascadia Mono NF 14'",
    'opacity=uint32 93',
    'easy-copy-paste=true',
    'remember-window-size=true',
    "theme-dark='Dark Pastel'",
    "theme-light='Gruvbox Light'",
    'window-height=uint32 945',
    'window-width=uint32 1237',
    'terminal-padding=(uint32 12, uint32 12, uint32 12, uint32 12)'
)) {
    if ($blackboxDconf -notmatch [regex]::Escape($capturedBlackboxSetting)) {
        $errors.Add("Captured GREYWARD Black Box production state is missing: $capturedBlackboxSetting")
    }
}
$blackboxScheme = Get-Content -Raw -LiteralPath $blackboxSchemePath
if ($blackboxScheme -notmatch '"name": "GREYWARD Obsidian"' -or $blackboxScheme -notmatch '"background-color": "#0A1722"' -or $blackboxScheme -notmatch '"foreground-color": "#DFDFDD"') {
    $errors.Add('GREYWARD Black Box scheme does not preserve the production obsidian/platinum palette.')
}
foreach ($scheme in @(
    @{ Path = $blackboxDarkPastelSchemePath; Name = 'Dark Pastel' },
    @{ Path = $blackboxParaisoSchemePath; Name = 'Paraiso Dark' },
    @{ Path = $blackboxSetiSchemePath; Name = 'Seti' },
    @{ Path = $blackboxVibrantInkSchemePath; Name = 'Vibrant Ink' }
)) {
    $schemeText = Get-Content -Raw -LiteralPath $scheme.Path
    if ($schemeText -notmatch ('"name": "' + [regex]::Escape($scheme.Name) + '"') -or
        $schemeText -notmatch '"use-theme-colors": false' -or
        ([regex]::Matches($schemeText, '#[0-9a-fA-F]{6}').Count -ne 18)) {
        $errors.Add("Black Box scheme is incomplete: $($scheme.Name).")
    }
}

$zshConfigurator = Get-Content -Raw -LiteralPath $zshConfiguratorPath
$zshrc = Get-Content -Raw -LiteralPath $zshrcPath
$p10k = Get-Content -Raw -LiteralPath $p10kPath
$zshSources = Get-Content -Raw -LiteralPath $zshSourcesPath
$terminalBrief = Get-Content -Raw -LiteralPath $terminalBriefPath
if ($zshConfigurator -notmatch '/usr/share/greyward/zsh/sources\.env' -or
    $zshConfigurator -notmatch 'fetch --quiet --depth=1' -or
    $zshConfigurator -notmatch 'usermod --shell /usr/bin/zsh' -or
    $zshrc -notmatch 'ZSH_THEME="powerlevel10k/powerlevel10k"' -or
    $zshrc -notmatch 'DISABLE_AUTO_UPDATE=true' -or
    $p10k -notmatch 'POWERLEVEL9K_MODE=nerdfont-complete' -or
    ([regex]::Matches($p10k, '(?m)^    context +# current user$').Count -ne 1) -or
    $p10k -notmatch '(?m)^    dir +# current directory$' -or
    $p10k -notmatch "POWERLEVEL9K_CONTEXT_TEMPLATE='%n'" -or
    $p10k -notmatch '(?m)^  typeset -g POWERLEVEL9K_DIR_MAX_LENGTH=$' -or
    $zshrc -notmatch 'TERM_PROGRAM:-.*Black Box' -or
    $zshrc -notmatch 'GREYWARD_TERMINAL_BRIEF:-.*1' -or
    $zshrc -notmatch 'GREYWARD_TERMINAL_BRIEF_RENDERED' -or
    $zshrc -match 'export GREYWARD_TERMINAL_BRIEF_RENDERED' -or
    $zshrc -notmatch '/usr/local/libexec/greyward-terminal-brief' -or
    $zshrc -notmatch 'SSH_CONNECTION' -or
    $zshrc -notmatch 'ZSH_EXECUTION_STRING' -or
    $zshSources -notmatch 'GREYWARD_OH_MY_ZSH_REF=' -or
    $zshSources -notmatch 'GREYWARD_POWERLEVEL10K_REF=') {
    $errors.Add('Production zsh provisioning does not install pinned Oh My Zsh and Powerlevel10k defaults.')
}
if ($terminalBrief -notmatch 'def render\(' -or
    $terminalBrief -notmatch 'def render_compact\(' -or
    $terminalBrief -notmatch 'def _card\(' -or
    $terminalBrief -match 'RAPID_SESSION_SECONDS' -or
    $terminalBrief -match 'gdbus|dbus|dnf|flatpak|curl|wget|nmcli|systemctl|opensnitch' -or
    $terminalBrief -notmatch 'unknown') {
    $errors.Add('The terminal brief must use local system reads, neutral unknown fallbacks, and no provider calls.')
}
if ((Get-Content -Raw -LiteralPath $productionProvisionPath) -notmatch 'configure-zsh\.sh' -or
    (Get-Content -Raw -LiteralPath $imageEntryPoint) -notmatch 'configure-zsh\.sh' -or
        (Get-Content -Raw -LiteralPath $productionAcceptanceImplementationPath) -notmatch 'POWERLEVEL9K_MODE=nerdfont-complete' -or
    (Get-Content -Raw -LiteralPath $devDeployPath) -notmatch 'greyward-configure-zsh' -or
    (Get-Content -Raw -LiteralPath $productionProvisionPath) -notmatch 'greyward-terminal-brief\.py' -or
    (Get-Content -Raw -LiteralPath $devDeployPath) -notmatch 'greyward-terminal-brief\.py') {
    $errors.Add('Production/image/acceptance paths do not consume the canonical zsh payload.')
}

# The production image stage must not carry the disposable VM's Labwc
# environment/autostart pair. The source tree remains available to the
# development overlay, but image/build.sh must curate the shared compositor
# assets instead of copying the VM renderer and Virtual-1 setup into a
# production input directory.
$imageBuilder = Get-Content -Raw -LiteralPath $imageEntryPoint
if ($imageBuilder -match 'cp -a "\$session" "\$output/session"' -or
    $imageBuilder -match 'cp -a "\$session/labwc" "\$output/labwc"') {
    $errors += 'Production image staging must curate session/Labwc files and exclude the VM-only environment/autostart.'
}
if ($imageBuilder -notmatch 'cp -a "\$session/labwc/themerc" "\$output/labwc/Greyward/"') {
    $errors += 'Production image staging must place the Labwc theme where the production provisioner consumes it.'
}

foreach ($softwareDesktop in @($softwareDesktopPath, $softwareRuntimeDesktopPath)) {
    if ((Test-Path -LiteralPath $softwareDesktop) -and (Get-Content -Raw -LiteralPath $softwareDesktop) -notmatch '(?m)^Categories=Settings;PackageManager;$') {
        $errors.Add("Software must expose the complete PackageManager category hierarchy: $softwareDesktop")
    }
}

if (Test-Path -LiteralPath $braveFlagsPath) {
    if ((Get-Content -Raw -LiteralPath $braveFlagsPath) -notmatch '--enable-features=WaylandWindowDecorations') {
        $errors.Add('Brave Flatpak flags must enable persistent Wayland window decorations.')
    }
    if ((Get-Content -Raw -LiteralPath $productionProvisionPath) -notmatch 'brave-flags\.conf') {
        $errors.Add('Production provisioning does not seed Brave''s persistent Wayland decoration flags.')
    }
}

if (Test-Path -LiteralPath $securePluginManifestPath) {
    $securePluginManifest = Get-Content -Raw -LiteralPath $securePluginManifestPath
    if ($securePluginManifest -notmatch '"process"') {
        $errors.Add('The GREYWARD Secure DMS plugin uses local commands but does not declare the process permission.')
    }
}

if (Test-Path -LiteralPath $securityCenterRoutePath) {
    $securityCenterRoute = Get-Content -Raw -LiteralPath $securityCenterRoutePath
    if ($securityCenterRoute -notmatch 'threats\)') {
        $errors.Add('The Security Center route helper must support the threats destination.')
    }
    if ($securityCenterRoute -notmatch '\[\[ -n "\$event_id" && ! "\$event_id"') {
        $errors.Add('The Security Center route helper must allow the general threats page without a focused event id.')
    }
    if ($securityCenterRoute -notmatch '\[\[ "\$page" == "threats" && -n "\$event_id" \]\]') {
        $errors.Add('The Security Center route helper must only write a focused event when one is supplied.')
    }
}
if (Test-Path -LiteralPath $securePluginWidgetPath) {
    $securePluginWidget = Get-Content -Raw -LiteralPath $securePluginWidgetPath
    if ($securePluginWidget -notmatch '/usr/bin/gdbus') {
        $errors.Add('The GREYWARD Secure DMS plugin must use the packaged absolute gdbus path.')
    }
    if ($securePluginWidget -match 'GetShellSummary[\s\S]{0,1200}\},\s*(12000|16000)\)') {
        $errors.Add('The GREYWARD Secure DMS plugin must not use Proc.runCommand debounce as a transport timeout.')
    }
}

if (Test-Path -LiteralPath $imageKickstartPath) {
    $installer = Get-Content -Raw -LiteralPath $imageKickstartPath
    if ($installer -notmatch '/run/install/repo/greyward/production' -or
        $installer -notmatch 'payload\.sha256' -or
        $installer -notmatch 'media_root' -or
        $installer -notmatch 'payload copy did not create' -or
        $installer -notmatch 'target_stage' -or
        $installer -notmatch '/mnt/sysroot/usr/lib/greyward/installer/production' -or
        $installer -match 'target_stage=/mnt/sysroot/var/lib/greyward/installer/production') {
        $errors.Add('The production ISO Kickstart does not copy the GREYWARD production stage into the installed target.')
    }
    if ($installer -notmatch 'install -d -m 0755 /mnt/sysroot/var/lib/greyward/installer' -or
        $installer -notmatch 'touch /mnt/sysroot/var/lib/greyward/installer/production-pending') {
        $errors.Add('The installer must create the first-boot marker directory before writing production-pending.')
    }
    if ($installer -match 'liveinst|greyward-live|account-handoff|account-contract') {
        $errors.Add('The installer-only Kickstart must not carry a live desktop or temporary-account hand-off.')
    }
    if ($installer -notmatch '(?m)^autopart\s+--type=btrfs\s+--encrypted\s*$') {
        $errors.Add('The production ISO Kickstart does not require encrypted Btrfs automatic partitioning.')
    }
    if ($installer -match '(?m)^\s*user\s+') {
        $errors.Add('The production ISO Kickstart embeds a default installed user instead of leaving account creation to Anaconda.')
    }
    if ($installer -notmatch '(?m)^firstboot\s+--disable\s*$' -or
        $installer -match '(?m)^\s*rootpw\s+' -or
        $installer -notmatch 'offline/installer-packages\.ks' -or
        $installer -notmatch '(?m)^cdrom\s*$' -or
        $installer -match '(?m)^(url|repo)\s+' -or
        $installer -notmatch 'plymouth-set-default-theme greyward' -or
        $installer -match 'plymouth-set-default-theme -R' -or
        $installer -notmatch 'chroot /mnt/sysroot /usr/bin/dracut --regenerate-all --force' -or
        $installer -notmatch "greyward-branding-\*\.rpm" -or
        $installer -notmatch 'provision-firstboot\.service' -or
        $installer -notmatch 'production-pending' -or
        $installer -match 'chroot /mnt/sysroot.*provision\.sh') {
        $errors.Add('The production ISO Kickstart must leave account setup to Anaconda and defer GREYWARD provisioning to the retryable first boot gate.')
    }
    if ($installer -notmatch '(?m)^bootloader\s+--timeout=5\s*$' -or
        $installer -notmatch '(?m)^reboot\s+--eject\s*$' -or
        $installer -notmatch 'anaconda-reboot-requested') {
        $errors.Add('The installer-only Kickstart must request the standard post-install reboot.')
    }
}
if (-not (Test-Path -LiteralPath $securityContractPath)) {
    $errors.Add('The production Security Center package contract is missing.')
}
if (-not (Test-Path -LiteralPath $anacondaCssPath) -or -not (Test-Path -LiteralPath $anacondaConfPath)) {
    $errors.Add('The supported Anaconda GREYWARD branding sources are missing.')
} else {
    $anacondaCss = Get-Content -Raw -LiteralPath $anacondaCssPath
    $anacondaConf = Get-Content -Raw -LiteralPath $anacondaConfPath
    if ($anacondaCss -notmatch '(?m)^\.product-logo\s*\{' -or
        $anacondaCss -notmatch 'greyward-anaconda-logo\.png' -or
        $anacondaCss -notmatch 'greyward_obsidian' -or
        $anacondaCss -notmatch 'greyward_charcoal') {
        $errors.Add('The Anaconda stylesheet must provide the GREYWARD product logo and restrained dark chrome.')
    }
    if ($anacondaConf -notmatch '(?m)^profile_id\s*=\s*greyward\s*$' -or
        $anacondaConf -notmatch '(?m)^base_profile\s*=\s*fedora\s*$' -or
        $anacondaConf -notmatch '(?m)^os_id\s*=\s*fedora\s*$' -or
        $anacondaConf -match '(?im)^\s*variant_id\s*=\s*workstation\s*$' -or
        $anacondaConf -match '(?im)^\s*hidden_spokes\s*=.*UserSpoke' -or
        $anacondaConf -match '(?im)^\s*hidden_webui_pages\s*=.*anaconda-screen-accounts' -or
        $anacondaConf -notmatch '(?m)^hidden_spokes\s*=\s*$' -or
        $anacondaConf -notmatch '(?m)^hidden_webui_pages\s*=\s*$' -or
        $anacondaConf -notmatch '(?m)^custom_stylesheet\s*=\s*/usr/share/anaconda/pixmaps/greyward-anaconda\.css\s*$') {
        $errors.Add('The Anaconda GREYWARD profile must inherit Fedora, keep account creation visible, and use the supported stylesheet hook.')
    }
}
$imageBuilderText = if (Test-Path -LiteralPath $imageEntryPoint) { Get-Content -Raw -LiteralPath $imageEntryPoint } else { '' }
$imageIsoBuilderText = if (Test-Path -LiteralPath $imageIsoEntryPoint) { Get-Content -Raw -LiteralPath $imageIsoEntryPoint } else { '' }
if ($imageBuilderText -notmatch 'security-build-manifest' -or $imageBuilderText -notmatch 'security-center-contract\.tsv' -or $imageBuilderText -notmatch 'greyward-anaconda-logo\.png') {
    $errors.Add('The production image stager must bind Security Center RPMs to the canonical build manifest and file contract.')
}
if ($imageIsoBuilderText -notmatch 'security-build-manifest') {
    $errors.Add('The ISO entry point must require and forward the Security Center build manifest.')
}

if (Test-Path -LiteralPath $imageIsoEntryPoint) {
    $imageBuilder = Get-Content -Raw -LiteralPath $imageIsoEntryPoint
    if ($imageBuilder -notmatch 'mkksiso' -or $imageBuilder -notmatch 'xorriso' -or $imageBuilder -notmatch 'Fedora-E-' -or $imageBuilder -notmatch '--ks' -or $imageBuilder -notmatch '--add' -or $imageBuilder -notmatch '--updates' -or $imageBuilder -notmatch 'rpm2cpio' -or $imageBuilder -notmatch 'etc/anaconda/profile\.d/greyward\.conf' -or $imageBuilder -notmatch 'greyward-anaconda-logo\.png' -or $imageBuilder -notmatch 'inst\.profile=greyward') {
        $errors.Add('The ISO builder must keep Fedora Anaconda behavior intact while adding the Kickstart, staged production payload, and minimal GTK branding.')
    }
    if ($imageBuilder -notmatch 'Install GREYWARD OS' -or $imageBuilder -notmatch 'GREYWARD-INSTALLER-44') {
        $errors.Add('The installer ISO must expose the GREYWARD boot-menu label and volume.')
    }
    if ($imageBuilder -notmatch 'set default="0"' -or $imageBuilder -notmatch '--replace .set default="1". .set default="0".') {
        $errors.Add('The installer ISO must boot the normal installation entry instead of the media-check entry.')
    }
    if ($imageBuilder -match 'livemedia-creator|greyward-live\.ks|liveinst|greyward-live-installer') {
        $errors.Add('The canonical ISO builder must not boot or compose a live desktop.')
    }
}

if (Test-Path -LiteralPath $session10ReportPath) {
    $session10Report = Get-Content -Raw -LiteralPath $session10ReportPath
    if ($session10Report -notmatch '(?im)^Status:\s*\*\*(PASS|BLOCKED|HISTORICAL VALIDATION BACKLOG)\*\*') {
        $errors.Add('Session 10 report must explicitly declare PASS, BLOCKED, or HISTORICAL VALIDATION BACKLOG.')
    }
}

# Production/image inputs must not silently reintroduce mutable branch or
# development-package selectors. Comments and documentation state policy; the
# active input lines are what this check protects.
$mutableInputRoots = @(
    (Join-Path $repo 'environment\production'),
    (Join-Path $repo 'environment\flatpak'),
    (Join-Path $repo 'environment\image'),
    (Join-Path $repo 'security-center\packaging')
)
foreach ($mutableRoot in $mutableInputRoots) {
    if (-not (Test-Path -LiteralPath $mutableRoot)) { continue }
    Get-ChildItem -LiteralPath $mutableRoot -Recurse -File | Where-Object { $_.Extension -notin @('.md', '.png', '.svg') } | ForEach-Object {
        $lineNumber = 0
        foreach ($line in (Get-Content -LiteralPath $_.FullName)) {
            $lineNumber++
            if ($line.TrimStart().StartsWith('#')) { continue }
            $activeLine = ($line -split '#', 2)[0]
            if ($activeLine -match '(?i)\blatest\b|\bmaster\b|(?:^|[^A-Za-z0-9])[^\s/]+-git(?:[^A-Za-z0-9]|$)') {
                $errors.Add("Mutable build input selector in $($_.FullName):$lineNumber")
            }
        }
    }
}

if (Test-Path -LiteralPath $factoryPath) {
    $factory = Get-Content -Raw -LiteralPath $factoryPath
    if ($factory -match 'source\s*=\s*"\$\{path\.root\}/session"' -or $factory -match 'destination\s*=\s*"/tmp/greyward-production/session"') {
        $errors.Add('The disposable factory stages environment/session as a nested directory, but production provisioning expects its Labwc and DMS payloads at the stage root.')
    }
    foreach ($factoryPayload in @('/tmp/greyward-production/labwc', '/tmp/greyward-production/dankmaterialshell')) {
        if ($factory -notmatch [regex]::Escape($factoryPayload)) {
            $errors.Add("The disposable factory does not stage the production payload at $factoryPayload.")
        }
    }
    if ($factory -notmatch 'variable\s+"bootstrap_password"[\s\S]*?sensitive\s*=\s*true' -or
        $factory -notmatch 'ssh_password\s*=\s*var\.bootstrap_password' -or
        $factory -match 'ssh_password\s*=\s*"') {
        $errors.Add('The disposable factory must receive its bootstrap password as a sensitive runtime variable, never a repository literal.')
    }
}

if (-not (Test-Path -LiteralPath $rootLicensePath) -or
    (Get-Content -Raw -LiteralPath $rootLicensePath) -notmatch 'GNU GENERAL PUBLIC LICENSE\s+Version 3, 29 June 2007') {
    $errors.Add('The repository root must retain the complete GNU GPL version 3 license text.')
}
if (-not (Test-Path -LiteralPath $licensingPath) -or
    (Get-Content -Raw -LiteralPath $licensingPath) -notmatch 'GPL-3\.0-only material' -or
    (Get-Content -Raw -LiteralPath $licensingPath) -notmatch 'Reserved branding' -or
    (Get-Content -Raw -LiteralPath $licensingPath) -notmatch 'does not automatically receive permission') {
    $errors.Add('LICENSING.md must separate GPL code/documentation from reserved GREYWARD branding without restricting GPL forks.')
}
foreach ($gplMetadataPath in @($securityWorkspaceManifestPath, $securityCenterSpecPath, $securityContextSpecPath)) {
    if (-not (Test-Path -LiteralPath $gplMetadataPath) -or
        (Get-Content -Raw -LiteralPath $gplMetadataPath) -notmatch 'GPL-3\.0-only') {
        $errors.Add("GREYWARD source package metadata must declare GPL-3.0-only: $gplMetadataPath")
    }
}
if (Test-Path -LiteralPath $securityCenterSpecPath) {
    $securityCenterSpec = Get-Content -Raw -LiteralPath $securityCenterSpecPath
    foreach ($fileContextRuntime in @('python3-gobject-base', 'gtk4')) {
        if ($securityCenterSpec -notmatch "(?m)^Requires:\s+$([regex]::Escape($fileContextRuntime))\s*$") {
            $errors.Add("Security Center RPM must directly require the GTK file-context runtime: $fileContextRuntime")
        }
    }
}
foreach ($rpmSpecPath in @($securityCenterSpecPath, $securityContextSpecPath, $brandingSpecPath)) {
    if (-not (Test-Path -LiteralPath $rpmSpecPath)) { continue }
    $rpmSpec = Get-Content -Raw -LiteralPath $rpmSpecPath
    $headerVersion = [regex]::Match($rpmSpec, '(?m)^Version:\s+([^\s]+)').Groups[1].Value
    $headerRelease = [regex]::Match($rpmSpec, '(?m)^Release:\s+([0-9]+)').Groups[1].Value
    $latestChangelog = [regex]::Match($rpmSpec, '(?m)^\* .+ - ([^-\s]+)-([0-9]+)\s*$')
    if (-not $headerVersion -or -not $headerRelease -or -not $latestChangelog.Success -or
        $latestChangelog.Groups[1].Value -ne $headerVersion -or
        $latestChangelog.Groups[2].Value -ne $headerRelease) {
        $errors.Add("RPM header Version/Release must match the newest changelog entry: $rpmSpecPath")
    }
}
if (-not (Test-Path -LiteralPath $brandingSpecPath) -or
    (Get-Content -Raw -LiteralPath $brandingSpecPath) -notmatch '(?m)^License:\s+GPL-3\.0-only AND LicenseRef-GREYWARD-Branding\s*$') {
    $errors.Add('The branding package must declare its mixed GPL and reserved-branding contents.')
}
if (-not (Test-Path -LiteralPath $brandingProvenancePath) -or
    (Get-Content -Raw -LiteralPath $brandingProvenancePath) -notmatch 'repository origin, not authorship' -or
    (Get-Content -Raw -LiteralPath $brandingProvenancePath) -notmatch 'reserved branding' -or
    -not (Test-Path -LiteralPath $brandingLicensePath) -or
    (Get-Content -Raw -LiteralPath $brandingLicensePath) -notmatch 'does not apply to third-party') {
    $errors.Add('GREYWARD identity assets must retain provenance, reserved-branding scope, and a third-party exclusion.')
}
foreach ($fontReceipt in @(
    @{ Path = $interFontPath; Hash = '4989b125924991b90d05b2d16e0e388c48f7d5bb8b30539bbf9c755278d0ccaf'; License = $interLicensePath },
    @{ Path = $materialFontPath; Hash = 'd719f22fdee27e344b07e46e6fa8b50b1fce3cfcb03d4a84f03fafbf0812fc22'; License = $materialLicensePath }
)) {
    if (-not (Test-Path -LiteralPath $fontReceipt.Path) -or
        (Get-FileHash -LiteralPath $fontReceipt.Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $fontReceipt.Hash -or
        -not (Test-Path -LiteralPath $fontReceipt.License)) {
        $errors.Add("Bundled font receipt or license is missing/mismatched: $($fontReceipt.Path)")
    }
}
if (-not (Test-Path -LiteralPath $thirdPartyNoticesPath) -or
    (Get-Content -Raw -LiteralPath $thirdPartyNoticesPath) -notmatch 'db9d4955a8155d4c6f157027a7f3d61173546afe71eff439f74cf7b918b27f2b') {
    $errors.Add('Third-party notices must retain the exact DMS v1.5.3 QML archive receipt for bundled fonts.')
}
if (-not (Test-Path -LiteralPath $publicExportPath) -or
    (Get-Content -Raw -LiteralPath $publicExportPath) -notmatch 'rev-list --all --count' -or
    (Get-Content -Raw -LiteralPath $publicExportPath) -notmatch 'Destination must be outside') {
    $errors.Add('The clean-history public export guard is missing or incomplete.')
}

foreach ($developmentKickstartPath in $developmentKickstartPaths) {
    if (Test-Path -LiteralPath $developmentKickstartPath) {
        $developmentKickstart = Get-Content -Raw -LiteralPath $developmentKickstartPath
        if ($developmentKickstart -notmatch '__BOOTSTRAP_PASSWORD__' -or
            $developmentKickstart -match '(?i)--(?:password|passphrase)=stendev') {
            $errors.Add("Development Kickstart must use the runtime bootstrap-password placeholder without a fixed credential: $developmentKickstartPath")
        }
    }
}

if (Test-Path -LiteralPath $factoryCreatePath) {
    $factoryCreate = Get-Content -Raw -LiteralPath $factoryCreatePath
    if ($factoryCreate -notmatch 'PKR_VAR_bootstrap_password' -or
        $factoryCreate -notmatch "Replace\('__BOOTSTRAP_PASSWORD__'") {
        $errors.Add('The factory entry point must pass the prompted bootstrap password to both Packer and the ignored generated Kickstart.')
    }
}

if (Test-Path -LiteralPath $imageEntryPoint) {
    $imageBuild = Get-Content -Raw -LiteralPath $imageEntryPoint
    foreach ($requiredProductionSessionFile in @(
        'greyward-display-power',
        'greyward-dms-session-migrate',
        'greyward-dms.service',
        'greyward-labwc.desktop',
        'greyward-session-idle.service',
        'greyward-session-lock'
    )) {
        if ($imageBuild -notmatch [regex]::Escape($requiredProductionSessionFile)) {
            $errors.Add("Production image staging does not include required session payload: $requiredProductionSessionFile")
        }
    }
}

if (Test-Path -LiteralPath $developmentOverlayPath) {
    $developmentOverlay = Get-Content -Raw -LiteralPath $developmentOverlayPath
    if ($developmentOverlay -match '/tmp/greyward-production/session/labwc' -or
        $developmentOverlay -match '/tmp/greyward-production/session/dankmaterialshell') {
        $errors.Add('The development overlay must consume the factory stage root for Labwc and DMS payloads.')
    }
    foreach ($developmentPayload in @('/tmp/greyward-production/labwc', '/tmp/greyward-production/dankmaterialshell')) {
        if ($developmentOverlay -notmatch [regex]::Escape($developmentPayload)) {
            $errors.Add("The development overlay does not consume the staged payload at $developmentPayload.")
        }
    }
}

$productionProvision = Get-Content -Raw -LiteralPath $productionProvisionPath
if ($productionProvision -notmatch 'systemctl --global enable greyward-security-context-user\.service' -or
    $productionProvision -notmatch 'systemctl --global enable greyward-update-center\.service') {
    $errors.Add('Production provisioning must globally enable the user Security Context and Update Center services after first setup.')
}

if (Test-Path -LiteralPath $dmsSettingsPath) {
    $dmsSettings = Get-Content -Raw -LiteralPath $dmsSettingsPath
    if ($dmsSettings -match '(?i)/home/stendev|stendev') {
        $errors.Add('Production DMS settings contain a developer-home reference.')
    }
    foreach ($requiredDmsPath in @('/usr/share/greyward/dms/greyward-obsidian.json', '/usr/share/greyward/dms/greyward-symbol.svg', '/usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg')) {
        if ($dmsSettings -notmatch [regex]::Escape($requiredDmsPath)) {
            $errors.Add("Production DMS settings do not use the stable system asset path: $requiredDmsPath")
        }
    }
    $dmsSettingsJson = $dmsSettings | ConvertFrom-Json
    if ($dmsSettingsJson.greeterWallpaperFillMode -ne 'Fill') {
        $errors.Add('DMS settings must keep the GREYWARD greetd background in Fill mode.')
    }
    if ($dmsSettingsJson.widgetBackgroundCustomColor -ne '#D8E0E7' -or [double]$dmsSettingsJson.widgetBackgroundCustomStrength -lt 0.2 -or $dmsSettingsJson.controlCenterTileColorMode -ne 'primary' -or $dmsSettingsJson.buttonColorMode -ne 'primary') {
        $errors.Add('DMS must retain the light-grey translucent widget material for the frosted desktop treatment.')
    }
    $taskbar = @($dmsSettingsJson.barConfigs) | Where-Object { $_.id -eq 'default' } | Select-Object -First 1
    $leftWidgets = @($taskbar.leftWidgets)
    $leftWidgetIds = @($leftWidgets | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.id } })
    $rightWidgetIds = @($taskbar.rightWidgets | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.id } })
    $appsDock = @($leftWidgets | Where-Object { $_ -isnot [string] -and $_.id -eq 'appsDock' } | Select-Object -First 1)
    if ($null -eq $taskbar -or [double]$taskbar.spacing -ne 7 -or [double]$taskbar.iconScale -ne 1.0 -or [double]$appsDock.appsDockIconSizePercentage -lt 120 -or [double]$dmsSettingsJson.launcherLogoSizeOffset -gt 36 -or $leftWidgetIds.Count -ne 5 -or $leftWidgetIds[1] -ne 'spacer' -or $leftWidgetIds[3] -ne 'spacer' -or $rightWidgetIds[0] -ne 'greywardNetworkTraffic' -or $rightWidgetIds[1] -ne 'greywardPublicIp') {
        $errors.Add('DMS taskbar geometry must retain clear widget separation, readable application icons, and a restrained launcher mark.')
    }
    if ($leftWidgetIds -contains 'runningApps' -or $appsDock.Count -ne 1) {
        $errors.Add('The canonical GREYWARD taskbar must use DMS AppsDock so pinned and running applications share one model.')
    }
}

if (Test-Path -LiteralPath $dmsServicePath) {
    $dmsService = Get-Content -Raw -LiteralPath $dmsServicePath
    if ($dmsService -notmatch '(?m)^Environment=HTTP_PROXY=http://127\.0\.0\.1:9\s*$' -or
        $dmsService -notmatch '(?m)^Environment=http_proxy=http://127\.0\.0\.1:9\s*$' -or
        $dmsService -notmatch 'NO_PROXY=localhost,127\.0\.0\.1,::1') {
        $errors.Add('The DMS service must contain upstream cleartext HTTP geolocation through a closed loopback proxy while preserving local HTTP.')
    }
    if ($dmsService -match '(?m)^Environment=(?:HTTPS_PROXY|https_proxy)=') {
        $errors.Add('The DMS cleartext containment must not block the reviewed HTTPS Network Identity providers.')
    }
}

if (Test-Path -LiteralPath $dmsSessionMigratePath) {
    $dmsSessionMigrate = Get-Content -Raw -LiteralPath $dmsSessionMigratePath
    if ($dmsSessionMigrate -notmatch 'has\("barPinnedApps"\)' -or $dmsSessionMigrate -notmatch 'brave-browser' -or $dmsSessionMigrate -notmatch 'tabby' -or $dmsSessionMigrate -notmatch 'greyward-terminal' -or $dmsSessionMigrate -notmatch 'com\.raggesilver\.BlackBox' -or $dmsSessionMigrate -notmatch 'org\.gnome\.Nautilus' -or $dmsSessionMigrate -notmatch 'exit 0') {
        $errors.Add('DMS default pin migration must preserve an established user barPinnedApps list.')
    }
}

if (Test-Path -LiteralPath $dmsAppsDockLabelsPatchPath) {
    $dmsAppsDockLabelsPatch = Get-Content -Raw -LiteralPath $dmsAppsDockLabelsPatchPath
    if ($dmsAppsDockLabelsPatch -notmatch 'I18n\.tr\("Pin to taskbar"\)' -or $dmsAppsDockLabelsPatch -notmatch 'I18n\.tr\("Unpin from taskbar"\)') {
        $errors.Add('The GREYWARD AppsDock context-menu patch must use taskbar terminology for pinning.')
    }
}

if (Test-Path -LiteralPath $dmsAppsDockToggleMinimizePatchPath) {
    $dmsAppsDockToggleMinimizePatch = Get-Content -Raw -LiteralPath $dmsAppsDockToggleMinimizePatchPath
    if ($dmsAppsDockToggleMinimizePatch -notmatch 'toplevel\.minimized = true' -or $dmsAppsDockToggleMinimizePatch -notmatch 'toplevel\.activate\(\)') {
        $errors.Add('The GREYWARD AppsDock patch must restore unfocused windows and minimize the focused window.')
    }
}

if (Test-Path -LiteralPath $dmsAppsDockSpacingPatchPath) {
    $dmsAppsDockSpacingPatch = Get-Content -Raw -LiteralPath $dmsAppsDockSpacingPatchPath
    if ($dmsAppsDockSpacingPatch -notmatch 'spacing: Theme\.spacingS' -or $dmsAppsDockSpacingPatch -notmatch 'spacingXS') {
        $errors.Add('The GREYWARD AppsDock spacing patch must increase the native item gap from spacingXS to spacingS.')
    }
}

if (Test-Path -LiteralPath $networkTrafficPluginManifestPath) {
    $networkTrafficManifest = Get-Content -Raw -LiteralPath $networkTrafficPluginManifestPath | ConvertFrom-Json
    if ($networkTrafficManifest.id -ne 'greywardNetworkTraffic' -or $networkTrafficManifest.component -ne './NetworkTrafficWidget.qml' -or $networkTrafficManifest.type -ne 'widget') {
        $errors.Add('The GREYWARD Network Traffic plugin manifest must identify the canonical widget component.')
    }
}

if ((Test-Path -LiteralPath $publicIpPluginManifestPath) -and (Test-Path -LiteralPath $publicIpPluginWidgetPath)) {
    $publicIpManifest = Get-Content -Raw -LiteralPath $publicIpPluginManifestPath | ConvertFrom-Json
    $publicIpWidget = Get-Content -Raw -LiteralPath $publicIpPluginWidgetPath
    if ($publicIpManifest.id -ne 'greywardPublicIp' -or $publicIpManifest.component -ne './PublicIpWidget.qml' -or $publicIpManifest.type -ne 'widget') {
        $errors.Add('The GREYWARD Network Identity plugin manifest must identify the canonical widget component.')
    }
    if ($publicIpWidget -notmatch 'property bool stateInitialized: false' -or
        $publicIpWidget -notmatch 'property bool publicLookupEnabled: false' -or
        $publicIpWidget -notmatch 'loadPluginState\(\s*root\.pluginId, "publicLookupEnabled", true\)' -or
        $publicIpWidget -notmatch 'savePluginState\(root\.pluginId, "publicLookupEnabled", enabled\)' -or
        $publicIpWidget -notmatch 'removePluginStateKey\(root\.pluginId, "publicIp"\)' -or
        $publicIpWidget -notmatch 'DankToggle' -or
        $publicIpWidget -notmatch 'text: qsTr\("Public IP check"\)') {
        $errors.Add('The public-IP lookup must use a fail-closed, persistent, user-visible pill switch.')
    }
    if ($publicIpWidget -notmatch 'function fetchPublicIdentity\(\)\s*\{\s*if \(!root\.stateInitialized \|\| !root\.publicLookupEnabled \|\| root\.requestInFlight\)' -or
        $publicIpWidget -notmatch 'function fetchFallback\(generation, primaryStatus\)\s*\{\s*if \(generation !== root\.requestGeneration \|\| !root\.publicLookupEnabled\)' -or
        $publicIpWidget -notmatch 'running: root\.stateInitialized && root\.publicLookupEnabled' -or
        $publicIpWidget -notmatch 'generation !== root\.requestGeneration \|\| !root\.publicLookupEnabled') {
        $errors.Add('Every automatic public-IP request path must honor initialization, the saved opt-out, and canceled request generations.')
    }
    if ($publicIpWidget -notmatch '"--proto", "=https", "--tlsv1\.2"' -or
        $publicIpWidget -match 'http://' -or
        $publicIpWidget -notmatch [regex]::Escape('https://ipapi.co/json/') -or
        $publicIpWidget -notmatch [regex]::Escape('https://ipwho.is/')) {
        $errors.Add('Public-IP providers must remain HTTPS-only and match the reviewed endpoints.')
    }
    if ($publicIpWidget -notmatch 'name: "public"' -or
        $publicIpWidget -notmatch 'name: "lan"' -or
        $publicIpWidget -match 'qsTr\("PUBLIC %1"\)|qsTr\("LOCAL %1"\)' -or
        $publicIpWidget -notmatch '"ip", "-json", "route", "get", "192\.0\.2\.1"') {
        $errors.Add('The Network Identity pill must show icon-labeled public and local addresses side by side.')
    }
    if ($publicIpWidget -match 'staleCacheLifetimeMs|cacheIsUsable|usingLocalFallback' -or
        $publicIpWidget -match 'loadPluginState\(root\.pluginId, "publicIp"' -or
        $publicIpWidget -match 'savePluginState\(root\.pluginId, "publicIp"') {
        $errors.Add('The Network Identity pill must not restore or substitute stale public-IP state.')
    }
}

if (Test-Path -LiteralPath $dmsPluginSettingsPath) {
    $dmsPluginSettings = Get-Content -Raw -LiteralPath $dmsPluginSettingsPath | ConvertFrom-Json
    if ($null -eq $dmsPluginSettings.greywardNetworkTraffic -or $dmsPluginSettings.greywardNetworkTraffic.enabled -ne $true) {
        $errors.Add('The GREYWARD Network Traffic plugin must be enabled in the canonical DMS plugin settings.')
    }
    if ($null -eq $dmsPluginSettings.greywardPublicIp -or $dmsPluginSettings.greywardPublicIp.enabled -ne $true) {
        $errors.Add('The GREYWARD Network Identity plugin must be enabled in the canonical DMS plugin settings.')
    }
}

if (Test-Path -LiteralPath $dmsThemePath) {
    $dmsTheme = Get-Content -Raw -LiteralPath $dmsThemePath | ConvertFrom-Json
    if ($dmsTheme.dark.background -ne '#000000') {
        $errors.Add('The canonical DMS dark theme must retain an AMOLED-black background.')
    }
}

if (Test-Path -LiteralPath $labwcThemePath) {
    $labwcTheme = Get-Content -Raw -LiteralPath $labwcThemePath
    if ($labwcTheme -notmatch '(?m)^window\.active\.title\.bg\.color:\s*#[0-9a-fA-F]{8}\s*$') {
        $errors.Add('The Labwc titlebar must retain its translucent frosted material color.')
    }
}

$labwcRcPath = Join-Path $repo 'environment\session\labwc\rc.xml'
if (Test-Path -LiteralPath $labwcRcPath) {
    $labwcRc = Get-Content -Raw -LiteralPath $labwcRcPath
    if ($labwcRc -notmatch 'identifier="com\.brave\.Browser" serverDecoration="yes"' -or $labwcRc -notmatch 'identifier="brave" serverDecoration="yes"') {
        $errors.Add('Labwc must force server-side decorations for Brave so its window controls survive updates.')
    }
    if ($labwcRc -notmatch '<maximizedDecoration>titlebar</maximizedDecoration>') {
        $errors.Add('Labwc must retain the maximized titlebar so Brave window controls remain visible.')
    }
}

if (Test-Path -LiteralPath $securityCenterStylesPath) {
    $securityCenterStyles = Get-Content -Raw -LiteralPath $securityCenterStylesPath
    if ($securityCenterStyles -notmatch '--frost:\s*rgba\(' -or $securityCenterStyles -notmatch 'backdrop-filter:\s*blur\(') {
        $errors.Add('Security Center must retain the frosted material tokens and blur enhancement.')
    }
}

if ((Test-Path -LiteralPath $developmentPackagesPath) -and (Test-Path -LiteralPath $productionPackagesPath)) {
    $developmentPackages = Get-Content -LiteralPath $developmentPackagesPath | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }
    $productionPackages = Get-Content -LiteralPath $productionPackagesPath | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }
    $securityCenterBuildOnly = @('gcc', 'gcc-c++', 'make', 'cmake', 'ninja-build', 'rust', 'cargo', 'rustfmt', 'clippy', 'rpm-build', 'desktop-file-utils', 'webkit2gtk4.1-devel', 'openssl-devel', 'libappindicator-gtk3-devel', 'librsvg2-devel', 'libxdo-devel')
    foreach ($package in $securityCenterBuildOnly) {
        if ($package -notin $developmentPackages) {
            $errors.Add("Development package list is missing Security Center build prerequisite: $package")
        }
        if ($package -in $productionPackages) {
            $errors.Add("Production package list must not include Security Center build-only package: $package")
        }
    }
}

foreach ($productionPath in @(
    (Join-Path $repo 'environment\production'),
    (Join-Path $repo 'environment\session')
)) {
    if (Test-Path -LiteralPath $productionPath) {
        $productionText = if ((Get-Item -LiteralPath $productionPath).PSIsContainer) {
            # The installed-root acceptance checker must name prohibited
            # development services and accounts in order to reject them; it is
            # not an image input that enables those services.
            (Get-ChildItem -LiteralPath $productionPath -Recurse -File | Where-Object { $_.Extension -notin @('.md', '.png') -and $_.Name -ne 'production-acceptance.sh' } | Get-Content -Raw) -join "`n"
        } else { Get-Content -Raw -LiteralPath $productionPath }
        foreach ($developerMarker in @('NOPASSWD:', 'hypervkvpd', 'ssh-keygen', '/home/stendev')) {
            if ($productionText -match [regex]::Escape($developerMarker)) {
                $errors.Add("Production input contains developer-only marker '$developerMarker': $productionPath")
            }
        }
    }
}
if ((Test-Path -LiteralPath $defaultAppsPath) -and (Test-Path -LiteralPath $mimeAppsPath) -and (Test-Path -LiteralPath $softwareWrapperPath) -and (Test-Path -LiteralPath $productionProvisionPath)) {
    $defaultEntries = Get-Content -LiteralPath $defaultAppsPath | Where-Object {
        $line = $_.Trim()
        $line -and -not $line.StartsWith('#')
    }
    $expectedDefaults = @{
        'io.github.hkdb.Aerion' = 'io.github.hkdb.Aerion.desktop'
        'com.collaboraoffice.Office' = 'com.collaboraoffice.Office.desktop'
        'org.kde.haruna' = 'org.kde.haruna.desktop'
        'com.brave.Browser' = 'com.brave.Browser.desktop'
        'com.protonvpn.www' = 'com.protonvpn.www.desktop'
    }
    if ($defaultEntries.Count -ne $expectedDefaults.Count) {
        $errors.Add("Expected exactly $($expectedDefaults.Count) production Flatpak defaults, found $($defaultEntries.Count).")
    }
    foreach ($entry in $defaultEntries) {
        $parts = $entry.Split('|') | ForEach-Object { $_.Trim() }
        if ($parts.Count -ne 2 -or -not $expectedDefaults.ContainsKey($parts[0]) -or $expectedDefaults[$parts[0]] -ne $parts[1]) {
            $errors.Add("Invalid or unexpected production Flatpak default: '$entry'.")
        }
    }

    $mimeApps = Get-Content -Raw -LiteralPath $mimeAppsPath
    $expectedMimeDefaults = @{
        'x-scheme-handler/mailto' = 'io.github.hkdb.Aerion.desktop'
        'x-scheme-handler/http' = 'com.brave.Browser.desktop'
        'x-scheme-handler/https' = 'com.brave.Browser.desktop'
        'text/plain' = 'org.gnome.TextEditor.desktop'
        'application/pdf' = 'org.gnome.Papers.desktop'
        'image/png' = 'org.gnome.Loupe.desktop'
        'image/jpeg' = 'org.gnome.Loupe.desktop'
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' = 'com.collaboraoffice.Office.desktop'
        'video/mp4' = 'org.kde.haruna.desktop'
    }
    foreach ($mime in $expectedMimeDefaults.Keys) {
        $pattern = '(?m)^' + [regex]::Escape($mime) + '=' + [regex]::Escape($expectedMimeDefaults[$mime]) + ';'
        if ($mimeApps -notmatch $pattern) {
            $errors.Add("Missing expected MIME default for '$mime'.")
        }
    }

    $provision = Get-Content -Raw -LiteralPath $productionProvisionPath
    if ($provision -notmatch 'default-applications\.list' -or $provision -notmatch 'flatpak install --system --noninteractive flathub') {
        $errors.Add('Production provisioning does not consume and install the canonical Flatpak default list.')
    }
    if ($provision -notmatch '/usr/share/greyward/dms') {
        $errors.Add('Production provisioning does not install the stable system DMS asset directory.')
    }

    $softwareWrapper = Get-Content -Raw -LiteralPath $softwareWrapperPath
    if ($softwareWrapper -match '\.var/app/io\.github\.kolunmi\.Bazaar' -or $softwareWrapper -notmatch '\$config_root/greyward-privacy\.yaml') {
        $errors.Add('GREYWARD Software wrapper does not pass the sandbox-visible curated configuration path.')
    }
}

if (-not (Test-Path -LiteralPath $wallpaperDirectory -PathType Container)) {
    $errors.Add("Production wallpaper collection is missing: $wallpaperDirectory")
} else {
    $wallpapers = @(Get-ChildItem -LiteralPath $wallpaperDirectory -File -Filter 'greyward-wallpaper-*.jpg')
    if ($wallpapers.Count -ne 2) { $errors.Add("Expected exactly 2 production wallpapers, found $($wallpapers.Count).") }
    foreach ($wallpaper in $wallpapers) {
        if ($wallpaper.Length -le 0) { $errors.Add("Production wallpaper is empty: $($wallpaper.FullName)") }
    }
    $provision = Get-Content -Raw -LiteralPath $productionProvisionPath
    foreach ($requiredWallpaperText in @('branding/wallpaper', '/usr/share/backgrounds/greyward', 'greyward-wallpaper-black-art-4k.jpg', 'greyward-wallpaper-2109-4k.jpg', 'greeter_wallpaper_override.jpg', 'greyward-sync-greeter-wallpaper', '/usr/local/libexec/greyward-sync-greeter-wallpaper', 'ExecStartPre=/usr/local/libexec/greyward-sync-greeter-wallpaper')) {
        if ($provision -notmatch [regex]::Escape($requiredWallpaperText)) {
            $errors.Add("Production provisioning does not install the wallpaper collection: $requiredWallpaperText")
        }
    }
    foreach ($autostartPath in @(
        (Join-Path $repo 'environment\production\labwc-autostart'),
        (Join-Path $repo 'environment\session\labwc\autostart')
    )) {
        $autostart = Get-Content -Raw -LiteralPath $autostartPath
        if ($autostart -notmatch 'wallpaper set /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k\.jpg') {
            $errors.Add("Labwc autostart does not apply the real shared wallpaper path: $autostartPath")
        }
        if ($autostart -match 'wallpaper set .*DankMaterialShell/greyward-wallpaper\.png') {
            $errors.Add("Labwc autostart still applies the compatibility symlink instead of the shared wallpaper path: $autostartPath")
        }
    }
}
if (Test-Path -LiteralPath $retiredGreeterWallpaperPath) {
    $errors.Add("The retired greeter-only wallpaper must not return: $retiredGreeterWallpaperPath")
}

$plymouthScriptPath = Join-Path $repo 'packaging\greyward-branding\SOURCES\greyward.script'
$plymouthSpecPath = Join-Path $repo 'packaging\greyward-branding\SPECS\greyward-branding.spec'
$plymouthUpdateStatusPath = Join-Path $repo 'packaging\greyward-branding\SOURCES\greyward-update-status.service'
$brandingManifestPath = Join-Path $repo 'branding\manifest.json'
if ((Test-Path -LiteralPath $plymouthScriptPath) -and (Test-Path -LiteralPath $plymouthSpecPath) -and (Test-Path -LiteralPath $plymouthUpdateStatusPath) -and (Test-Path -LiteralPath $brandingManifestPath)) {
    $plymouthScript = Get-Content -Raw -LiteralPath $plymouthScriptPath
    $plymouthSpec = Get-Content -Raw -LiteralPath $plymouthSpecPath
    $plymouthUpdateStatus = Get-Content -Raw -LiteralPath $plymouthUpdateStatusPath
    $brandingManifest = Get-Content -Raw -LiteralPath $brandingManifestPath
    foreach ($required in @('Plymouth.SetDisplayPasswordFunction', 'Plymouth.SetDisplayNormalFunction', 'Plymouth.SetRootMountedFunction', 'Plymouth.SetSystemUpdateFunction', 'Installing system updates', 'Keep this computer powered on', '% complete', 'Preparing update...', 'VERIFYING KEY', 'SECURE STORAGE UNLOCKED', 'Passphrase incorrect', 'greyward-symbol-256.png')) {
        if ($plymouthScript -notmatch [regex]::Escape($required)) { $errors.Add("Plymouth unlock theme is missing required behavior: $required") }
    }
    if ($plymouthScript -match 'Plymouth\.SetKeyboardInputFunction') { $errors.Add('Plymouth unlock theme must not receive raw keyboard input.') }
    if ($plymouthScript -match 'greyward-wordmark') { $errors.Add('Plymouth unlock theme must not use the GREYWARD wordmark.') }
    if ($plymouthSpec -notmatch 'Requires:\s+plymouth-plugin-script' -or $plymouthSpec -notmatch 'Requires:\s+plymouth-plugin-label' -or $plymouthSpec -match 'Source\d+:\s+greyward-wordmark') { $errors.Add('Plymouth RPM must require script and label plugins and contain no wordmark asset.') }
    if ($plymouthUpdateStatus -notmatch '(?m)^ConditionPathExists=/system-update\s*$' -or
        $plymouthUpdateStatus -notmatch '(?m)^ExecStart=/usr/bin/plymouth change-mode --updates\s*$' -or
        $plymouthUpdateStatus -notmatch '(?m)^ExecStart=/usr/bin/plymouth display-message "--text=GREYWARD system update in progress"\s*$' -or
        $plymouthUpdateStatus -notmatch 'Before=.*dnf5-offline-transaction\.service') {
        $errors.Add('Plymouth update status unit must enter update mode and display feedback before DNF5 starts.')
    }
    if ($plymouthUpdateStatus -match '(?m)^ExecStart=/usr/bin/plymouth message(?:\s|$)') { $errors.Add('Plymouth update status unit must not use the obsolete message command.') }
    if ($brandingManifest -match 'plymouth-[^\r\n]+wordmark') { $errors.Add('Plymouth manifest consumers must derive only from the canonical symbol SVG.') }
    if ($productionProvision -notmatch 'greyward-branding-' -or $productionProvision -notmatch 'plymouth-set-default-theme greyward' -or $productionProvision -notmatch 'dracut --regenerate-all --force') {
        $errors.Add('Production provisioning must install, select, and include the GREYWARD Plymouth theme.')
    }
    $imageBuilder = Get-Content -Raw -LiteralPath $imageEntryPoint
    if ($imageBuilder -notmatch '--branding-rpm' -or $imageBuilder -notmatch 'greyward-branding') { $errors.Add('Image staging must require a GREYWARD branding RPM.') }
}
if ($errors.Count) { @{ok=$false; errors=$errors} | ConvertTo-Json -Depth 5 -Compress; exit 1 }
@{ok=$true; message='Static validation passed.'} | ConvertTo-Json -Compress
