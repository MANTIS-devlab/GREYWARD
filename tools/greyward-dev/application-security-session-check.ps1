# Fixed separate-account regression check. No VM lifecycle or active-session control.
. (Join-Path $PSScriptRoot 'common.ps1')

function Read-ProbeDesktop {
    $command = @'
python3 -I -c 'import json,subprocess; print(json.dumps({"enforcing":subprocess.check_output(["getenforce"],text=True).strip(),"desktop_pid":int(subprocess.check_output(["systemctl","--user","show","greyward-dms.service","-p","MainPID","--value"],text=True))}))'
'@
    return (Invoke-GreywardSsh -Command $command | ConvertFrom-Json)
}

function Invoke-ProbeAccount {
    param([Parameter(Mandatory)][string]$Command)
    & ssh -F $script:SshConfigPath -o BatchMode=yes -o ConnectTimeout=10 -l greyward-guard-probe $script:SshAlias $Command
    if ($LASTEXITCODE -ne 0) { throw "Separate-account command failed ($LASTEXITCODE)." }
}

$before = Read-ProbeDesktop
if ($before.enforcing -ne 'Enforcing' -or $before.desktop_pid -le 1) { throw 'Enforcing and an active recovery desktop are required.' }
Invoke-GreywardSsh -Command 'test "$(id -u)" = 1001; test "$(id -u greyward-guard-probe)" = 1002; test "$(id -G greyward-guard-probe)" = 1002; test -d /var/tmp/greyward-application-security-probe'

foreach ($filename in @('application-security-feasibility.sh', 'application-security-probe.py',
        'application-security-routes.sh', 'application-security-headless.sh', 'application-security-portal-probe.py')) {
    $source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $filename)).Replace("`r`n", "`n")
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
    Invoke-GreywardSsh -Command "printf '%s' '$encoded' | base64 -d > /var/tmp/greyward-application-security-probe/$filename"
}
$source = [IO.File]::ReadAllText((Join-Path $script:RepoRoot 'spikes/application-security/selinux/greyward_guard_probe.te')).Replace("`r`n", "`n")
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
Invoke-GreywardSsh -Command "printf '%s' '$encoded' | base64 -d > /var/tmp/greyward-application-security-probe/greyward_guard_probe.te"

try {
    Invoke-GreywardSsh -Command 'sudo -n bash /var/tmp/greyward-application-security-probe/application-security-feasibility.sh setup /var/tmp/greyward-application-security-probe'
    Invoke-ProbeAccount -Command 'bash /usr/local/libexec/greyward-application-security-routes.sh'
    Invoke-GreywardSsh -Command 'sudo -n bash /var/tmp/greyward-application-security-probe/application-security-feasibility.sh desktop /var/tmp/greyward-application-security-probe'
    $headless = @'
set -e
export WLR_BACKENDS=headless WLR_HEADLESS_OUTPUTS=1 WLR_RENDERER=pixman QT_QUICK_BACKEND=software XDG_SEAT=greyward-headless-probe
export XDG_SESSION_ID=$(loginctl show-session self -p Id --value)
test -n "$XDG_SESSION_ID"
timeout 50s uwsm start -F -e -D GREYWARD:labwc -- /usr/bin/labwc -s /usr/local/libexec/greyward-application-security-headless.sh
'@
    Invoke-ProbeAccount -Command $headless.Replace("`r`n", "`n")
    $verify = @'
sudo -n python3 -I -c 'import json; from pathlib import Path; p=Path("/home/greyward-guard-probe"); portal=json.loads((p/"portal-probe-result.json").read_text()); shell=json.loads((p/"session-shell-result.json").read_text()); print(json.dumps({"portal_passed":portal.get("passed"),"portal_checks":len(portal.get("results",[])),"flatpak_results":[r for r in portal["results"] if r["test"].startswith("flatpak_")],"shell":shell})); raise SystemExit(0 if portal.get("passed") is True and shell.get("state")=="READY" else 1)'
'@
    Invoke-GreywardSsh -Command $verify
} finally {
    Invoke-GreywardSsh -Command 'sudo -n bash /var/tmp/greyward-application-security-probe/application-security-feasibility.sh rollback /var/tmp/greyward-application-security-probe'
    $after = Read-ProbeDesktop
    if ($after.enforcing -ne 'Enforcing' -or $after.desktop_pid -ne $before.desktop_pid) { throw 'Recovery desktop/enforcement regression.' }
}
