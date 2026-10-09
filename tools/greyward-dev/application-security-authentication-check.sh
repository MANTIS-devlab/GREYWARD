#!/usr/bin/bash
# Focused, reversible kernel validation on the owned UID-1002 account only.
# Never an enrollment, package-install or production-authentication command.
set -euo pipefail
test "$(id -u)" = 0
base=/var/tmp/greyward-application-security-build/authentication-check
runtime=/run/greyward-authentication-boundary
reader=/usr/local/libexec/greyward-authentication-boundary-probe.py
auth_python=/usr/local/libexec/greyward-authentication-boundary-python
authorization_policy=/usr/share/polkit-1/actions/systems.mantis.greyward.ApplicationSecurity1.policy
test "$(cat /var/lib/greyward-development/application-security/account.uid)" = 1002
test "$(getent passwd greyward-guard-probe | cut -d: -f3-6)" = '1002:1002::/home/greyward-guard-probe' || {
  # GECOS may be descriptive. UID/GID/home must still match the owned receipt.
  test "$(getent passwd greyward-guard-probe | awk -F: '{print $3":"$4":"$6}')" = '1002:1002:/home/greyward-guard-probe'
}
if pgrep -u 1002 >/dev/null; then echo 'Separate account is busy' >&2; exit 1; fi
test ! -e "$runtime"
test ! -e "$reader"
test ! -e "$auth_python"
test ! -e "$authorization_policy"
modules=(greyward_guard_probe greyward_application_auth greyward_application_grants greyward_authentication_boundary_probe greyward_application_auth_deny)
profile_module=greyward_authentication_profile_access
if semodule -l | awk '{print $1}' | grep -Fxq "$profile_module"; then exit 1; fi
profile_installed=0
for module in "${modules[@]}"; do
  if semodule -l | awk '{print $1}' | grep -Fxq "$module"; then echo 'Owned test module already exists' >&2; exit 1; fi
done
installed=0
fixture=''
cleanup() {
  systemctl stop greyward-application-security-lock-probe.service 2>/dev/null || true
  if test -n "$fixture"; then
    # PAM can move descendants to a logind scope outside the transient unit.
    # Admission required no UID-1002 processes, so these are owned test work.
    loginctl terminate-user greyward-guard-probe
    # logind has no signal permission into the protected subject. The root
    # coordinator terminates only this initially empty, owned test UID using
    # held pidfds before uninstalling policy or removing its private input.
    /usr/bin/python3 -I - <<'PY'
import os, pathlib, signal
for path in pathlib.Path('/proc').iterdir():
    if not path.name.isdecimal():
        continue
    try:
        handle = os.pidfd_open(int(path.name))
    except ProcessLookupError:
        continue
    try:
        if path.stat().st_uid == 1002:
            signal.pidfd_send_signal(handle, signal.SIGKILL)
    except (FileNotFoundError, ProcessLookupError):
        pass
    finally:
        os.close(handle)
PY
    for attempt in {1..30}; do
      if ! pgrep -u 1002 >/dev/null; then break; fi
      sleep 0.1
    done
    if pgrep -u 1002 >/dev/null; then
      echo 'Private account workloads remain; retain policy for recovery' >&2
      python3 -I /usr/local/libexec/greyward-application-security-authorization.py --restore
      return 1
    fi
  fi
  if test -n "$fixture"; then
    python3 -I /usr/local/libexec/greyward-application-security-authorization.py --restore
    # Startup diagnostics only: never retain shell/PAM logs or authentication
    # data. Root-private copies avoid orphan labels after module removal.
    for log in dbus-daemon.log labwc.log; do
      if test -f "$fixture/$log"; then
        install -m0600 "$fixture/$log" "$base/$log"
        restorecon "$base/$log"
      fi
    done
    test "${fixture%/*}" = /var/lib/greyward-development/application-security
    case "$fixture" in /var/lib/greyward-development/application-security/lock-probe.*) rm -rf -- "$fixture" ;; *) exit 1;; esac
  fi
  systemctl stop greyward-auth-boundary-host.service greyward-auth-boundary-reader.service 2>/dev/null || true
  if test "$profile_installed" = 1; then semodule -r "$profile_module"; fi
  if test "$installed" = 1; then semodule -r "${modules[@]}"; fi
  rm -f -- "$reader"
  rm -f -- "$auth_python"
  rm -f -- "$authorization_policy"
  # Exact root-created scratch directory, not a discovered/caller-supplied path.
  if test -d "$runtime" && test "$(stat -c %u "$runtime")" = 0; then rm -rf -- "$runtime"; fi
}
trap cleanup EXIT
cd "$base"
for module in greyward_guard_probe greyward_application_auth greyward_application_grants greyward_authentication_boundary_probe; do
  make -f /usr/share/selinux/devel/Makefile "$module.pp" >/dev/null
done
semodule -i greyward_guard_probe.pp -i greyward_application_auth.pp -i greyward_application_grants.pp -i greyward_authentication_boundary_probe.pp -i greyward_application_auth_deny.cil
installed=1
install -d -m0755 "$runtime"
chcon -t greyward_as_auth_runtime_t "$runtime"
install -m0555 /usr/bin/python3.14 "$runtime/auth-python"
chcon -t greyward_as_auth_exec_t "$runtime/auth-python"
install -m0444 application-security-authentication-boundary.py "$runtime/probe.py"
chcon -t greyward_as_auth_runtime_t "$runtime/probe.py"
install -m0444 application-security-authentication-boundary.py "$reader"
restorecon "$reader"
/usr/bin/python3 -I - "$runtime" "$reader" <<'PY'
import json, os, select, subprocess, sys
from pathlib import Path
runtime, reader = sys.argv[1:]
props = ["-p", "User=1002", "-p", "Group=1002", "-p", "RuntimeMaxSec=25",
         "-p", "TimeoutStopSec=2", "-p", "PrivateNetwork=yes", "-p", "PrivateTmp=yes",
         "-p", "ProtectSystem=strict", "-p", "ProtectHome=yes", "-p", "CapabilityBoundingSet=",
         "-p", "MemoryMax=128M", "-p", "TasksMax=16"]
host = subprocess.Popen(["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--no-ask-password",
    "--unit=greyward-auth-boundary-host", *props, "-p", "SELinuxContext=system_u:system_r:greyward_as_auth_t:s0",
    "--", runtime + "/auth-python", "-I", runtime + "/probe.py", "--host"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    if not select.select([host.stdout], [], [], 8)[0]:
        raise RuntimeError("Authentication fixture did not become ready")
    line = host.stdout.readline(2048)
    if not line:
        host.wait(timeout=3)
        raise RuntimeError("Authentication helper did not start: " + host.stderr.read(2048))
    metadata = json.loads(line)
    target = Path(f"/proc/{metadata['pid']}")
    if target.stat().st_uid != 1002 or (target / "attr/current").read_text().strip("\0\n") != "system_u:system_r:greyward_as_auth_t:s0" or (target / "stat").read_text().rsplit(")", 1)[1].split()[19] != metadata["start"]:
        raise RuntimeError("Authentication helper identity changed")
    result = subprocess.run(["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--no-ask-password",
        "--unit=greyward-auth-boundary-reader", *props, "-p", "SELinuxContext=system_u:system_r:greyward_guard_t:s0",
        "--", "/usr/bin/python3", "-I", reader, "--reader"], input=json.dumps(metadata) + "\n",
        text=True, capture_output=True, timeout=12)
    if result.returncode:
        raise RuntimeError("Synthetic reader failed: " + result.stderr[:2048])
    outcome = json.loads(result.stdout)
    if outcome.get("passed") is not True:
        raise RuntimeError("Boundary did not pass")
    print(json.dumps(outcome), flush=True)
    host.stdin.write("finish\n")
    host.stdin.flush()
    if host.wait(timeout=5) != 0:
        raise RuntimeError("Authentication fixture failed: " + host.stderr.read(2048))
finally:
    if host.poll() is None:
        subprocess.run(["/usr/bin/systemctl", "stop", "greyward-auth-boundary-host.service"], timeout=5, check=True)
        host.wait(timeout=5)
PY
if test "${1:-}" = --native-lock; then
  test "$#" = 1
  fixture=$(mktemp -d /var/lib/greyward-development/application-security/lock-probe.XXXXXXXX)
  install -d -o1002 -g1002 -m0700 "$fixture"
  for directory in home runtime tmp config config/labwc config/DankMaterialShell state cache; do
    install -d -o1002 -g1002 -m0700 "$fixture/$directory"
  done
  install -d -m0755 "$fixture/bin"
  install -m0555 /usr/bin/python3.14 "$auth_python"
  chcon -t greyward_as_auth_exec_t "$auth_python"
  # A debug-edited or mismatched artifact must never become trusted input.
  /usr/bin/python3 -I - <<'PY'
import hashlib, json, pathlib
base = pathlib.Path('/var/tmp/greyward-application-security-build/authentication-shell-v5')
manifest = json.loads((base / 'authentication.json').read_text())
files = {}
for path in sorted((base / 'shell').rglob('*')):
    if path.is_symlink() or not (path.is_file() or path.is_dir()):
        raise RuntimeError('Invalid authentication artifact')
    if path.is_file():
        files[path.relative_to(base / 'shell').as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
digest = hashlib.sha256(''.join(f'{key}\0{value}\n' for key, value in sorted(files.items())).encode()).hexdigest()
if manifest.get('schema') != 'greyward.authentication-shell/v1' or manifest.get('sourceRelease') != 'v1.6.2-6' or manifest.get('shellFiles') != files or manifest.get('shellDigest') != digest:
    raise RuntimeError('Authentication receipt mismatch')
PY
  cp -a /var/tmp/greyward-application-security-build/authentication-shell-v5/shell "$fixture/shell"
  install -m0644 "$base/systems.mantis.greyward.ApplicationSecurity1.policy" "$authorization_policy"
  restorecon "$authorization_policy"
  chown -R root:root "$fixture/shell"
  chmod -R a-w "$fixture/shell"
  chcon -R -t usr_t "$fixture/shell"
  for selected in 'auth-python:/usr/bin/python3.14' 'dbus-daemon:/usr/bin/dbus-daemon' 'labwc:/usr/bin/labwc' 'dms:/usr/lib/greyward/dms/v1.6.2-6/bin/dms' 'qs:/usr/bin/quickshell' 'wtype:/usr/local/lib/greyward-development/wtype-probe/wtype'; do
    install -m0555 "${selected#*:}" "$fixture/bin/${selected%%:*}"
    chcon -t greyward_as_auth_exec_t "$fixture/bin/${selected%%:*}"
  done
  # Fixed root default, not the development account's mutable preferences.
  /usr/bin/python3 -I - "$fixture" <<'PY'
import json, os, pathlib, sys
base = pathlib.Path(sys.argv[1])
settings = json.loads(pathlib.Path('/etc/skel/.config/DankMaterialShell/settings.json').read_text())
settings.update({'customPowerActionLock': '', 'loginctlLockIntegration': False,
    'lockAtStartup': False, 'lockBeforeSuspend': False, 'fadeToLockEnabled': False,
    'fadeToDpmsEnabled': False, 'lockScreenPowerOffMonitorsOnLock': False,
    'lockScreenVideoEnabled': False, 'lockPamExternallyManaged': True,
    'lockPamPath': '/etc/pam.d/greyward-dms-lock', 'enableFprint': False, 'enableU2f': False,
    'lockScreenNotificationMode': 0, 'lockScreenShowMediaPlayer': False})
for key in ('acMonitorTimeout', 'acLockTimeout', 'acPostLockMonitorTimeout',
            'batteryMonitorTimeout', 'batteryLockTimeout', 'batteryPostLockMonitorTimeout',
            'acSuspendTimeout', 'batterySuspendTimeout'):
    settings[key] = 0
target = base / 'config/DankMaterialShell/settings.json'
target.write_text(json.dumps(settings))
os.chown(target, 0, 0)
target.chmod(0o444)
(base / 'session-bus.conf').write_text('<busconfig><type>session</type><listen>unix:path=/run/greyward-application-security-lock/runtime/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="1002"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
(base / 'config/labwc/rc.xml').write_text('<labwc_config><core><decoration>server</decoration></core></labwc_config>')
(base / 'config/labwc/autostart').write_text('#!/bin/sh\n')
PY
  install -m0444 "$base/application-security-authentication-session.py" "$fixture/authentication-session.py"
  chcon -t greyward_as_auth_runtime_t "$fixture" "$fixture/bin" "$fixture/authentication-session.py" "$fixture/session-bus.conf"
  for directory in home runtime tmp config state cache; do chcon -R -t greyward_as_auth_runtime_t "$fixture/$directory"; done
  /usr/bin/python3 -I "$base/application-security-lock.py" --protected-authentication "$fixture"
elif test "${1:-}" = --tool-profile; then
  test "$#" = 1
  install -m0555 /usr/bin/ssh-keygen "$runtime/key-inspection"
  printf 'bb13e6ff90ade685d2154772b6a25729e5a5a98193fdb7d6ceba53cad315a109  %s\n' "$runtime/key-inspection" | sha256sum --check --strict >/dev/null
  chcon -t bin_t "$runtime/key-inspection"
  install -d -m0755 "$runtime/home" "$runtime/home/.ssh"
  /usr/bin/ssh-keygen -q -t ed25519 -N '' -C synthetic-fixture -f "$runtime/home/.ssh/id_ed25519"
  chown 1002:1002 "$runtime/home/.ssh/id_ed25519"
  chmod 0400 "$runtime/home/.ssh/id_ed25519"
  chcon -t greyward_as_profile_probe_secret_t "$runtime/home" "$runtime/home/.ssh" "$runtime/home/.ssh/id_ed25519"
  printf '(allow greyward_as_profile_probe_t greyward_as_profile_probe_secret_t (file (open read getattr)))\n' > "$base/$profile_module.cil"
  semodule -i "$base/$profile_module.cil"
  profile_installed=1
  run_profile() {
    systemd-run --quiet --collect --wait --service-type=exec \
      -p User=greyward-guard-probe -p Group=greyward-guard-probe \
      -p "SELinuxContext=$1" -p NoNewPrivileges=yes -p CapabilityBoundingSet= \
      -p PrivateNetwork=yes -p PrivateTmp=yes -p PrivateDevices=yes \
      -p ProtectSystem=strict -p ProtectHome=read-only -p RuntimeMaxSec=5 \
      -p StandardInput=null -p StandardOutput=null -p StandardError=null \
      "${@:2}"
  }
  for attempt in 1 2; do
    run_profile system_u:system_r:greyward_as_profile_probe_t:s0 "$runtime/key-inspection" -l -f "$runtime/home/.ssh/id_ed25519"
  done
  if run_profile system_u:system_r:greyward_guard_t:s0 /usr/bin/ssh-keygen -l -f "$runtime/home/.ssh/id_ed25519"; then
    echo 'Ordinary direct execution bypassed protection' >&2; exit 1
  fi
  if run_profile system_u:system_r:greyward_guard_t:s0 "$runtime/key-inspection" -l -f "$runtime/home/.ssh/id_ed25519"; then
    echo 'Ordinary direct entry gained profile' >&2; exit 1
  fi
  semodule -r "$profile_module"
  profile_installed=0
  if run_profile system_u:system_r:greyward_as_profile_probe_t:s0 "$runtime/key-inspection" -l -f "$runtime/home/.ssh/id_ed25519"; then
    echo 'Revoked kernel access still applies' >&2; exit 1
  fi
  printf '%s\n' '{"schema":"greyward.tool-profile-kernel-probe/v1","profile":"openssh-key-inspection/v1","allowed_reuses":2,"direct_execution_denied":true,"direct_profile_entry_denied":true,"revocation_denied":true,"streams":"NULL","coverage":"UNKNOWN"}'
elif test "$#" != 0; then
  echo 'Unsupported test mode' >&2; exit 1
fi
