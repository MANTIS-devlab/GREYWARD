#!/usr/bin/python3
"""Fixed synthetic file-export probes, never a product launcher/permission API."""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    home = Path("/home/greyward-guard-probe")
    context = Path("/proc/self/attr/current").read_text().rstrip("\x00\n")
    if os.getuid() != 1002 or context.split(":")[2] != "greyward_guard_t":
        raise RuntimeError("Run only in the separately enrolled synthetic subject")
    if Path("/sys/fs/selinux/enforce").read_text().strip() != "1":
        raise RuntimeError("SELinux enforcing is required")
    status = Path('/proc/self/status').read_text()
    if not any(line == 'CapEff:\t0000000000000000' for line in status.splitlines()):
        raise RuntimeError('The ordinary host subject must have no effective capabilities')
    # The systemd unit's outer network namespace belongs to the initial user
    # namespace and has only loopback. This operation must fail as the ordinary
    # subject. Even unexpected success touches no host/VM interface.
    outer_network = subprocess.run(['/usr/sbin/ip', 'link', 'set', 'dev', 'lo', 'down'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=2, check=False)
    if outer_network.returncode == 0:
        raise RuntimeError('Ordinary subject unexpectedly configured the outer namespace')
    # PrivateTmp creates an outer mount namespace owned by the initial user
    # namespace. Remounting its private /tmp must still require host capability.
    # Unexpected success cannot modify the VM's shared mounts.
    outer_mount = subprocess.run(['/usr/bin/mount', '-o', 'remount,ro', '/tmp'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=2, check=False)
    if outer_mount.returncode == 0:
        raise RuntimeError('Ordinary subject unexpectedly remounted the outer namespace')
    try:
        descriptor = os.open('/proc/sys/user/max_user_namespaces', os.O_WRONLY | os.O_CLOEXEC)
    except PermissionError:
        pass
    else:
        os.close(descriptor)
        raise RuntimeError('Ordinary subject unexpectedly opened the host namespace limit for write')
    scratch = home / "deputy-probe"
    scratch.mkdir(mode=0o700, exist_ok=True)
    metadata = scratch.lstat()
    if scratch.is_symlink() or not scratch.is_dir() or metadata.st_uid != os.getuid():
        raise RuntimeError("Unsafe synthetic output directory")
    os.chmod(scratch, 0o700)
    environment = {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    tools = {
        "cp": lambda source, target: ["/usr/bin/cp", "--", str(source), str(target)],
        "rsync": lambda source, target: ["/usr/bin/rsync", "--", str(source), str(target)],
        "tar": lambda source, target: ["/usr/bin/tar", "--create", "--file", str(target), "--directory", str(source.parent), "--", source.name],
        "gpg-store": lambda source, target: ["/usr/bin/gpg", "--batch", "--no-options", "--no-autostart", "--homedir", str(scratch), "--store", "--compress-algo", "none", "--output", str(target), "--", str(source)],
    }
    results = []
    for name, command in tools.items():
        positive = scratch / (name + "-ordinary.out")
        negative = scratch / (name + "-protected.out")
        for target in (positive, negative):
            if target.exists() or target.is_symlink():
                if target.is_symlink() or target.lstat().st_uid != os.getuid():
                    raise RuntimeError("Unsafe existing synthetic output")
                target.unlink()
        try:
            ordinary = subprocess.run(command(home / "ordinary.txt", positive), env=environment,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, timeout=5, check=False)
            control = ordinary.returncode == 0 and positive.is_file() and positive.stat().st_size > 0
            protected = subprocess.run(command(home / "protected/credential", negative), env=environment,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=5, check=False)
            # Only known synthetic markers are inspected. Do not print/store
            # file content, command output or arguments as security telemetry.
            exported = False
            if negative.is_file():
                if negative.stat().st_size > 64 * 1024:
                    raise RuntimeError("Synthetic output exceeded its bound")
                with negative.open("rb") as stream:
                    exported = b"synthetic credential\n" in stream.read(64 * 1024 + 1)
            passed = control and protected.returncode != 0 and not exported
            results.append({"tool": name, "ordinary_control": control,
                            "protected_command_denied": protected.returncode != 0,
                            "synthetic_export_present": bool(exported), "passed": passed})
        except (OSError, subprocess.TimeoutExpired):
            results.append({"tool": name, "state": "UNAVAILABLE", "passed": False})
    project = scratch / "npm-project"
    project.mkdir(mode=0o700, exist_ok=True)
    if project.is_symlink() or project.lstat().st_uid != os.getuid():
        raise RuntimeError("Unsafe synthetic task project")
    for name in ("package.json", "result.json", "user.npmrc", "global.npmrc"):
        selected = project / name
        if selected.exists() or selected.is_symlink():
            if selected.is_symlink() or selected.lstat().st_uid != os.getuid():
                raise RuntimeError("Unsafe existing task fixture")
            selected.unlink()
    # npm rejects loading one pathname as both configuration scopes. Separate
    # empty fixed files also exclude the test account's existing preferences.
    for name in ("user.npmrc", "global.npmrc"):
        descriptor = os.open(project / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
    descriptor = os.open(project / "package.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"name": "greyward-synthetic-task", "version": "1.0.0", "private": True,
                   "scripts": {"preinstall": "/usr/bin/python3 -I /usr/local/libexec/greyward-application-security-task-probe.py"}}, stream)
    try:
        task = subprocess.run(["/usr/bin/npm", "install", "--offline", "--no-audit", "--no-fund", "--package-lock=false",
                               "--ignore-scripts=false", "--userconfig=" + str(project / "user.npmrc"),
                               "--globalconfig=" + str(project / "global.npmrc"),
                               "--cache=" + str(scratch / "npm-cache")], cwd=project, env=environment,
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=10, check=False)
        result = project / "result.json"
        if result.is_symlink() or result.stat().st_uid != os.getuid() or result.stat().st_size > 2048:
            raise RuntimeError("Unsafe synthetic task result")
        with result.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
        task_passed = (task.returncode == 0 and value.get("ordinary_control") is True
                       and value.get("protected_read_denied") is True
                       and value.get("subject_context", "").split(":")[2] == "greyward_guard_t"
                       and value.get("profile_claimed") is False)
        results.append({"tool": "npm-offline-preinstall", "ordinary_control": value.get("ordinary_control"),
                        "protected_read_denied": value.get("protected_read_denied"),
                        "passed": task_passed})
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        results.append({"tool": "npm-offline-preinstall", "state": "UNAVAILABLE", "passed": False})
    project = scratch / "pip-project"
    project.mkdir(mode=0o700, exist_ok=True)
    if project.is_symlink() or project.lstat().st_uid != os.getuid():
        raise RuntimeError("Unsafe synthetic pip project")
    inputs = {
        "pyproject.toml": '[build-system]\nrequires=[]\nbuild-backend="probe_backend"\nbackend-path=["."]\n',
        "probe_backend.py": Path('/usr/local/libexec/greyward-application-security-pip-backend.py').read_text(),
    }
    for name in (*inputs, "result.json"):
        selected = project / name
        if selected.exists() or selected.is_symlink():
            if selected.is_symlink() or selected.lstat().st_uid != os.getuid():
                raise RuntimeError("Unsafe existing pip fixture")
            selected.unlink()
        if name in inputs:
            descriptor = os.open(selected, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(inputs[name])
    try:
        task = subprocess.run(['/usr/bin/python3', '-I', '/usr/local/libexec/greyward-application-security-pip-launch.py'],
                              cwd=project, env=environment, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        result = project / 'result.json'
        if result.is_symlink() or result.stat().st_uid != os.getuid() or result.stat().st_size > 2048:
            raise RuntimeError("Unsafe synthetic pip result")
        with result.open('r', encoding='utf-8') as stream:
            value = json.load(stream)
        passed = (task.returncode == 0 and value.get('ordinary_control') is True
                  and value.get('protected_read_denied') is True
                  and value.get('subject_context', '').split(':')[2] == 'greyward_guard_t'
                  and value.get('profile_claimed') is False)
        results.append({'tool': 'pip-offline-pep517', 'ordinary_control': value.get('ordinary_control'),
                        'protected_read_denied': value.get('protected_read_denied'), 'passed': passed})
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        results.append({'tool': 'pip-offline-pep517', 'state': 'UNAVAILABLE', 'passed': False})
    # Use an existing system application/runtime, no install/override mutation.
    # This invokes its runtime shell rather than the browser GUI. It tests the
    # unmanaged/broad-home boundary, not normal graphical/portal compatibility.
    runtime = scratch / 'flatpak-runtime'
    runtime.mkdir(mode=0o700, exist_ok=True)
    if runtime.is_symlink() or runtime.lstat().st_uid != os.getuid():
        raise RuntimeError('Unsafe private Flatpak runtime directory')
    os.chmod(runtime, 0o700)
    script = r'''
ordinary=false
present=false
denied=false
aliases_present=true
aliases_denied=true
test "$(cat /home/greyward-guard-probe/ordinary.txt)" = ordinary && ordinary=true
test -f /home/greyward-guard-probe/protected/credential && present=true
if ! head -c 1 /home/greyward-guard-probe/protected/credential >/dev/null 2>/dev/null; then denied=true; fi
for alias in /home/greyward-guard-probe/credential-link /home/greyward-guard-probe/credential-hardlink; do
    test -f "$alias" || aliases_present=false
    if head -c 1 "$alias" >/dev/null 2>/dev/null; then aliases_denied=false; fi
done
context=$(cat /proc/self/attr/current | tr -d '\000')
caps=$(grep '^CapEff:' /proc/self/status | awk '{print $2}')
printf '{"ordinary_control":%s,"protected_present":%s,"protected_read_failed":%s,"aliases_present":%s,"aliases_denied":%s,"subject_context":"%s","effective_capabilities":"%s"}\n' "$ordinary" "$present" "$denied" "$aliases_present" "$aliases_denied" "$context" "$caps"
'''
    flatpak_task = None
    try:
        task = subprocess.run(['/usr/bin/flatpak', 'run', '--system', '--unshare=network', '--no-a11y-bus',
                               '--no-session-bus', '--nodevice=all',
                               '--no-documents-portal', '--nosocket=session-bus', '--nosocket=system-bus',
                               '--nosocket=wayland', '--nosocket=x11', '--nosocket=fallback-x11',
                               '--filesystem=home', '--command=sh', 'com.brave.Browser/x86_64/stable', '-c', script],
                              env={**environment, 'XDG_RUNTIME_DIR': str(runtime)}, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
        flatpak_task = task
        if len(task.stdout) > 2048:
            raise ValueError('Oversized fixed Flatpak probe')
        value = json.loads(task.stdout)
        passed = (task.returncode == 0 and value.get('ordinary_control') is True
                  and value.get('protected_present') is True and value.get('protected_read_failed') is True
                  and value.get('aliases_present') is True and value.get('aliases_denied') is True
                  and value.get('subject_context', '').split(':')[2] == 'greyward_guard_t'
                  and value.get('effective_capabilities') == '0000000000000000')
        # Error status alone is not authoritative block evidence. The wrapper
        # independently requires a kernel AVC for this fixed synthetic inode.
        results.append({'tool': 'flatpak-broad-home', 'ordinary_control': value.get('ordinary_control'),
                        'protected_present': value.get('protected_present'),
                        'protected_read_failed': value.get('protected_read_failed'),
                        'aliases_present': value.get('aliases_present'),
                        'aliases_denied': value.get('aliases_denied'), 'passed': passed})
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        # Only this fixed fresh-account fixture's bounded startup diagnostic.
        # Never ingest command output into the product event/history pipeline.
        diagnostic = None if flatpak_task is None else ''.join(
            character for character in flatpak_task.stderr[:512].decode('utf-8', errors='replace')
            if character.isprintable()).replace(str(home), '[PROBE_HOME]')
        results.append({'tool': 'flatpak-broad-home', 'state': 'UNAVAILABLE', 'passed': False,
                        'startup_diagnostic': diagnostic})
    print(json.dumps({"schema": "greyward.application-security.deputy-probe/v1",
                      "subject_context": context, "results": results,
                      "passed": all(item["passed"] for item in results)}, sort_keys=True))
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    sys.exit(main())
