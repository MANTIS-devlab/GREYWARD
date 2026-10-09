#!/usr/bin/python3
"""Root coordinator for native PAM on one owned, private headless display.

Only UID 1002 receives a temporary password. Its original hash/change date is
restored on every exit; the existing root-only recovery receipt survives a
crash. Keyboard input uses a signed extracted wtype on that private socket,
never /dev/uinput. No password is placed in argv, environment, file or output.
"""
import importlib.util
import json
import os
import pty
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

BASE = "/run/greyward-application-security-lock"
UNIT = "greyward-application-security-lock-probe.service"
STATE = Path("/var/lib/greyward-development/application-security")
ACTUATOR = "/usr/local/lib/greyward-development/wtype-probe/wtype"
PROTECTED = False
FIXTURE = None


def load_authentication():
    path = Path("/usr/local/libexec/greyward-application-security-authorization.py")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError("Unsafe fixed authentication helper")
    spec = importlib.util.spec_from_file_location("private_authentication", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.owned_account()
    return module


def process_identity(pid, expected):
    handle = os.pidfd_open(pid)
    try:
        root = Path(f"/proc/{pid}")
        if root.stat().st_uid != 1002:
            raise RuntimeError("Wrong private process UID")
        context = (root / "attr/current").read_text().rstrip("\x00\n")
        expected_context = "system_u:system_r:greyward_as_auth_t:s0" if PROTECTED else "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0"
        if context != expected_context:
            raise RuntimeError("Wrong private process SELinux context")
        if (root / "comm").read_text().strip() != expected:
            raise RuntimeError("Wrong private process executable")
        executables = {"dms": "/usr/lib/greyward/dms/v1.6.2-6/bin/dms",
                       "labwc": "/usr/bin/labwc", "qs": "/usr/bin/quickshell"}
        if PROTECTED:
            selected = FIXTURE / "bin" / {"dms": "dms", "labwc": "labwc", "qs": "qs"}[expected]
            held = (root / "exe").stat()
            executable = selected.lstat()
            if (held.st_dev, held.st_ino) != (executable.st_dev, executable.st_ino):
                raise RuntimeError("Private protected process uses another generation")
        else:
            if os.readlink(root / "exe") != executables[expected]:
                raise RuntimeError("Private process does not use the pinned executable")
            executable = Path(executables[expected]).lstat()
        if not stat.S_ISREG(executable.st_mode) or executable.st_uid != 0 or executable.st_mode & 0o022:
            raise RuntimeError("Private executable is not root owned")
        environment = (root / "environ").read_bytes().split(b"\0")
        if f"XDG_RUNTIME_DIR={BASE}/runtime".encode() not in environment:
            raise RuntimeError("Process does not belong to the private display")
        if select.select([handle], [], [], 0)[0]:
            raise RuntimeError("Private process exited during validation")
        return handle
    except Exception:
        os.close(handle)
        raise


def socket_peer(path, expected_comm):
    metadata = path.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 1002:
        raise RuntimeError("Wrong private socket owner/type")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(2)
        connection.connect(str(path))
        pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 1002:
            raise RuntimeError("Wrong private socket peer")
        handle = process_identity(pid, expected_comm)
    return pid, handle


def run():
    global PROTECTED, FIXTURE
    auth = load_authentication()
    if subprocess.check_output(["/usr/sbin/getenforce"], text=True).strip() != "Enforcing":
        raise RuntimeError("SELinux must remain enforcing")
    argument = sys.argv[1:]
    if len(argument) == 2 and argument[0] == "--protected-authentication":
        PROTECTED = True
        argument = argument[1:]
    if len(argument) != 1:
        raise RuntimeError("One root-created fixed fixture is required")
    fixture = Path(argument[0])
    FIXTURE = fixture
    if fixture.parent != STATE or not fixture.name.startswith("lock-probe."):
        raise RuntimeError("Unsupported fixture path")
    metadata = fixture.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 1002 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("Unsafe private fixture")
    for path in [ACTUATOR, "/usr/local/libexec/greyward-application-security-lock-session.sh"]:
        metadata = Path(path).lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError("Unsafe fixed display helper")
    handles = []
    namespace = None
    unit_started = False
    authentication_started = False
    private_login = None
    private_terminal = None
    login_handle = None
    try:
        password = auth.prepare_password()
        if PROTECTED:
            # Root-only fixture: establish a real private login/PAM scope while
            # deliberately skipping login authentication. Native lock/Polkit
            # authentication is tested separately, with synthetic credentials.
            private_login, private_terminal = pty.fork()
            if private_login == 0:
                with open("/proc/self/attr/exec", "wb", buffering=0) as context:
                    context.write(b"system_u:system_r:local_login_t:s0")
                os.execve("/usr/bin/login", ["login", "-f", "greyward-guard-probe"],
                          {"PATH": "/usr/bin:/usr/sbin", "TERM": "dumb", "LANG": "C.UTF-8"})
            login_handle = os.pidfd_open(private_login)
            time.sleep(.5)
            os.write(private_terminal, b"exec /usr/bin/sleep 65\n")
        invocation = [
            "/usr/bin/systemd-run", "--quiet", "--collect", "--unit=" + UNIT.removesuffix(".service"),
            "-p", "User=greyward-guard-probe", "-p", "Group=greyward-guard-probe",
            "-p", "SELinuxContext=" + ("system_u:system_r:greyward_as_auth_t:s0" if PROTECTED else "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0"),
            "-p", "RuntimeMaxSec=75", "-p", "TimeoutStopSec=3", "-p", "MemoryMax=768M",
            "-p", "CPUQuota=100%", "-p", "TasksMax=128", "-p", "PrivateNetwork=yes",
            "-p", "PrivateTmp=yes", "-p", "ProtectHome=yes", "-p", "ProtectSystem=strict",
            "-p", f"BindPaths={fixture}:{BASE}", "-p", f"ReadWritePaths={BASE}",
            "-E", "PATH=/usr/bin:/bin",
        ]
        invocation += (["/usr/local/libexec/greyward-authentication-boundary-python", "-I", BASE + "/authentication-session.py"]
                       if PROTECTED else ["/bin/bash", "/usr/local/libexec/greyward-application-security-lock-session.sh"])
        if PROTECTED:
            invocation[invocation.index("-E"):invocation.index("-E")] = ["-p", f"BindPaths={fixture}/tmp:/tmp"]
        subprocess.run(invocation, check=True, timeout=6)
        unit_started = True
        if PROTECTED:
            # Quickshell's Polkit agent binds an actual logind session, rather
            # than a service process merely sharing a UID. This fixture admits
            # only the root-created UID-1002 leader/session, never seat0.
            leader = int(subprocess.check_output(["/usr/bin/systemctl", "show", UNIT, "-p", "MainPID", "--value"], text=True))
            until = time.monotonic() + 4
            scope = None
            while time.monotonic() < until:
                sessions = subprocess.check_output(["/usr/bin/loginctl", "list-sessions", "--no-legend", "--no-pager"], text=True)
                for row in sessions.splitlines():
                    fields = row.split()
                    if len(fields) > 4 and fields[1] == "1002" and fields[4] == str(private_login):
                        scope = subprocess.check_output(["/usr/bin/loginctl", "show-session", fields[0], "-p", "Scope", "--value"], text=True).strip()
                        break
                if scope:
                    break
                time.sleep(.05)
            if not scope or not scope.startswith("session-") or not scope.endswith(".scope"):
                raise RuntimeError("Owned private PAM scope unavailable")
            control = subprocess.check_output(["/usr/bin/systemctl", "show", scope, "-p", "ControlGroup", "--value"], text=True).strip()
            if not control.startswith("/user.slice/user-1002.slice/session-") or ".." in control:
                raise RuntimeError(f"Unexpected private session cgroup: {control!r}")
            handle = os.pidfd_open(leader)
            try:
                process = Path(f"/proc/{leader}")
                if process.stat().st_uid != 1002 or (process / "attr/current").read_text().strip("\0\n") != "system_u:system_r:greyward_as_auth_t:s0":
                    raise RuntimeError("Private leader changed")
                (Path("/sys/fs/cgroup" + control) / "cgroup.procs").write_text(str(leader))
                target = fixture / "session-admitted"
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
                os.close(descriptor)
            finally:
                os.close(handle)
        deadline = time.monotonic() + 25
        backend_socket = None
        display_socket = fixture / "runtime/wayland-0"
        while time.monotonic() < deadline:
            candidates = list((fixture / "runtime").glob("danklinux-*.sock"))
            if len(candidates) == 1 and display_socket.exists():
                backend_socket = candidates[0]
                break
            active = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", UNIT], capture_output=True, timeout=2)
            if active.returncode:
                raise RuntimeError("Private authentication unit exited before readiness")
            time.sleep(0.1)
        if backend_socket is None:
            raise RuntimeError("One private backend socket was not ready")
        backend, handle = socket_peer(backend_socket, "dms")
        handles.append(handle)
        if stat.S_IMODE(backend_socket.stat().st_mode) != 0o600:
            raise RuntimeError("Backend socket is not private")
        compositor, handle = socket_peer(display_socket, "labwc")
        handles.append(handle)
        # Hold the actual mount namespace, not a reusable numerical PID target.
        namespace = os.open(f"/proc/{compositor}/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        if select.select(handles, [], [], 0)[0]:
            raise RuntimeError("Private socket peer exited during namespace capture")
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": BASE + "/home", "USER": "greyward-guard-probe",
            "LOGNAME": "greyward-guard-probe", "XDG_RUNTIME_DIR": BASE + "/runtime",
            "WAYLAND_DISPLAY": "wayland-0", "DMS_SOCKET": BASE + "/runtime/" + backend_socket.name,
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + BASE + "/runtime/bus",
            "XDG_CONFIG_HOME": BASE + "/config", "XDG_STATE_HOME": BASE + "/state",
            "XDG_CACHE_HOME": BASE + "/cache", "LC_ALL": "C.UTF-8"
        }
        if PROTECTED:
            environment["DMS_SHELL_DIR"] = BASE + "/shell"

        def enter():
            os.setns(namespace, os.CLONE_NEWNS)
            os.setgroups([])
            os.setgid(1002)
            os.setuid(1002)

        def command(arguments, value=None):
            if select.select(handles, [], [], 0)[0]:
                raise RuntimeError("Private display process is no longer alive")
            result = subprocess.run(arguments, input=value, capture_output=True, env=environment,
                                    preexec_fn=enter, timeout=6, text=True)
            if result.returncode:
                # Do not echo keyboard input or arbitrary shell/provider logs.
                raise RuntimeError(f"Private command failed ({Path(arguments[0]).name}, {result.returncode})")
            if len(result.stdout) > 8192:
                raise RuntimeError("Private readback exceeds limit")
            return result.stdout.strip()

        def ipc(target, method, *arguments):
            return command([BASE + "/bin/dms" if PROTECTED else "/usr/local/bin/greyward-dms", "ipc", "call", target, method, *arguments])

        while time.monotonic() < deadline:
            try:
                status = json.loads(ipc("lock", "status"))
                break
            except (subprocess.TimeoutExpired, RuntimeError, json.JSONDecodeError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Private shell IPC was not ready")
        # Before a mutation, positively identify the sole UI process as another
        # confined UID-1002 process in this exact runtime, and bind its pidfd.
        candidates = []
        for path in Path("/proc").iterdir():
            if path.name.isdecimal():
                try:
                    if path.stat().st_uid == 1002 and (path / "comm").read_text().strip() == "qs":
                        candidates.append(int(path.name))
                except (OSError, ValueError):
                    continue
        if len(candidates) != 1:
            raise RuntimeError("Expected one separate-account shell")
        handles.append(process_identity(candidates[0], "qs"))
        if PROTECTED and json.loads(ipc("authentication", "status"))["polkitRegistered"] is not True:
            raise RuntimeError("Protected Polkit agent did not register: " + (fixture / "session-readback.json").read_text())
        if PROTECTED:
            print("PROTECTED_POLKIT_REGISTERED", flush=True)
        for key, value in [("loginctlLockIntegration", False), ("customPowerActionLock", ""),
                           ("lockPamExternallyManaged", True), ("lockPamPath", "/etc/pam.d/greyward-dms-lock")]:
            if json.loads(ipc("settings", "get", key)) != value:
                raise RuntimeError("Private native lock settings differ")
        if status["sessionLockSecure"] or status["shouldLock"]:
            raise RuntimeError("Unexpected initial private lock")

        def wait_state(locked):
            until = time.monotonic() + 8
            while time.monotonic() < until:
                state = json.loads(ipc("lock", "status"))
                if state["sessionLockSecure"] is locked and state["shouldLock"] is locked:
                    return
                time.sleep(0.1)
            raise RuntimeError("Private native lock did not reach the expected state")

        results = []
        if PROTECTED:
            results.append("protected_polkit_registered")
        actuator = BASE + "/bin/wtype" if PROTECTED else ACTUATOR
        for cycle in range(2):
            ipc("lock", "lock")
            wait_state(True)
            if PROTECTED:
                print(f"PROTECTED_LOCK_CYCLE_{cycle + 1}_SECURE", flush=True)
            if PROTECTED and cycle == 0:
                for method in ["unlock", "forceReset"]:
                    try:
                        ipc("lock", method)
                    except (RuntimeError, subprocess.TimeoutExpired):
                        pass
                    # DMS may return exit 0 for an absent Quickshell method.
                    # The authoritative result is that both secure/desired
                    # lock states remain active, rather than CLI exit status.
                    wait_state(True)
                results.append("unauthenticated_release_ipc_refused")
            time.sleep(0.4)
            if cycle == 0:
                authentication_started = True
                command([actuator, "-", "-k", "Return"], "synthetic-wrong-password")
                time.sleep(3)
                state = json.loads(ipc("lock", "status"))
                if not state["sessionLockSecure"] or not state["shouldLock"]:
                    raise RuntimeError("Wrong password released the native lock")
                results.append("wrong_password_retains_secure_lock")
            command([actuator, "-M", "ctrl", "-k", "a", "-m", "ctrl", "-k", "BackSpace"])
            command([actuator, "-", "-k", "Return"], password)
            wait_state(False)
            results.append(f"pam_unlock_cycle_{cycle + 1}")
        if PROTECTED:
            # Use the fixed synthetic sleep in this exact private login scope.
            # No root command or grant is executed by these auth_self actions.
            subjects = []
            for path in Path("/proc").iterdir():
                if not path.name.isdecimal():
                    continue
                try:
                    if path.stat().st_uid == 1002 and (path / "comm").read_text().strip() == "sleep" and (path / "cgroup").read_text().strip() == "0::" + control:
                        subjects.append(path)
                except FileNotFoundError:
                    continue
            if len(subjects) != 1:
                raise RuntimeError("One fixed private authentication subject required")
            subject = subjects[0]
            start = (subject / "stat").read_text().rsplit(")", 1)[1].split()[19]
            subject_handle = os.pidfd_open(int(subject.name))
            handles.append(subject_handle)
            for cycle in range(2):
                request = subprocess.Popen(["/usr/bin/pkcheck", "--action-id", "systems.mantis.greyward.application-security.grant-owner",
                    "--process", f"{subject.name},{start},1002", "--allow-user-interaction"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    until = time.monotonic() + 6
                    while time.monotonic() < until:
                        state = json.loads(ipc("authentication", "status"))
                        if state["polkitActive"] and state["responseRequired"]:
                            break
                        if request.poll() is not None:
                            raise RuntimeError("Sensitive action skipped fresh protected authentication")
                        time.sleep(.1)
                    else:
                        raise RuntimeError("Protected authorization prompt unavailable")
                    time.sleep(.4)
                    command([actuator, "-", "-k", "Return"], password)
                    if request.wait(timeout=6) != 0:
                        raise RuntimeError("Protected owner authentication failed")
                    results.append(f"fresh_protected_polkit_cycle_{cycle + 1}")
                finally:
                    if request.poll() is None:
                        request.kill()
                        request.wait(timeout=3)
        print(json.dumps({"schema": "greyward.application-security.native-lock-probe/v1",
                          "passed": True, "checks": results, "display": "PRIVATE_HEADLESS",
                          "uid": 1002, "domain": "greyward_as_auth_t" if PROTECTED else "greyward_guard_t", "loginctl_tested": False}))
    finally:
        if PROTECTED and not authentication_started:
            # Startup only, before any response/password entered the renderer.
            source = fixture / "dms.log"
            if source.exists():
                target = Path("/var/tmp/greyward-application-security-build/authentication-check/dms-startup.log")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as log:
                    log.write(source.read_bytes()[:16_384])
        try:
            if unit_started:
                stopped = subprocess.run(["/usr/bin/systemctl", "stop", UNIT], capture_output=True, timeout=8)
                if stopped.returncode not in {0, 5}:
                    raise RuntimeError("Owned private unit could not be stopped")
        finally:
            try:
                auth.restore()
            finally:
                if namespace is not None:
                    os.close(namespace)
                for handle in handles:
                    os.close(handle)
                if private_terminal is not None:
                    os.close(private_terminal)
                if login_handle is not None:
                    try:
                        signal.pidfd_send_signal(login_handle, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.close(login_handle)
                    os.waitpid(private_login, 0)


if __name__ == "__main__":
    try:
        run()
    except Exception as failure:
        print(f"Private native lock validation failed: {type(failure).__name__}: {failure}", file=sys.stderr)
        raise SystemExit(1)
