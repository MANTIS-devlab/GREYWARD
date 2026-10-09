#!/usr/bin/python3
"""Development-only fresh-auth probe for the owned UID 1002, never the desktop.

Temporarily set a random probe password, use a private process-bound terminal
agent twice, restore the original hash/change date. No password is printed or
stored. A root-only recovery receipt survives coordinator interruption.
"""
import json
import os
import pathlib
import pty
import pwd
import re
import select
import secrets
import signal
import stat
import subprocess
import sys
import termios
import time

ACCOUNT = "greyward-guard-probe"
STATE = pathlib.Path("/var/lib/greyward-development/application-security")
BACKUP = STATE / "authentication-shadow-backup.json"
BINARY = "/usr/local/libexec/greyward-application-security-fresh-auth-test"


def owned_account():
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError("Root development fixture required")
    for path in [STATE, *STATE.parents]:
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError("Unsafe development receipt directory")
    if stat.S_IMODE(STATE.stat().st_mode) != 0o700:
        raise RuntimeError("Private receipt directory required")
    marker = STATE / "account.uid"
    metadata = marker.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or metadata.st_mode & 0o022:
        raise RuntimeError("Unsafe account receipt")
    account = pwd.getpwnam(ACCOUNT)
    if account.pw_uid != 1002 or account.pw_gid != 1002 or account.pw_dir != "/home/greyward-guard-probe" or marker.read_text().strip() != "1002":
        raise RuntimeError("Refusing unowned or changed probe account")
    if os.getgrouplist(ACCOUNT, 1002) != [1002]:
        raise RuntimeError("Probe account has unexpected additional groups")


def restore():
    owned_account()
    if not BACKUP.exists():
        return
    metadata = BACKUP.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or metadata.st_size > 4096:
        raise RuntimeError("Unsafe password recovery receipt")
    data = json.loads(BACKUP.read_text())
    if data["uid"] != 1002 or data["account"] != ACCOUNT or "\n" in data["hash"] or ":" in data["hash"]:
        raise RuntimeError("Invalid password recovery receipt")
    subprocess.run(["/usr/sbin/chpasswd", "-e"], input=f'{ACCOUNT}:{data["hash"]}\n', text=True, capture_output=True, check=True)
    day = str(int(data["last_change"])) if data["last_change"] else "-1"
    subprocess.run(["/usr/bin/chage", "-d", day, ACCOUNT], capture_output=True, check=True)
    BACKUP.unlink()


def prepare_password():
    restore()
    raw = subprocess.check_output(["/usr/bin/getent", "shadow", ACCOUNT], text=True)
    fields = raw.strip().split(":")
    if len(fields) != 9 or fields[0] != ACCOUNT:
        raise RuntimeError("Probe shadow receipt unavailable")
    descriptor = os.open(BACKUP, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump({"account": ACCOUNT, "uid": 1002, "hash": fields[1], "last_change": fields[2]}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    password = secrets.token_urlsafe(32)
    subprocess.run(["/usr/sbin/chpasswd"], input=f"{ACCOUNT}:{password}\n", text=True, capture_output=True, check=True)
    return password


def agent(pid_start):
    notify_read, notify_write = os.pipe()
    os.set_inheritable(notify_write, True)
    pid, master = pty.fork()
    if pid == 0:
        os.close(notify_read)
        settings = termios.tcgetattr(0)
        settings[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, settings)
        os.setgroups([])
        os.setgid(1002)
        os.setuid(1002)
        os.execve("/usr/bin/pkttyagent", ["pkttyagent", f"--process={pid_start}", f"--notify-fd={notify_write}"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    os.close(notify_write)
    return pid, master, notify_read


def stop_agent(pid):
    # The unreaped direct child anchors its process-group ID against reuse.
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for _ in range(20):
        child, _ = os.waitpid(pid, os.WNOHANG)
        if child:
            return
        time.sleep(0.05)
    os.killpg(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


def run():
    owned_account()
    metadata = pathlib.Path(BINARY).lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError("Reviewed root-owned test binary required")
    process = None
    agent_pid = None
    master = notify = None
    try:
        password = prepare_password()
        process = subprocess.Popen([BINARY, "--ignored", "--exact", "fresh_owner_checks_require_two_actual_authentications", "--nocapture"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + (150 if os.environ.get('GREYWARD_CRITICAL_GRANTS') else 110 if os.environ.get('GREYWARD_CRITICAL_REGISTRATION') else 35)
        expected_prompts = 5 if os.environ.get('GREYWARD_CRITICAL_TRANSPORT') else 3 if os.environ.get('GREYWARD_CRITICAL_GRANTS') else 2
        line_buffer = b""
        prompt_buffer = b""
        prompts = 0
        ready = False
        while process.poll() is None and time.monotonic() < deadline:
            watched = [process.stdout]
            if master is not None:
                watched.append(master)
            if notify is not None:
                watched.append(notify)
            readable, _, _ = select.select(watched, [], [], 0.1)
            for descriptor in readable:
                if descriptor == process.stdout:
                    chunk = os.read(process.stdout.fileno(), 4096)
                    line_buffer = (line_buffer + chunk)[-8192:]
                    match = re.search(rb"AUTH_SUBJECT=(:[0-9]+\.[0-9]+),([0-9]+):([0-9]+)\r?\n", line_buffer)
                    if match and agent_pid is None:
                        pid_start = match.group(2).decode("ascii") + "," + match.group(3).decode("ascii")
                        agent_pid, master, notify = agent(pid_start)
                elif descriptor == notify:
                    if not os.read(notify, 1):
                        os.close(notify)
                        notify = None
                        if os.waitid(os.P_PID, agent_pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                            raise RuntimeError("Private agent exited before registration")
                        process.stdin.write(b"1")
                        process.stdin.flush()
                        ready = True
                else:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        chunk = b""
                    prompt_buffer = (prompt_buffer + chunk)[-8192:]
                    if b"Password:" in prompt_buffer:
                        if prompts >= expected_prompts:
                            raise RuntimeError("Unexpected extra authentication challenge")
                        os.write(master, password.encode("ascii") + b"\n")
                        prompts += 1
                        prompt_buffer = b""
        if process.poll() is None:
            raise RuntimeError("Private authentication deadline expired")
        if process.returncode != 0 or prompts != expected_prompts or not ready:
            diagnostic = process.stderr.read(4096).decode("utf-8", errors="replace")
            # Rust failure diagnostics contain only the fixed fixture assertion
            # or authority/kernel decision; the agent terminal is never logged.
            print(diagnostic, file=sys.stderr)
            raise RuntimeError(f"Private fresh-authentication probe failed (status={process.returncode}, prompts={prompts}, agent_ready={ready})")
        critical = bool(os.environ.get('GREYWARD_CRITICAL_GRANTS'))
        print(json.dumps({"schema": "greyward.application-security.auth-probe/v1", "passed": True,
            "owner_authentications": prompts, "grant_mutated": critical,
            "descriptor_labels_verified": bool(os.environ.get('GREYWARD_CRITICAL_REGISTRATION')),
            "kernel_deny_allow_direct_bypass_revocation_verified": critical,
            "coverage": "UNKNOWN"}))
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            if agent_pid is not None:
                stop_agent(agent_pid)
            for descriptor in [master, notify]:
                if descriptor is not None:
                    os.close(descriptor)
        finally:
            restore()


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--restore"]:
            restore()
            print("PROBE_PASSWORD_RESTORED")
        elif not sys.argv[1:]:
            run()
        else:
            raise RuntimeError("Unsupported development fixture arguments")
    except RuntimeError as failure:
        print(str(failure), file=sys.stderr)
        raise SystemExit(1)
    except Exception as failure:
        # No raw terminal output, command output, shadow hash or password.
        print(f"Private authentication probe unavailable ({type(failure).__name__}); inspect bounded fixture state", file=sys.stderr)
        raise SystemExit(1)
