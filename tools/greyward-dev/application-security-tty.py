#!/usr/bin/python3
"""Private PTY/PAM-session probe; skips password authentication deliberately.

This never touches a graphical seat or another user's terminal. Fixed synthetic
account and command only; no generic root command or account API.
"""
import json
import os
from pathlib import Path
import pty
import select
import signal
import stat
import time
import sys


def run(critical=False):
    if os.getuid() != 0 or Path("/sys/fs/selinux/enforce").read_text().strip() != "1":
        raise RuntimeError("Root and SELinux enforcing are required")
    receipt = Path("/var/lib/greyward-development/application-security/account.uid")
    metadata = receipt.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise RuntimeError("Missing private account ownership receipt")
    import pwd
    account = pwd.getpwnam("greyward-guard-probe")
    if account.pw_uid != int(receipt.read_text()) or account.pw_dir != "/home/greyward-guard-probe":
        raise RuntimeError("Unexpected probe account")
    command = (b"/usr/bin/python3 -I /usr/local/libexec/greyward-application-security-probe.py "
               b"--home /home/greyward-guard-probe --route-only; exit\n")
    if critical:
        command = b"/usr/bin/python3 -I /usr/local/libexec/greyward-application-security-critical-session.py; exit\n"
    pid, terminal = pty.fork()
    if pid == 0:
        # Match getty's login execution context. A root Python helper otherwise
        # stays unconfined_service_t, for which PAM has no enrolled-user mapping.
        # This changes only this child at its next exec; no login/PAM files change.
        with open("/proc/self/attr/exec", "wb", buffering=0) as context:
            context.write(b"system_u:system_r:local_login_t:s0")
        os.execve("/usr/bin/login", ["login", "-f", "greyward-guard-probe"],
                  {"PATH": "/usr/bin:/usr/sbin", "TERM": "dumb", "LANG": "C.UTF-8"})
    process = os.pidfd_open(pid)
    output = bytearray()
    deadline = time.monotonic() + (65 if critical else 20)
    sent = False
    started = time.monotonic()
    status = None
    try:
        while time.monotonic() < deadline and len(output) < 131072:
            if not sent and time.monotonic() - started >= 0.5:
                os.write(terminal, command)
                sent = True
            if select.select([terminal], [], [], 0.1)[0]:
                try:
                    data = os.read(terminal, 8192)
                except OSError:
                    break
                if not data:
                    break
                output.extend(data)
            if status is None:
                ended, candidate = os.waitpid(pid, os.WNOHANG)
                if ended:
                    status = candidate
                    # Drain any final buffered output without an unbounded wait.
                    if not select.select([terminal], [], [], 0)[0]:
                        break
        if status is None:
            # The slave PTY closes before login finishes PAM-session cleanup.
            # Give that tracked pidfd a bounded grace period before termination.
            select.select([process], [], [], max(0, min(2, deadline - time.monotonic())))
            ended, candidate = os.waitpid(pid, os.WNOHANG)
            if ended:
                status = candidate
            else:
                signal.pidfd_send_signal(process, signal.SIGKILL)
                _, status = os.waitpid(pid, 0)
    finally:
        os.close(terminal)
        os.close(process)
    evidence = None
    for line in output.decode("utf-8", errors="replace").splitlines():
        if line.startswith("{"):
            try:
                candidate = json.loads(line)
            except ValueError:
                continue
            if candidate.get("schema") == ("greyward.application-security.critical-session/v1" if critical else "greyward.application-security.probe/v1"):
                evidence = candidate
    passed = bool(evidence and evidence["passed"] and
                  (all(evidence["checks"].values()) if critical else len(evidence["results"]) == 24)
                  and os.waitstatus_to_exitcode(status) == 0)
    print(json.dumps({"schema": "greyward.application-security.tty/v1", "passed": passed,
                      "scope": "private-pty-pam-session-with-authentication-skipped",
                      "exit_code": os.waitstatus_to_exitcode(status), "probe": evidence}, sort_keys=True))
    if not passed:
        # Fixed login -f and synthetic probe only; no password, user command,
        # secret content or active session is collected by this test helper.
        print(output.decode("utf-8", errors="replace")[-2000:], file=sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ['--critical']):
        raise SystemExit('Only fixed private PTY modes are supported')
    raise SystemExit(run(sys.argv[1:] == ['--critical']))
