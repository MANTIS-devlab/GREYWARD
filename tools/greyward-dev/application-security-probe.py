#!/usr/bin/python3
"""Adversarial checks inside the separate SELinux feasibility account.

This is a probe, not a launcher or an enforcement implementation. No secret
contents are emitted; fixtures are synthetic. Run as greyward-guard-probe.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import subprocess
import signal
import socket
import sys
import time

SUBJECT = "greyward_guard_t"
SECRET = "greyward_guard_secret_t"


def denied_open(path):
    try:
        with path.open("rb") as stream:
            stream.read(1)
    except OSError as error:
        return error.errno == errno.EACCES
    return False


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--owner", action="store_true")
    parser.add_argument("--route-only", action="store_true",
                        help="Exercise a session execution route without the owner fixture")
    parser.add_argument("--bind-alias", action="store_true",
                        help="Check the private bind mount supplied by the root lifecycle")
    args = parser.parse_args()
    home = args.home.resolve(strict=True)
    namespace_root = (os.getuid() == 0 and
        Path('/proc/self/uid_map').read_text().split() == ['0', '1002', '1'])
    if home != Path.home().resolve(strict=True) or (os.getuid() == 0 and not namespace_root):
        parser.error("Run only as the isolated account against its own home")
    if namespace_root and args.owner:
        parser.error("Namespace attack probe cannot become the grant owner")
    context = Path("/proc/self/attr/current").read_text().strip().rstrip("\x00")
    if args.owner:
        if context.split(":")[2] != "greyward_guard_owner_t":
            parser.error("Owner fixture requires its independently selected context")
        # Synthetic data only: a positive control for cross-context memory/FD tests.
        replacement = home / "protected" / ".replacement"
        replacement.write_bytes(b"synthetic replacement\n")
        replacement.replace(home / "protected" / "replaced-credential")
        directory = home / "protected" / "created-directory"
        directory.mkdir(exist_ok=True)
        (directory / "credential").write_bytes(b"synthetic child\n")
        import_target = home / "protected" / "outside-import"
        import_target.unlink(missing_ok=True)
        import_source = home / "ordinary-import-source"
        import_source.write_bytes(b"ordinary import fixture\n")
        import_denied = False
        try:
            import_source.replace(import_target)
        except OSError as error:
            import_denied = error.errno == errno.EACCES
        agent_path = home / "owner-agent.sock"
        agent_path.unlink(missing_ok=True)
        agent = None
        loaded = False
        agent_environment = {"PATH": "/usr/bin", "HOME": str(home), "LANG": "C",
                             "SSH_AUTH_SOCK": str(agent_path)}
        try:
            agent = subprocess.Popen(["/usr/bin/ssh-agent", "-D", "-a", str(agent_path)],
                                     env=agent_environment, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(30):
                if agent.poll() is not None or agent_path.exists():
                    break
                time.sleep(0.1)
            if agent.poll() is None and agent_path.exists():
                result = subprocess.run(["/usr/bin/ssh-add", "-q", str(home / "protected" / "agent-key")],
                                        env=agent_environment, capture_output=True, timeout=3, check=False)
                loaded = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            loaded = False
        socket_path = home / "owner.sock"
        socket_path.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint, \
                (home / "protected" / "credential").open("rb") as stream:
            endpoint.bind(str(socket_path))
            endpoint.listen(1)
            data = ctypes.create_string_buffer(stream.read(64))
            (home / "owner.json").write_text(json.dumps({"pid": os.getpid(),
                "address": ctypes.addressof(data), "descriptor": stream.fileno(),
                "outside_import_denied": import_denied, "agent_loaded": loaded,
                "agent_pid": agent.pid if agent is not None else None}))
            try:
                time.sleep(60)
            finally:
                if agent is not None and agent.poll() is None:
                    agent.terminate()
                    try:
                        agent.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        agent.kill()
                        agent.wait(timeout=3)
        return 0
    results = []

    def check(name, passed, **details):
        results.append({"test": name, "passed": bool(passed), **details})

    check("subject_context", context.split(":")[2] == SUBJECT, context=context)
    check("enforcing", Path("/sys/fs/selinux/enforce").read_text().strip() == "1")
    ordinary = home / "ordinary.txt"
    check("ordinary_file_positive_control", ordinary.read_text() == "ordinary\n")
    # A same-domain endpoint must work before a cross-domain failure can be
    # interpreted as enforcement rather than missing Unix socket support.
    socket_path = home / "ordinary-probe.sock"
    socket_path.unlink(missing_ok=True)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint, \
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            endpoint.bind(str(socket_path))
            endpoint.listen(1)
            client.settimeout(2)
            client.connect(str(socket_path))
            with endpoint.accept()[0] as accepted:
                accepted.sendall(b"ordinary")
                check("ordinary_unix_socket_positive_control", client.recv(8) == b"ordinary")
    except OSError as error:
        check("ordinary_unix_socket_positive_control", False,
              reason=errno.errorcode.get(error.errno, "UNKNOWN"))
    finally:
        socket_path.unlink(missing_ok=True)
    target = home / "protected" / "credential"
    check("direct_python_read_denied", denied_open(target))
    check("symlink_read_denied", denied_open(home / "credential-link"))
    check("hardlink_read_denied", denied_open(home / "credential-hardlink"))
    if args.bind_alias:
        alias = home / "bound-secret" / "credential"
        try:
            original, mounted = target.stat(), alias.stat()
            # ismount() misses same-filesystem bind mounts. Use the live kernel
            # mount table plus inode identity, not path naming, as the control.
            mounted_here = any(line.split()[4] == str(home / "bound-secret")
                               for line in Path("/proc/self/mountinfo").read_text().splitlines())
            check("private_bind_mount_object_identity", mounted_here and
                  (original.st_dev, original.st_ino) == (mounted.st_dev, mounted.st_ino))
            check("private_bind_mount_read_denied", denied_open(alias))
        except OSError as error:
            check("private_bind_mount_fixture", False,
                  reason=errno.errorcode.get(error.errno, "UNKNOWN"))
    for name, path in (
        ("atomic_replacement", home / "protected" / "replaced-credential"),
        ("directory_inheritance", home / "protected" / "created-directory" / "credential"),
    ):
        try:
            label = os.getxattr(path, "security.selinux").decode().rstrip("\x00")
            check(name + "_label", label.split(":")[2] == SECRET)
            check(name + "_read_denied", denied_open(path))
        except OSError as error:
            check(name + "_fixture", False, reason=errno.errorcode.get(error.errno, "UNKNOWN"))
    for name, command in (
        ("direct_native_exec_denied", ["/usr/bin/cat", str(target)]),
        ("copied_native_exec_denied", [str(home / "unknown-cat"), str(target)]),
        ("shell_child_denied", ["/bin/bash", "--noprofile", "--norc", "-c", 'cat "$1"', "probe", str(target)]),
        ("interpreter_child_denied", ["/usr/bin/python3", "-c", "import sys; open(sys.argv[1], 'rb').read(1)", str(target)]),
        ("resource_relabel_denied", ["/usr/bin/chcon", "-t", "user_home_t", str(target)]),
        ("grant_context_transition_denied", ["/usr/bin/runcon", "-r", "greyward_guard_owner_r", "-t", "greyward_guard_owner_t", "/usr/bin/cat", str(target)]),
        ("unconfined_transition_denied", ["/usr/bin/runcon", "-u", "unconfined_u", "-r", "unconfined_r", "-t", "unconfined_t", "/usr/bin/cat", str(target)]),
    ):
        if name.endswith("exec_denied") or name in {"shell_child_denied", "interpreter_child_denied"}:
            positive = [part.replace(str(target), str(ordinary)) for part in command]
            result = subprocess.run(positive, capture_output=True, timeout=10, check=False)
            check(name.removesuffix("_denied") + "_positive_control",
                  result.returncode == 0 and result.stdout in {b"ordinary\n", b""},
                  exit_code=result.returncode)
        try:
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
            check(name, result.returncode != 0 and not result.stdout, exit_code=result.returncode)
        except (OSError, subprocess.TimeoutExpired) as error:
            check(name, False, reason=type(error).__name__)
    for name, path in (
        ("protected_create_denied", home / "protected" / "replacement"),
        ("protected_write_denied", target),
    ):
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError as error:
            check(name, error.errno == errno.EACCES)
        else:
            os.close(descriptor)
            check(name, False)
    owner_path = home / "owner.json"
    if args.route_only:
        pass
    elif owner_path.is_file():
        owner = json.loads(owner_path.read_text())
        check("outside_import_without_relabel_denied", owner["outside_import_denied"])
        check("outside_import_target_absent", not (home / "protected" / "outside-import").exists())
        check("real_owner_agent_loaded_positive_control", owner["agent_loaded"])
        agent_result = subprocess.run(["/usr/bin/ssh-add", "-l"], capture_output=True,
            env={"PATH": "/usr/bin", "HOME": str(home), "LANG": "C",
                 "SSH_AUTH_SOCK": str(home / "owner-agent.sock")}, timeout=3, check=False)
        check("real_owner_agent_access_denied", owner["agent_loaded"] and
              agent_result.returncode == 2 and not agent_result.stdout)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            try:
                client.connect(str(home / "owner.sock"))
            except OSError as error:
                check("same_uid_owner_socket_denied", error.errno in {errno.EACCES, errno.EPERM})
            else:
                check("same_uid_owner_socket_denied", False)
        check("same_uid_proc_descriptor_denied", denied_open(
            Path(f"/proc/{owner['pid']}/fd/{owner['descriptor']}")))

        class IOVec(ctypes.Structure):
            _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]

        libc = ctypes.CDLL(None, use_errno=True)
        buffer = ctypes.create_string_buffer(1)
        local = IOVec(ctypes.addressof(buffer), 1)
        remote = IOVec(owner["address"], 1)
        libc.process_vm_readv.argtypes = [ctypes.c_int, ctypes.POINTER(IOVec),
            ctypes.c_ulong, ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.c_ulong]
        libc.process_vm_readv.restype = ctypes.c_ssize_t
        result = libc.process_vm_readv(owner["pid"], ctypes.byref(local), 1,
                                      ctypes.byref(remote), 1, 0)
        check("same_uid_process_memory_denied", result == -1 and
              ctypes.get_errno() in {errno.EACCES, errno.EPERM})
        libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        libc.ptrace.restype = ctypes.c_long
        result = libc.ptrace(0x4206, owner["pid"], None, None)  # PTRACE_SEIZE: no stop.
        check("same_uid_ptrace_denied", result == -1 and
              ctypes.get_errno() in {errno.EACCES, errno.EPERM})
        try:
            os.kill(owner["pid"], signal.SIGCONT)
        except OSError as error:
            check("same_uid_owner_signal_denied", error.errno in {errno.EACCES, errno.EPERM})
        else:
            check("same_uid_owner_signal_denied", False)
    else:
        check("same_uid_owner_fixture_available", False)
    passed = all(item["passed"] for item in results)
    print(json.dumps({"schema": "greyward.application-security.probe/v1", "passed": passed,
                      "namespace_root": namespace_root,
                      "scope": "synthetic-confined-route" if args.route_only else
                               "synthetic-namespace-root-subject" if namespace_root else
                               "synthetic-resource-confined-subject", "results": results}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(run())
