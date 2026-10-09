#!/usr/bin/python3
"""Compile the admitted ordinary role closure from the installed Fedora policy.

Root packaging/admission input, never a user policy or a coverage receipt.
The role closure must be revalidated after every policy update.
"""
import argparse
import hashlib
import json
from pathlib import Path
import setools


def role_domains(policy):
    domains = sorted(str(t) for t in policy.lookup_role("greyward_guard_r").types()
                     if any(str(a) == "domain" for a in t.attributes()))
    if "greyward_guard_t" not in domains or len(domains) > 256:
        raise ValueError("Invalid ordinary role closure")
    forbidden = {"unconfined_t", "init_t", "sshd_t", "greyward_as_auth_t"}
    if forbidden.intersection(domains):
        raise ValueError("Privileged domain admitted to ordinary role")
    return domains


def assemble(policy, output):
    domains = role_domains(policy)
    ordinary = [t for t in domains if t != "greyward_as_display_t"]
    lines = ["(typeattribute greyward_as_ordinary)",
             "(typeattributeset greyward_as_ordinary (" + " ".join(ordinary) + "))"]
    for target in ["greyward_as_auth_t", "greyward_as_display_t"]:
        for cls, rights in {
            "process": "ptrace signal sigkill sigstop transition dyntransition",
            "file": "read write append",
            "fd": "use", "fifo_file": "open read write append",
        }.items():
            if target == 'greyward_as_display_t' and cls == 'fd':
                continue  # required, content-typed read-only Wayland keymap handoff
            lines.append(f"(deny greyward_as_ordinary {target} ({cls} ({rights})))")
            lines.append(f"(neverallow greyward_as_ordinary {target} ({cls} ({rights})))")
    for target, cls, rights in [
        ("greyward_as_auth_t", "unix_stream_socket", "connectto"),
        ("greyward_as_auth_runtime_t", "dir", "open read write add_name remove_name"),
        ("greyward_as_auth_runtime_t", "file", "open read write append execute"),
        ("greyward_as_auth_runtime_t", "sock_file", "open read write"),
        ("greyward_as_auth_exec_t", "file", "execute entrypoint"),
        ("greyward_as_display_exec_t", "file", "execute entrypoint"),
        ("event_device_t", "chr_file", "open read write ioctl"),
        ("mouse_device_t", "chr_file", "open read write ioctl"),
        ("console_device_t", "chr_file", "open read write ioctl"),
        ("greyward_as_seat_tty_t", "chr_file", "open read write ioctl"),
        ("sudo_exec_t", "file", "execute entrypoint"),
    ]:
        lines.append(f"(deny greyward_as_ordinary {target} ({cls} ({rights})))")
        lines.append(f"(neverallow greyward_as_ordinary {target} ({cls} ({rights})))")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    data = ("\n".join(lines) + "\n").encode()
    (output / "ordinary.cil").write_bytes(data)
    (output / "ordinary.json").write_text(json.dumps({
        "schema": "greyward.ordinary-role/v1", "domains": domains,
        "ordinary": ordinary, "sha256": hashlib.sha256(data).hexdigest(),
    }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assemble(setools.SELinuxPolicy(), args.output)
