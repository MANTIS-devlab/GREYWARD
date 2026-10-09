#!/usr/bin/python3
"""Bounded negative first-use experiment on the installed enrolled desktop.

No authorization, policy installation, grant, override or service changes.
The optional standard FileChooser request is closed by its own connection.
Directory enumeration is attempted, never protected-file content reads.
This is a prerequisite probe, not a positive grant/GUI acceptance receipt.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import time

BUS = "systems.mantis.greyward.ApplicationSecurity1"
OBJECT = "/systems/mantis/greyward/ApplicationSecurity1"
SCHEMA = "greyward.application-security.first-use-proof/v1"


def run(arguments, timeout=15):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout,
                            env={**os.environ, "LC_ALL": "C"})
    if len(result.stdout) + len(result.stderr) > 256 * 1024:
        raise RuntimeError("Probe response exceeded budget")
    return result


def broker(method, signature=None, *arguments):
    command = ["/usr/bin/busctl", "--system", "call", BUS, OBJECT, BUS, method]
    if signature:
        command += [signature, *map(str, arguments)]
    result = run(command)
    result.check_returncode()
    raw = result.stdout.decode().strip()
    if not raw.startswith('s "'):
        raise RuntimeError("Unexpected broker reply")
    value = json.loads(json.loads(raw[2:]))
    if value.get("schema") != "greyward.application-security/v1":
        raise RuntimeError("Unexpected broker schema")
    return value


def new_events(value, cursor, resource):
    if value.get("source_state") != "AVAILABLE":
        raise RuntimeError("Root audit source unavailable")
    return [item for item in value["events"]
            if item["sequence"] > cursor and item["resource_ref"] == resource]


def portal_request(folder):
    """Use the stock FileChooser on one maintained connection; no file selection."""
    gio = ctypes.CDLL("libgio-2.0.so.0")
    glib = ctypes.CDLL("libglib-2.0.so.0")
    obj = ctypes.CDLL("libgobject-2.0.so.0")
    pointer = ctypes.c_void_p
    gio.g_bus_get_sync.argtypes = [ctypes.c_int, pointer, pointer]
    gio.g_bus_get_sync.restype = pointer
    glib.g_variant_parse.argtypes = [pointer, ctypes.c_char_p, pointer, pointer, pointer]
    glib.g_variant_parse.restype = pointer
    glib.g_variant_ref_sink.argtypes = [pointer]
    glib.g_variant_ref_sink.restype = pointer
    glib.g_variant_unref.argtypes = [pointer]
    glib.g_variant_get_child_value.argtypes = [pointer, ctypes.c_size_t]
    glib.g_variant_get_child_value.restype = pointer
    glib.g_variant_get_string.argtypes = [pointer, pointer]
    glib.g_variant_get_string.restype = ctypes.c_char_p
    gio.g_dbus_connection_call_sync.argtypes = [pointer, ctypes.c_char_p,
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, pointer, pointer,
        ctypes.c_int, ctypes.c_int, pointer, pointer]
    gio.g_dbus_connection_call_sync.restype = pointer
    obj.g_object_unref.argtypes = [pointer]
    connection = gio.g_bus_get_sync(2, None, None)
    if not connection:
        raise RuntimeError("Session portal connection unavailable")

    def call(path, interface, method, parameters=None):
        variant = None
        if parameters:
            variant = glib.g_variant_parse(None, parameters.encode(), None, None, None)
            if not variant:
                raise RuntimeError("Invalid fixed portal arguments")
            glib.g_variant_ref_sink(variant)
        try:
            answer = gio.g_dbus_connection_call_sync(connection,
                b"org.freedesktop.portal.Desktop", path.encode(), interface.encode(),
                method.encode(), variant, None, 0, 5000, None, None)
            if not answer:
                raise RuntimeError("Portal call failed")
            return answer
        finally:
            if variant:
                glib.g_variant_unref(variant)

    handle = None
    try:
        encoded = ", ".join(f"byte 0x{byte:02x}" for byte in os.fsencode(folder) + b"\0")
        token = "greyward_probe_" + os.urandom(8).hex()
        parameters = ("('', 'GREYWARD first-use technical check', "
                      "{'handle_token': <'" + token + "'>, 'current_folder': <[" +
                      encoded + "]>, 'modal': <false>})")
        answer = call("/org/freedesktop/portal/desktop",
                      "org.freedesktop.portal.FileChooser", "OpenFile", parameters)
        try:
            child = glib.g_variant_get_child_value(answer, 0)
            try:
                handle = glib.g_variant_get_string(child, None).decode()
            finally:
                glib.g_variant_unref(child)
        finally:
            glib.g_variant_unref(answer)
        time.sleep(4)
    finally:
        if handle:
            answer = call(handle, "org.freedesktop.portal.Request", "Close")
            glib.g_variant_unref(answer)
        obj.g_object_unref(connection)
    print(json.dumps({"stock_portal_requested": True, "own_request_closed": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--registered-folder", required=True)
    parser.add_argument("--portal", action="store_true",
                        help="Briefly show/close only the probe's ordinary FileChooser")
    args = parser.parse_args()
    if os.getuid() == 0 or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}", args.app):
        raise RuntimeError("An enrolled non-root account and installed Flatpak ID are required")
    if run(["/usr/sbin/getenforce"]).stdout.strip() != b"Enforcing":
        raise RuntimeError("SELinux must remain Enforcing")
    folder = Path(args.registered_folder)
    if not folder.is_absolute() or folder.is_symlink() or folder.stat().st_uid != os.getuid():
        raise RuntimeError("Owned registered directory required")
    label = os.getxattr(folder, "security.selinux").decode().strip("\0").split(":")[2]
    match = re.fullmatch(r"greyward_as_resource_([0-9a-f]{64})_t", label)
    if not match:
        raise RuntimeError("Folder has no generated resource label")
    resource = "resource_" + match[1]
    registered = broker("GetProtectedResource", "s", resource)["resource"]
    if registered["owner_uid"] != os.getuid() or registered["coverage"] != "PROTECTED":
        raise RuntimeError("Broker does not verify this resource label")

    info = run(["/usr/bin/flatpak", "info", "--system", "--show-commit", args.app])
    info.check_returncode()
    prefix = ["/usr/bin/flatpak", "run", "--system"]
    native = run(["/usr/bin/ls", str(folder)])
    native_denied = native.returncode != 0 and b"Permission denied" in native.stderr
    if not native_denied:
        raise RuntimeError("Ordinary native directory denial was not demonstrated")
    before = broker("ReadSecurityEvents", "tu", 0, 100)["cursor"]
    invisible = run([*prefix, "--command=/usr/bin/ls", args.app, "-d", str(folder)])
    absent_events = new_events(broker("ReadSecurityEvents", "tu", before, 100), before, resource)
    exposed = run([*prefix, f"--filesystem={folder}:ro", "--command=/usr/bin/ls",
                   args.app, str(folder)])
    after = broker("ReadSecurityEvents", "tu", before, 100)
    events = new_events(after, before, resource)
    exposed_denied = exposed.returncode != 0 and b"Permission denied" in exposed.stderr
    if not exposed_denied or not events:
        raise RuntimeError("Flatpak denial and corresponding root evidence were not demonstrated")
    report = {"schema": SCHEMA, "application": args.app,
              "deployment": info.stdout.decode().strip(),
              "native_directory_denied": native_denied,
              "namespace_hidden": invisible.returncode != 0 and b"No such file" in invisible.stderr,
              "default_attempt_resource_events": len(absent_events),
              "exposed_folder_denied": exposed_denied,
              "denial_events": [{key: item.get(key) for key in
                                ("action", "attribution", "process", "policy_revision")}
                               for item in events],
              "gate_a": "NOT DEMONSTRATED", "gate_b": "NOT DEMONSTRATED",
              "authorization_performed": False, "policy_changed": False,
              "persistent_overrides_changed": False}
    if args.portal:
        portal_before = after["cursor"]
        script = Path(__file__).read_text().split('\nif __name__ == "__main__":', 1)[0]
        child = subprocess.run([*prefix, "--command=/usr/bin/python3", args.app, "-c",
                                script + "\nportal_request(" + repr(str(folder)) + ")"],
                               capture_output=True, timeout=15,
                               env={**os.environ, "LC_ALL": "C"})
        # Only the portal helper executes inside the Flatpak, not the host CLI.
        report["portal_result"] = {"exit": child.returncode,
                                   "output": child.stdout.decode()[:512],
                                   "error": child.stderr.decode()[:512]}
        report["portal_resource_events"] = [{key: item.get(key) for key in
                                            ("action", "attribution", "process")}
                                           for item in new_events(broker("ReadSecurityEvents", "tu",
                                               portal_before, 100), portal_before, resource)]
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
