#!/usr/bin/env python3
"""Opt-in: run INSIDE Bazaar Flatpak with --helper PATH, never on user state.

Uses private session buses, a Unix-socket-only GTK Broadway display and
disposable cache/config/data directories. It requires gtk4-broadwayd and network
access for the patched case. No app installation, host-policy
change or active-instance restart is performed. This is not an ISO acceptance.
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import shutil
import subprocess
import sys
import tempfile
import time

from gi.repository import GLib


@contextmanager
def private_display(env):
    # Preserve the Flatpak runtime namespace (including its certificate broker).
    # Use a unique Broadway display and a private Unix HTTP socket, never the
    # real compositor or a TCP listener.
    with tempfile.TemporaryDirectory(prefix="gw-bz-") as temporary:
        runtime = Path(GLib.get_user_runtime_dir())
        prior_sockets = set(runtime.glob("broadway*.socket"))
        display = ":" + str(1000 + secrets.randbelow(50000))
        env = {**env, "GDK_BACKEND": "broadway", "BROADWAY_DISPLAY": display}
        backend = subprocess.Popen(
            ["gtk4-broadwayd", "--unixsocket=" + str(Path(temporary) / "http.sock"), display],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not (set(runtime.glob("broadway*.socket")) - prior_sockets):
                if backend.poll() is not None:
                    raise AssertionError("private display failed: " + backend.communicate()[0])
                if time.monotonic() >= deadline:
                    raise AssertionError("private display socket did not become ready")
                time.sleep(0.05)
            yield env
        finally:
            backend.terminate()
            try:
                backend.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                backend.kill()
                backend.communicate()


def cache_state(path):
    if not path.is_file():
        return None
    raw = path.read_bytes()
    value = GLib.Variant.new_from_bytes(
        GLib.VariantType.new("a{sv}"), GLib.Bytes.new(raw), False
    )
    assert value.is_normal_form(), "invalid serialized Explore state"
    state = value.unpack()
    return {"date": state["for-day"], "categories": len(state["categories"]),
            "sha256": hashlib.sha256(raw).hexdigest()}


def run_case(root, helper, name, seed=None):
    case = root / name
    for subdir in ("cache", "config", "data"):
        (case / subdir).mkdir(parents=True, mode=0o700)
    cache = case / "cache/io.github.kolunmi.Bazaar/core/flathub-cache"
    if seed is not None:
        # Preserve Bazaar's cache-version marker and related metadata as well
        # as Explore. Copying only Explore makes upstream discard the cache
        # as incompatible, independently of the GREYWARD startup check.
        shutil.copytree(seed, case / "cache", dirs_exist_ok=True)
    env = {**os.environ, "XDG_CACHE_HOME": str(case / "cache"),
           "XDG_CONFIG_HOME": str(case / "config"), "XDG_DATA_HOME": str(case / "data"),
           "GSETTINGS_BACKEND": "keyfile", "G_MESSAGES_DEBUG": "BAZAAR::FLATHUB"}
    # The preflight and the real application share only this scratch backend.
    child = """import os,subprocess,sys,time
subprocess.run(['gsettings','set','io.github.kolunmi.Bazaar','last-refresh-time',str(int(time.time()))],check=True)
if sys.argv[1] == '-':
    os.execvp('bazaar-daemon',['bazaar-daemon','--no-window-refresh'])
os.execvp('sh',['sh',sys.argv[1],'--no-window-refresh'])
"""
    started = time.monotonic()
    with private_display(env) as env:
        process = subprocess.Popen(
            ["dbus-run-session", "--", "python3", "-c", child, str(helper) if helper else "-"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True,
        )
        try:
            log = process.communicate(timeout=40)[0]
        except subprocess.TimeoutExpired:
            # Only the new test process group, never the user's Bazaar/desktop.
            os.killpg(process.pid, signal.SIGTERM)
            log = process.communicate(timeout=5)[0]
            raise AssertionError(f"scratch case timed out: {name}\n{log[-4000:]}")
    assert process.returncode == 0, log[-4000:]
    state = cache_state(cache)
    result = {"case": name, "seconds": round(time.monotonic() - started, 3),
              "sync_started": "Syncing with flathub for day:" in log,
              "sync_done": "Done syncing flathub state" in log, "state": state}
    print(json.dumps(result), flush=True)
    if name == "after" and not result["sync_done"]:
        print(log[-7000:], file=sys.stderr, flush=True)
    return result, cache.read_bytes() if cache.exists() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    args = parser.parse_args()
    helper = args.helper.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="greyward-explore-native-",
                                     dir=GLib.get_user_cache_dir()) as temporary:
        root = Path(temporary)
        before, _ = run_case(root, None, "before")
        assert not before["sync_started"] and before["state"] is None, before
        after, saved = run_case(root, helper, "after")
        assert after["sync_done"] and after["state"]["categories"] > 0, after
        warm, unchanged = run_case(root, helper, "warm", root / "after/cache")
        assert not warm["sync_started"] and unchanged == saved, warm
    print("BAZAAR_EXPLORE_NATIVE=PASS", flush=True)


if __name__ == "__main__":
    main()
