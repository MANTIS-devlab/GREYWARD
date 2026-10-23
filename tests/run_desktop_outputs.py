#!/usr/bin/env python3
"""Link the real PCManFM objects and test in a private headless Wayland seat.

Requires a completed patched native CMake build, Labwc, wlr-randr and D-Bus.
Never connects to an existing session, display or application bus.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time


def run(build, source, work):
    build, source, work = map(lambda p: Path(p).resolve(), (build, source, work))
    work.mkdir(mode=0o700, exist_ok=False)
    header = (build / 'pcmanfm/pcmanfm-qt').read_bytes()[:18]
    if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[16:18], 'little') != 3:
        raise RuntimeError('Expected the production x86_64 PIE executable, not a non-PIE native build')
    target = build / 'pcmanfm/CMakeFiles/pcmanfm-qt.dir'
    definitions = {}
    for line in (target / 'flags.make').read_text().splitlines():
        key, separator, value = line.partition(' = ')
        if separator:
            definitions[key] = shlex.split(value)
    driver = Path(__file__).with_name('test_desktop_outputs.cpp').resolve()
    # Preserve the target's visibility/standard flags so Qt signal templates
    # cannot interpose different inline definitions. Exceptions are test-only.
    subprocess.run(['/usr/bin/g++', *definitions['CXX_FLAGS'], '-fexceptions',
                    *definitions['CXX_DEFINES'], *definitions['CXX_INCLUDES'],
                    '-I' + str(source / 'pcmanfm'), '-c', str(driver),
                    '-o', str(work / 'driver.o')], check=True, timeout=180)
    link = shlex.split((target / 'link.txt').read_text())
    original = [i for i, item in enumerate(link) if item.endswith('/pcmanfm.cpp.o')]
    if len(original) != 1 or link.count('-o') != 1:
        raise RuntimeError('Expected the real single-main native link description')
    link[original[0]] = str(work / 'driver.o')
    executable = work / 'desktop-output-test'
    link[link.index('-o') + 1] = str(executable)
    subprocess.run(link, cwd=build / 'pcmanfm', check=True, timeout=90)

    home = work / 'home'
    runtime_directory = tempfile.TemporaryDirectory(prefix='greyward-desktop-test-')
    runtime = Path(runtime_directory.name)
    config = home / '.config'
    profile = config / 'pcmanfm-qt/greyward-test'
    desktop = home / 'Desktop'
    labwc = config / 'labwc'
    for directory in [runtime, profile, desktop, labwc, home / '.cache', home / '.local/share']:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    (config / 'user-dirs.dirs').write_text('XDG_DESKTOP_DIR="' + str(desktop) + '"\n')
    for name in ['alpha', 'beta', 'gamma']:
        (desktop / (name + '.txt')).write_text('synthetic ' + name + '\n')
    (profile / 'settings.conf').write_text('''[Desktop]
DesktopShortcuts=
WallpaperMode=color
BgColor=#101214
FgColor=#e2e5e7
WorkAreaMargins=20,20,20,20
[Volume]
MountOnStartup=false
MountRemovable=false
AutoRun=false
''')
    (desktop / 'folder ; $(literal)').mkdir()
    (labwc / 'rc.xml').write_text('<labwc_config/>\n')
    (labwc / 'autostart').write_text('#!/bin/sh\nexit 0\n')
    (labwc / 'autostart').chmod(0o700)
    # No service directories: test-only D-Bus must not activate host portal or
    # GVfs agents (and their FUSE mounts) as a side effect of a Qt/GIO probe.
    bus_config = work / 'session-bus.conf'
    bus_config.write_text('<busconfig><type>session</type>'
        + '<listen>unix:tmpdir=' + str(runtime) + '</listen><auth>EXTERNAL</auth>'
        + '<policy context="default"><allow own="*"/><allow send_destination="*"/>'
        + '<allow receive_sender="*"/></policy></busconfig>\n')
    result = work / 'exit-code'
    launch = work / 'launch.py'
    launch.write_text('import subprocess\nfrom pathlib import Path\n'
        + 'code=subprocess.run(' + repr([str(executable), '--desktop', '--profile=greyward-test']) + ').returncode\n'
        + 'Path(' + repr(str(result)) + ').write_text(str(code))\n')
    environment = {key: value for key, value in os.environ.items()
                   if key not in ['WAYLAND_DISPLAY', 'DISPLAY', 'DBUS_SESSION_BUS_ADDRESS',
                                  'QT_PLUGIN_PATH', 'QT_STYLE_OVERRIDE', 'QT_QPA_PLATFORMTHEME']}
    environment.update(HOME=str(home), XDG_CONFIG_HOME=str(config), XDG_CACHE_HOME=str(home / '.cache'),
        XDG_DATA_HOME=str(home / '.local/share'), XDG_RUNTIME_DIR=str(runtime),
        XDG_SESSION_TYPE='wayland', WLR_BACKENDS='headless', WLR_HEADLESS_OUTPUTS='3',
        WLR_RENDERER='pixman', WLR_LIBINPUT_NO_DEVICES='1', QT_QPA_PLATFORM='wayland',
        LIBGL_ALWAYS_SOFTWARE='1', QT_FORCE_STDERR_LOGGING='1', GIO_USE_VFS='local', GIO_USE_VOLUME_MONITOR='unix',
        GREYWARD_SYNTHETIC_DESKTOP_TEST='three-headless-outputs')
    with (work / 'headless.log').open('wb') as log:
        process = subprocess.Popen(['/usr/bin/dbus-run-session', '--config-file', str(bus_config), '--', '/usr/bin/labwc',
            '--config-dir', str(labwc), '--startup', '/usr/bin/python3 ' + shlex.quote(str(launch))],
            env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 65
            while time.monotonic() < deadline and not result.exists() and process.poll() is None:
                time.sleep(0.1)
            if not result.exists():
                raise RuntimeError('Private headless driver failed or timed out; inspect headless.log')
            code = int(result.read_text())
            output = (work / 'headless.log').read_text(errors='replace')
            print(output)
            if 'signal not found' in output:
                raise RuntimeError('Native Qt signal connection failed; reject this build')
            if code:
                raise RuntimeError('Desktop output integration failed: ' + str(code))
        finally:
            if process.poll() is None and os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            runtime_directory.cleanup()
    (work / 'result.json').write_text(json.dumps({'passed': True,
        'scope': 'private headless three-output native integration; no physical hardware claim'}) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    run(args.build, args.source, args.work)
