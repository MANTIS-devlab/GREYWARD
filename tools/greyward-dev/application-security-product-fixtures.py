#!/usr/bin/python3
"""Fixed synthetic payloads for the existing owned-account functional flow."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

BASE = Path('/var/tmp/greyward-application-security-build/product-fixtures')
HOME = Path('/home/greyward-guard-probe')
if len(sys.argv) != 3 or Path(sys.argv[2]) != BASE or sys.argv[1] not in {'prepare','install'}:
    raise SystemExit('Fixed product fixture path required')
if sys.argv[1] == 'prepare':
    if os.getuid() == 0: raise SystemExit('Nonprivileged fixture preparation required')
    BASE.mkdir(mode=0o700, exist_ok=True)
    if BASE.is_symlink() or BASE.stat().st_uid != os.getuid(): raise SystemExit('Unsafe fixture directory')
    app = BASE/'app'; app.mkdir(mode=0o700,exist_ok=True)
    (app/'AppRun').write_text('#!/bin/sh\nprintf "GUARD_PAYLOAD_OK\\n"\n')
    (app/'AppRun').chmod(0o755)
    squash=BASE/'app.squashfs'
    if squash.exists(): squash.unlink()
    subprocess.run(['/usr/bin/mksquashfs',str(app),str(squash),'-noappend','-no-xattrs','-no-progress','-processors','1'],check=True,stdout=subprocess.DEVNULL,timeout=10)
    elf=bytearray(128); elf[:7]=b'\x7fELF\x02\x01\x01'; elf[8:11]=b'AI\x02'
    struct.pack_into('<H',elf,18,62); struct.pack_into('<Q',elf,40,64)
    struct.pack_into('<HH',elf,58,64,1)
    (BASE/'guard-test.AppImage').write_bytes(elf+squash.read_bytes())
    (BASE/'guard-test.py').write_text('#!/usr/bin/python3\nimport os,socket\nassert os.environ["HOME"]=="/work"\nassert not os.path.exists("/run/user")\ntry: socket.socket(socket.AF_INET,socket.SOCK_STREAM)\nexcept PermissionError: pass\nelse: raise RuntimeError("Network unexpectedly available")\nprint("GUARD_PAYLOAD_OK")\n')
    (BASE/'guard-test.sh').write_text('#!/bin/sh\ntest "$HOME" = /work || exit 1\ntest ! -e /run/user || exit 1\nprintf "GUARD_PAYLOAD_OK\\n"\n')
    (BASE/'guard-graphical.py').write_text('''#!/usr/bin/python3
import ctypes,os,socket,subprocess
assert os.environ['HOME']=='/work'
assert not any(os.path.exists(p) for p in ['/run/guard-host-wayland','/run/user','/work/host','/work/config'])
try: socket.socket(socket.AF_INET,socket.SOCK_STREAM)
except PermissionError: pass
else: raise RuntimeError('Network unexpectedly available')
wl=ctypes.CDLL('libwayland-client.so.0')
wl.wl_display_connect.restype=ctypes.c_void_p
wl.wl_display_connect.argtypes=[ctypes.c_char_p]
wl.wl_display_roundtrip.argtypes=[ctypes.c_void_p]
wl.wl_display_disconnect.argtypes=[ctypes.c_void_p]
display=wl.wl_display_connect(None)
assert display and wl.wl_display_roundtrip(display)>=0
wl.wl_display_disconnect(display)
result=subprocess.run(['/usr/bin/zenity','--info','--text=GREYWARD private ISOLATED display fixture','--timeout=1'],timeout=8)
assert result.returncode in (0,5), result.returncode
''')
else:
    if os.getuid()!=0 or HOME.is_symlink() or HOME.stat().st_uid!=1002: raise SystemExit('Owned probe account required')
    for name in ['guard-test.py','guard-test.sh','guard-test.AppImage','guard-graphical.py']:
        target=HOME/name
        if target.is_symlink(): raise SystemExit('Unsafe fixture target')
        shutil.copyfile(BASE/name,target)
        os.chown(target,1002,1002); target.chmod(0o700)
    config=HOME/'appsec-graphical'; config.mkdir(mode=0o700,exist_ok=True)
    if config.is_symlink(): raise SystemExit('Unsafe display fixture')
    for name,contents in {'rc.xml':'<labwc_config/>\n','autostart':'','menu.xml':'<openbox_menu/>\n'}.items():
        target=config/name
        if target.is_symlink(): raise SystemExit('Unsafe display configuration')
        target.write_text(contents); os.chown(target,1002,1002)
    os.chown(config,1002,1002)
    handler=HOME/'appsec-safe-open'
    for directory in [handler,handler/'config',handler/'data',handler/'data'/'applications']:
        if directory.is_symlink(): raise SystemExit('Unsafe handler fixture')
        directory.mkdir(mode=0o700,exist_ok=True); os.chown(directory,1002,1002)
    for target,contents in {
        handler/'config'/'mimeapps.list':'[Default Applications]\ntext/plain=greyward-product-viewer.desktop;\n',
        handler/'data'/'applications'/'greyward-product-viewer.desktop':'[Desktop Entry]\nType=Application\nName=Synthetic shared viewer\nExec=/usr/bin/cat %f\nMimeType=text/plain;\n'
    }.items():
        if target.is_symlink(): raise SystemExit('Unsafe handler configuration')
        target.write_text(contents); target.chmod(0o600); os.chown(target,1002,1002)
    subprocess.run(['/usr/sbin/restorecon','-R',str(handler)],check=True,timeout=10)
    subprocess.run(['/usr/sbin/restorecon','-R',str(config),*[str(HOME/name) for name in ['guard-test.py','guard-test.sh','guard-test.AppImage','guard-graphical.py']]],check=True,timeout=10)
