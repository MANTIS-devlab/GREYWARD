#!/usr/bin/python3 -I
"""Explicit root/private-namespace administrator fixture; never a recovery route.

Uses an existing disposable test account and its root-private fixture password.
No real protected file is read. Does not change mappings, passwords or policy.
"""
import ctypes
import json
import os
from pathlib import Path
import pty
import pwd
import re
import select
import signal
import sys
import termios
import time

CONTEXT = b'greyward_admin_u:greyward_admin_r:greyward_admin_t:s0'
BASE = Path('/var/tmp/greyward-administration-20261009')

def main(uid, mode='normal'):
    if os.getuid() or os.geteuid() or uid < 1000 or uid == 1001:
        raise RuntimeError('Separate root/private test account required')
    if Path('/proc/self/ns/mnt').stat().st_ino == Path('/proc/1/ns/mnt').stat().st_ino:
        raise RuntimeError('PID 1 private mount namespace required')
    account = pwd.getpwuid(uid)
    password = (BASE/'fixture-password').read_bytes().strip()
    pts = BASE/'fixture-pts'; pts.mkdir(mode=0o700, exist_ok=True)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(b'devpts',os.fsencode(pts),b'devpts',0,b'newinstance,ptmxmode=0666,mode=0620') or libc.mount(os.fsencode(pts),b'/dev/pts',None,4096,None) or libc.mount(os.fsencode(pts/'ptmx'),b'/dev/ptmx',None,4096,None):
        raise RuntimeError('Private devpts fixture failed')
    request = BASE/'fixture-request'
    request.write_bytes(b'-i\0')
    request.chmod(0o600)
    os.setxattr(request,'security.selinux',b'system_u:object_r:greyward_admin_runtime_t:s0')
    fd = os.open(request,os.O_RDONLY)
    child, master = pty.fork()
    if not child:
        # The real graphical terminal creates this PTY after entering its
        # domain. The root-owned fixture must reproduce that label explicitly.
        os.setxattr(0, 'security.selinux', b'system_u:object_r:greyward_admin_devpts_t:s0')
        os.dup2(fd,3,inheritable=True)
        os.initgroups(account.pw_name,account.pw_gid); os.setgid(account.pw_gid)
        if ctypes.CDLL('libselinux.so.1').setexeccon(CONTEXT):os._exit(125)
        os.setuid(uid)
        os.execve('/usr/lib/greyward/application-security/administration/terminal', ['terminal','--console'],
                  {'PATH':'/usr/bin:/usr/sbin:/bin','HOME':str(BASE),'USER':account.pw_name,'LOGNAME':account.pw_name,'LANG':'C.UTF-8','TERM':'xterm-256color'})
    os.close(fd)
    buffer = b''; submitted = False; commands = False
    deadline = time.monotonic()+20
    try:
        while time.monotonic() < deadline:
            if not select.select([master],[],[],.2)[0]:continue
            try:data=os.read(master,8192)
            except OSError:break
            if not data:break
            buffer += data
            if not submitted and b'password for' in buffer.lower():
                if termios.tcgetattr(master)[3] & termios.ECHO:
                    raise RuntimeError('Password echo not disabled')
                if mode=='interrupted':os.kill(child,signal.SIGURG)
                os.write(master,(b'incorrect-private-fixture' if mode=='wrong' else password)+b'\n');submitted=True;buffer=b''
            if mode=='wrong' and submitted and b'Sorry' in buffer:
                os.write(master,b'\x03');time.sleep(.2)
                print(json.dumps({'wrong_password_refused':True,'no_root_command_started':b'ADMIN_UID=0' not in buffer}))
                return
            if submitted and not commands and (b'# ' in buffer or b']#' in buffer):
                os.write(master,b"printf 'ADMIN_UID='; id -u; printf 'ADMIN_CONTEXT='; id -Z; cat /var/tmp/greyward-administration-20261009/fixture-secret; exit\n")
                commands=True;buffer=b''
            if commands and b'Administration.' in buffer:break
        text=buffer.decode(errors='replace')
        if mode=='interrupted':
            if not submitted or commands or 'ADMIN_UID=0' in text:
                raise RuntimeError('Invalidated PAM entered an administrator command')
            print(json.dumps({'pam_invalidation_refuses_elevation':True}))
            return
        passed = 'ADMIN_UID=0' in text and 'sysadm_r:sysadm_t:' in text and 'GREYWARD_SYNTHETIC_SECRET' in text
        print(json.dumps({'fresh_authentication':submitted,'administrator_uid_role_and_synthetic_read':passed}))
        if not passed:
            # No password remains in the post-submit buffer; bound diagnostics.
            print(text[:2400])
            raise RuntimeError('Confined administration fixture failed')
        if mode=='cache':
            def until(marker, timeout=8):
                data=b'';until=time.monotonic()+timeout
                while time.monotonic()<until:
                    if not select.select([master],[],[],.2)[0]:continue
                    chunk=os.read(master,8192)
                    if not chunk:break
                    data+=chunk
                    if marker in data:return data
                raise RuntimeError('Terminal authentication-cache contract failed')
            os.write(master,b'sudo -n /usr/bin/true; echo CACHE_FIRST=$?; sudo -k; sudo -n /usr/bin/true; echo CACHE_RESET=$?\n')
            cache=until(b'\r\nCACHE_RESET=1\r\n')
            if not re.search(rb'CACHE_FIRST=0[\r\n]',cache):
                print(cache.decode(errors='replace')[:1800]);raise RuntimeError('Reviewed terminal cache was not usable')
            os.write(master,b'sudo -v\n');until(b'password for')
            os.write(master,password+b'\n');time.sleep(.2)
            os.write(master,b'sudo /usr/bin/sleep 125; echo ROOT_MAINTENANCE_FINISHED=$?; sudo -n /usr/bin/true; echo CACHE_EXPIRED=$?\n')
            expiry=until(b'\r\nCACHE_EXPIRED=1\r\n',135)
            if not re.search(rb'ROOT_MAINTENANCE_FINISHED=0[\r\n]',expiry):raise RuntimeError('Cache expiry interrupted an elevated command')
            print(json.dumps({'terminal_cache_reuse':True,'sudo_k_invalidation':True,'two_minute_expiry':True,'running_command_survives_expiry':True}))
    finally:
        try:os.kill(child,signal.SIGTERM)
        except ProcessLookupError:pass
        os.close(master)

if __name__ == '__main__':
    main(int(sys.argv[1]),sys.argv[2] if len(sys.argv)>2 else 'normal')
