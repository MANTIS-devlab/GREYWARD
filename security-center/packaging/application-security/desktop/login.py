#!/usr/bin/python3 -I
"""Fixed session selection; enrollment admission remains broker/kernel-bound."""
import ctypes, os, stat
from pathlib import Path
def detach_console(runtime, uid):
    """Detach ordinary startup from the authentication seat before admission."""
    meta=runtime.lstat()
    if runtime.is_symlink() or meta.st_uid!=uid or not stat.S_ISDIR(meta.st_mode):
        raise RuntimeError('Invalid user runtime')
    log=os.open(runtime/'greyward-desktop-start.log',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    meta=os.fstat(log)
    if meta.st_uid!=uid or meta.st_nlink!=1 or not stat.S_ISREG(meta.st_mode):
        os.close(log)
        raise RuntimeError('Invalid startup log')
    os.fchmod(log,0o600);os.ftruncate(log,0)
    null=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
    os.dup2(null,0);os.dup2(log,1);os.dup2(log,2)
    os.close(null);os.close(log)


def main():
    uid=os.getuid()
    start(uid)


def start(uid):
    seuser=ctypes.c_char_p(); serange=ctypes.c_char_p()
    import pwd
    name=pwd.getpwuid(uid).pw_name
    if ctypes.CDLL('libselinux.so.1').getseuserbyname(name.encode(),ctypes.byref(seuser),ctypes.byref(serange)):
        raise RuntimeError('Session mapping unavailable')
    if seuser.value==b'greyward_guard_u':
        # Admission protects tty1; ordinary startup cannot retain console IO.
        detach_console(Path('/run/user')/str(uid),uid)
        os.execv('/usr/bin/greyward-guard',['greyward-guard','desktop-session'])
    else:
        os.execv('/usr/local/libexec/greyward-start-labwc',['greyward-start-labwc'])


if __name__=='__main__':
    main()
