#!/usr/bin/python3
"""Minimum actual-session regression against the descriptor-registered fixture."""
import errno
import json
import os
from pathlib import Path
import subprocess

HOME=Path('/home/greyward-guard-probe')
SECRET=HOME/'registration-critical'/'synthetic'
def task(args,**kwargs):
    return subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,timeout=kwargs.pop('timeout',10),check=False,**kwargs)
def main():
    if os.getuid()!=1002 or Path.home()!=HOME or SECRET.is_symlink():
        raise RuntimeError('Only the owned synthetic session is supported')
    context=Path('/proc/self/attr/current').read_text().strip('\0\n')
    assert context.split(':')[2]=='greyward_guard_t'
    environment={**os.environ,'XDG_RUNTIME_DIR':'/run/user/1002',
        'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/1002/bus'}
    checks={'session_confined':True,'ordinary_control':(HOME/'ordinary.txt').read_text().strip()=='ordinary'}
    try:
        with SECRET.open('rb') as stream: stream.read(1)
        checks['interpreter_denied']=False
    except OSError as error: checks['interpreter_denied']=error.errno==errno.EACCES
    for name,binary in [('direct_denied','/usr/bin/cat'),('unknown_denied',str(HOME/'unknown-cat'))]:
        checks[name]=task([binary,str(SECRET)]).returncode!=0
    manager=task(['/usr/bin/systemctl','show','user@1002.service','-p','MainPID','--value'])
    pid=int(manager.stdout)
    checks['user_manager_confined']=pid>1 and Path(f'/proc/{pid}/attr/current').read_text().strip('\0\n').split(':')[2]=='greyward_guard_t'
    checks['user_service_denied']=task(['/usr/bin/systemd-run','--user','--quiet','--wait','--pipe','--collect',
        '--unit=greyward-appsec-critical-user-read','-p','RuntimeMaxSec=5','/usr/bin/cat',str(SECRET)],env=environment).returncode!=0
    script='cat "$HOME/ordinary.txt" >/dev/null && test -f "$HOME/registration-critical/synthetic" && ! head -c 1 "$HOME/registration-critical/synthetic" >/dev/null 2>/dev/null'
    flatpak=task(['/usr/bin/flatpak','run','--system','--unshare=network','--no-session-bus','--no-a11y-bus',
        '--nodevice=all','--nosocket=session-bus','--nosocket=system-bus','--nosocket=wayland','--nosocket=x11',
        '--nosocket=fallback-x11','--filesystem=home','--command=sh','com.brave.Browser/x86_64/stable','-c',script],
        env=environment,timeout=15)
    checks['flatpak_ordinary_control_and_protected_denial']=flatpak.returncode==0
    sid=task(['/usr/bin/loginctl','show-session','self','-p','Id','--value'],env=environment).stdout.decode().strip()
    assert sid
    environment.update(WLR_BACKENDS='headless',WLR_HEADLESS_OUTPUTS='1',WLR_RENDERER='pixman',
        QT_QUICK_BACKEND='software',XDG_SEAT='greyward-headless-probe',XDG_SESSION_ID=sid)
    receipt=HOME/'critical-shell.json'
    if receipt.is_symlink(): raise RuntimeError('Unsafe private shell receipt')
    receipt.unlink(missing_ok=True)
    display=task(['/usr/bin/timeout','40s','/usr/bin/uwsm','start','-F','-e','-D','GREYWARD:labwc','--',
        '/usr/bin/labwc','-s','/usr/local/libexec/greyward-application-security-critical-headless.sh'],env=environment,timeout=45)
    checks['dms_labwc_startup']=display.returncode==0 and receipt.exists() and json.loads(receipt.read_text()).get('state')=='READY'
    passed=all(checks.values())
    print(json.dumps({'schema':'greyward.application-security.critical-session/v1','passed':passed,
        'checks':checks,'coverage':'UNKNOWN'},sort_keys=True))
    return 0 if passed else 1
if __name__=='__main__':
    raise SystemExit(main())
