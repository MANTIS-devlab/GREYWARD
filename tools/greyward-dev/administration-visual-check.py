"""Separate-account private display check. Never sends keys to the real desktop."""
import os,ctypes,subprocess,time,select,signal,json,socket,array,sys
from pathlib import Path
B=Path('/run/greyward-admin-visual-test')
A=Path('/usr/lib/greyward/application-security/administration')
assert os.getuid()==0 and Path('/proc/self/ns/mnt').stat().st_ino!=Path('/proc/1/ns/mnt').stat().st_ino
uid=1003
lib=ctypes.CDLL(None,use_errno=True)
pts=B/'pts';pts.mkdir(mode=0o700,exist_ok=True)
assert not lib.mount(b'devpts',os.fsencode(pts),b'devpts',0,b'newinstance,ptmxmode=0666,mode=0620')
os.setxattr(pts/'ptmx','security.selinux',b'system_u:object_r:greyward_admin_devpts_t:s0')
assert not lib.mount(os.fsencode(pts),b'/dev/pts',None,4096,None)
assert not lib.mount(os.fsencode(pts/'ptmx'),b'/dev/ptmx',None,4096,None)
def enter(context):
 def invoke():
  os.setgroups([]);os.setgid(uid)
  assert not ctypes.CDLL('libselinux.so.1').setexeccon(context.encode())
  os.setuid(uid)
 return invoke
D='greyward_guard_u:greyward_guard_r:greyward_as_display_t:s0'
C='greyward_admin_u:greyward_admin_r:greyward_admin_t:s0'
H='system_u:system_r:greyward_as_auth_t:s0'
env={'PATH':'/usr/bin:/usr/sbin','HOME':str(B/'config'),'XDG_RUNTIME_DIR':str(B/'runtime'),'WLR_BACKENDS':'headless','WLR_HEADLESS_OUTPUTS':'1','WLR_RENDERER':'pixman','LANG':'C.UTF-8'}
log=(B/'display.log').open('wb')
started=time.time_ns()
display=subprocess.Popen([str(Path('/var/tmp/greyward-administration-20261009/labwc')),'-C',str(B/'config')],env=env,preexec_fn=enter(D),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
child=None
keymap=-1
try:
 for i in range(50):
  path=B/'runtime/wayland-0'
  if path.exists() and path.stat().st_mtime_ns>=started:break
  if display.poll()!=None:raise RuntimeError('Display failed '+display.stderr.read(1800).decode())
  time.sleep(.1)
 else:raise RuntimeError('Fresh fixture display socket missing')
 env['WAYLAND_DISPLAY']=str(B/'runtime/wayland-0')
 helper='/var/tmp/greyward-administration-20261009/private-input'
 left,right=socket.socketpair()
 generated=subprocess.Popen([helper,'--root-keymap'],env={**env,'GREYWARD_ROOT_TEST_SOCKET_FD':str(right.fileno())},pass_fds=(right.fileno(),))
 right.close()
 _,ancillary,_,_=left.recvmsg(1,socket.CMSG_SPACE(4));left.close()
 handles=array.array('i');handles.frombytes(ancillary[0][2]);keymap=handles[0]
 generated.wait(timeout=3)
 os.setxattr(keymap,'security.selinux',b'system_u:object_r:greyward_as_display_shm_t:s0')
 readonly=os.open(f'/proc/self/fd/{keymap}',os.O_RDONLY);os.close(keymap);keymap=readonly
 def keys(*arguments):
  trace=B/'input.log'
  with trace.open('wb') as log:
   os.fchmod(log.fileno(),0o600);os.setxattr(log.fileno(),'security.selinux',b'system_u:object_r:greyward_as_auth_runtime_t:s0')
   result=subprocess.run([helper,*arguments],env={**env,'GREYWARD_ROOT_TEST_KEYMAP_FD':str(keymap)},pass_fds=(keymap,),preexec_fn=enter(H),stdout=log,stderr=log,timeout=3)
  if result.returncode:raise RuntimeError('Private input failed '+str(result.returncode)+' display='+str(display.poll())+' '+trace.read_text()[:400])
 def capture(name):
  result=subprocess.run([str(Path('/var/tmp/greyward-administration-20261009/grim')),str(B/'auth'/name)],env=env,preexec_fn=enter(H),capture_output=True,timeout=3)
  if result.returncode:raise RuntimeError('Capture failed '+result.stderr.decode()[:300])
 keys('-M','ctrl','-M','alt','-k','F12','-m','alt','-m','ctrl');time.sleep(.2)
 capture('ordinary-indicator.png')
 request=B/'request';request.write_bytes(b'-i\0');request.chmod(0o600)
 os.setxattr(request,'security.selinux',b'system_u:object_r:greyward_admin_runtime_t:s0')
 descriptor=os.open(request,os.O_RDONLY);r,w=os.pipe()
 def admission():
  os.dup2(descriptor,3,inheritable=True);os.dup2(w,4,inheritable=True);enter(C)()
 env.update({'WAYLAND_DISPLAY':str(B/'runtime/wayland-0'),'FONTCONFIG_FILE':str(A/'fonts.conf')})
 with (B/'terminal.log').open('wb') as log:
  child=subprocess.Popen([str(A/'terminal')],env=env,preexec_fn=admission,pass_fds=tuple(sorted({descriptor,w,3,4})),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 os.close(descriptor);os.close(w)
 def ack(expected):
  until=time.monotonic()+5;buffer=b''
  while time.monotonic()<until:
   if select.select([r],[],[],.2)[0]:
    chunk=os.read(r,128)
    if not chunk:break
    buffer+=chunk
    if expected+b'\n' in buffer:return True
  raise RuntimeError('Terminal readiness failed '+repr(buffer)+' poll='+str(child.poll())+' error='+(child.stderr.read(2000).decode() if child.poll()!=None else 'running'))
 ack(b'READY');time.sleep(.6)
 capture('review-before-indicator.png')
 keys('-M','ctrl','-M','alt','-k','F12','-m','alt','-m','ctrl');time.sleep(.8)
 capture('review.png')
 if len(sys.argv)>1 and sys.argv[1]=='expired':
  time.sleep(121)
  keys('-k','Return');time.sleep(.2)
  capture('expired.png')
  assert not Path(f'/proc/{child.pid}/task/{child.pid}/children').read_text().strip(),'Expired request started a password/command child'
  print(json.dumps({'expired_graphical_proposal_refused':True}))
  sys.exit(0)
 keys('-k','Return');time.sleep(.7)
 capture('authentication.png')
 password=Path('/var/tmp/greyward-administration-20261009/fixture-password').read_bytes().strip()
 secret=os.memfd_create('private-test-input',os.MFD_CLOEXEC)
 os.write(secret,password+b'\n');os.lseek(secret,0,0)
 os.setxattr(secret,'security.selinux',b'system_u:object_r:greyward_as_auth_runtime_t:s0')
 readonly=os.open(f'/proc/self/fd/{secret}',os.O_RDONLY);os.close(secret)
 with (B/'input.log').open('wb') as log:
  os.setxattr(log.fileno(),'security.selinux',b'system_u:object_r:greyward_as_auth_runtime_t:s0')
  result=subprocess.run([helper,'-'],env={**env,'GREYWARD_ROOT_TEST_KEYMAP_FD':str(keymap)},pass_fds=(keymap,),preexec_fn=enter(H),stdin=readonly,stdout=log,stderr=log,timeout=3)
 os.close(readonly)
 if result.returncode:raise RuntimeError('Private graphical authentication input failed')
 time.sleep(.7);capture('administrator-shell.png')
 child.send_signal(signal.SIGUSR1);ack(b'PAUSED')
 child.send_signal(signal.SIGUSR2);ack(b'READY')
 time.sleep(.2);capture('resumed-administrator-shell.png')
 print(json.dumps({'protected_graphical_review':True,'exclusive_surface_pause_resume':True}))
finally:
 if keymap>=0:os.close(keymap)
 if child:
  time.sleep(.05)
  print('TERMINAL_EXIT',child.poll())
  if child.poll()==None:child.terminate();child.wait(timeout=3)
  (B/'terminal-debug.log').write_bytes(child.stderr.read())
 if display.poll()==None:display.terminate();display.wait(timeout=3)
 (B/'display-debug.log').write_bytes(display.stderr.read())
