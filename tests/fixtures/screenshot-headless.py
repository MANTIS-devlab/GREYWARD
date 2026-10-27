"""Namespace-only driver for the synthetic-input compositor fixture, never the live desktop."""
import json,os,pathlib,signal,struct,subprocess,sys,tempfile,time
assert os.environ.get('GREYWARD_SCREENSHOT_NAMESPACE_TEST') == '1'
ROOT=pathlib.Path(sys.argv[1]).resolve()
HELPER=r'''#!/usr/bin/python3
import json,os,pathlib,socket,struct,subprocess,time
base=pathlib.Path(os.environ['GW_CASE']);mode=(base/'mode-override').read_text() if (base/'mode-override').exists() else os.environ['GW_MODE']
with (base/'starts').open('a') as f:f.write('start\n')
if mode=='success':
 with (base/'image.png').open('wb') as image:
  p=subprocess.run(['/usr/bin/grim','-'],pass_fds=(3,),stdout=image,stderr=subprocess.PIPE,timeout=5)
 (base/'result.json').write_text(json.dumps({'exit':p.returncode,'stderr':p.stderr.decode()}));raise SystemExit(p.returncode)
s=socket.socket(fileno=3)
def send(obj,op,body):s.sendall(struct.pack('<II',obj,((8+len(body))<<16)|op)+body)
def string(text):
 b=text.encode()+b'\0';return struct.pack('<I',len(b))+b+b'\0'*((-len(b))%4)
buffer=b'';globals=[]
def receive_until(callback):
 global buffer
 while True:
  if len(buffer)<8:buffer+=s.recv(65536)
  if len(buffer)<8:raise RuntimeError('early disconnect')
  obj,word=struct.unpack('<II',buffer[:8]);size=word>>16;op=word&65535
  while len(buffer)<size:buffer+=s.recv(65536)
  body=buffer[8:size];buffer=buffer[size:]
  if obj==2 and op==0:
   name,n=struct.unpack('<II',body[:8]);iface=body[8:8+n-1].decode();v=struct.unpack('<I',body[8+((n+3)//4)*4:12+((n+3)//4)*4])[0];globals.append((name,iface,v))
  if obj==callback and op==0:return
send(1,1,struct.pack('<I',2));send(1,0,struct.pack('<I',3));receive_until(3)
manager=next(x for x in globals if x[1]=='zwlr_screencopy_manager_v1');output=next(x for x in globals if x[1]=='wl_output')
for item,id,version in [(manager,4,3),(output,5,3)]:send(2,0,struct.pack('<I',item[0])+string(item[1])+struct.pack('<II',min(item[2],version),id))
send(4,0,struct.pack('<III',6,0,5));send(1,0,struct.pack('<I',7));receive_until(7)
(base/'bound.json').write_text(json.dumps({'globals':[g[1] for g in globals],'frameRequested':True}))
start=time.monotonic();s.settimeout(5)
while s.recv(65536):pass
(base/'result.json').write_text(json.dumps({'disconnected':True,'seconds':time.monotonic()-start}))
'''
def wait_file(p,timeout=7):
 start=time.monotonic()
 while not p.exists():
  if time.monotonic()-start>timeout:raise RuntimeError('Timed out: '+str(p))
  time.sleep(.03)
 return json.loads(p.read_text()) if p.suffix=='.json' else p.read_bytes()
subprocess.run(['mount','--make-rprivate','/'],check=True)
with tempfile.TemporaryDirectory(prefix='greyward-screenshot-headless-') as temporary:
 root=pathlib.Path(temporary);helperdir=root/'helpers';helperdir.mkdir();helper=helperdir/'greyward-screenshot';helper.write_text(HELPER);helper.chmod(0o755)
 subprocess.run(['mount','--bind',str(helperdir),'/usr/local/libexec'],check=True)
 results={}
 for mode in ['success','deadline','lock']:
  case=root/mode;case.mkdir();runtime=case/'runtime';runtime.mkdir(mode=0o700);config=case/'config';config.mkdir();(config/'autostart').write_text('#!/bin/sh\n');(config/'autostart').chmod(0o700)
  env=dict(os.environ,XDG_RUNTIME_DIR=str(runtime),WLR_BACKENDS='headless',WLR_RENDERER='pixman',WLR_HEADLESS_OUTPUTS='2',GW_CASE=str(case),GW_MODE=mode,GW_TEST_LOCK_PID_FILE=str(case/'lock-pid'),GW_TEST_FREEZE_FRAMES=str(case/'freeze-frames'),GW_TEST_READY_FILE=str(case/'frame-ready'))
  env.pop('WAYLAND_DISPLAY',None);env.pop('WAYLAND_SOCKET',None);env.pop('DISPLAY',None)
  log=(case/'compositor.log').open('wb');p=subprocess.Popen([str(ROOT/'fixture/build/labwc'),'-C',str(config)],env=env,stdout=log,stderr=log)
  try:
   start=time.monotonic()
   while not (runtime/'wayland-0').exists():
    if p.poll() is not None:raise RuntimeError((case/'compositor.log').read_text())
    if time.monotonic()-start>8:raise RuntimeError('No nested socket')
    time.sleep(.03)
   wait_file(case/'frame-ready')
   env['WAYLAND_DISPLAY']='wayland-0'
   ordinary=subprocess.run(['/usr/bin/grim','-'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
   assert ordinary.returncode!=0 and not ordinary.stdout,ordinary.stderr
   p.send_signal(signal.SIGUSR1)
   if mode=='success':
    r=wait_file(case/'result.json');assert r['exit']==0,r;image=(case/'image.png').read_bytes();assert image[:8]==b'\x89PNG\r\n\x1a\n';r['size']=len(image);r['dimensions']=struct.unpack('>II',image[16:24]);r['ordinaryCaptureDenied']=True;results[mode]=r
   else:
    bound=wait_file(case/'bound.json');assert set(bound['globals']) <= {'wl_shm','wl_output','zxdg_output_manager_v1','zwlr_screencopy_manager_v1'},bound
    assert (case/'starts').read_text().count('start')==1
    p.send_signal(signal.SIGUSR1);time.sleep(.1);assert (case/'starts').read_text().count('start')==1
    if mode=='lock':
     (case/'lock-pid').write_text(str(os.getpid()))
     import socket
     lock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);lock.connect(str(runtime/'wayland-0'))
     def wire(obj,op,body):lock.sendall(struct.pack('<II',obj,((8+len(body))<<16)|op)+body)
     wire(1,1,struct.pack('<I',2));wire(1,0,struct.pack('<I',3))
     pending=b'';manager=None;done=False
     while not done:
      pending+=lock.recv(65536)
      while len(pending)>=8:
       obj,word=struct.unpack('<II',pending[:8]);length=word>>16;op=word&65535
       if len(pending)<length:break
       body=pending[8:length];pending=pending[length:]
       if obj==2 and op==0:
        name,n=struct.unpack('<II',body[:8])
        if body[8:8+n-1]==b'ext_session_lock_manager_v1':manager=name
       if obj==3 and op==0:done=True
     assert manager is not None,'Fixture authentication client cannot bind lock'
     iface=b'ext_session_lock_manager_v1\0'
     wire(2,0,struct.pack('<II',manager,len(iface))+iface+b'\0'*((-len(iface))%4)+struct.pack('<II',1,4))
     wire(4,1,struct.pack('<I',5))
    r=wait_file(case/'result.json');assert r['disconnected'],r
    if mode=='deadline':assert 2<r['seconds']<4.5,r
    if mode=='lock':
     assert r['seconds']<1.0,r;p.send_signal(signal.SIGUSR1);time.sleep(.15);assert (case/'starts').read_text().count('start')==1
    results[mode]=dict(r,globals=bound['globals'],duplicateGestureIgnored=True)
    if mode=='lock':
     # Hold the old scanout across a real native unlock: a false locked flag
     # alone must not make that protected framebuffer capturable.
     (case/'freeze-frames').touch();(case/'frame-ready').unlink(missing_ok=True)
     wire(5,2,b'')
     p.send_signal(signal.SIGUSR1);time.sleep(.15)
     assert (case/'starts').read_text().count('start')==1,'Stale protected frame admitted'
     (case/'freeze-frames').unlink();(case/'mode-override').write_text('success')
     (case/'result.json').unlink();p.send_signal(signal.SIGUSR2);wait_file(case/'frame-ready')
     p.send_signal(signal.SIGUSR1)
     after=wait_file(case/'result.json');assert after['exit']==0,after
     assert (case/'image.png').read_bytes()[:8]==b'\x89PNG\r\n\x1a\n'
     results[mode]['staleFrameDenied']=True;results[mode]['freshFrameAfterUnlock']=True
     lock.close()
  finally:
   p.terminate()
   try:p.wait(timeout=4)
   except subprocess.TimeoutExpired:p.kill();p.wait()
   log.close()
   if sys.exc_info()[0] is not None:
    print((case/"compositor.log").read_text(errors="replace")[-7000:],file=sys.stderr)
    print("starts:", (case/"starts").read_text() if (case/"starts").exists() else "none",file=sys.stderr)

 print(json.dumps(results,indent=2))
 (ROOT/'headless-readback.json').write_text(json.dumps(results,indent=2)+'\n')
