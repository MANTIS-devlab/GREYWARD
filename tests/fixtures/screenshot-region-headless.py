"""Drive only a disposable headless display; never connect to the user's desktop."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

assert os.environ.get('GREYWARD_REGION_HEADLESS_TEST') == '1'
assert os.geteuid() != 0, 'Run the selector fixture as an unprivileged build account'
ROOT = Path(__file__).resolve().parents[2]

CHILD = r'''
import importlib.machinery,importlib.util,json,sys
from pathlib import Path
import gi
gi.require_version('GdkPixbuf','2.0')
from gi.repository import GdkPixbuf
source,case,width,height,boundary=sys.argv[1:]
case=Path(case)
loader=importlib.machinery.SourceFileLoader('region',source)
spec=importlib.util.spec_from_loader(loader.name,loader)
m=importlib.util.module_from_spec(spec);loader.exec_module(m)
image=GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB,True,8,int(width),int(height))
image.fill(0xff0000ff)
image.new_subpixbuf(int(boundary),0,int(width)-int(boundary),int(height)).fill(0x0000ffff)
original=m.subprocess.Popen
def spawn(*args,**kwargs):
 process=original(*args,**kwargs)
 if args[0][0]=='/usr/bin/slurp':(case/'slurp-pid').write_text(str(process.pid))
 return process
m.subprocess.Popen=spawn
try:
 selected=m.select_region(image,m.output_signature())
 if selected is None:result={'cancelled':True}
 else:
  pixels=bytes(selected.get_pixels());stride=selected.get_rowstride()
  last=(selected.get_width()-1)*4
  result={'dimensions':[selected.get_width(),selected.get_height()],
          'firstPixel':list(pixels[:4]),'lastPixel':list(pixels[last:last+4])}
except Exception as error:
 result={'error':type(error).__name__+': '+str(error)}
(case/'result.json').write_text(json.dumps(result))
'''


def wait_file(path, process, log, timeout=8):
    end = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None or time.monotonic() > end:
            raise RuntimeError('Missing ' + str(path) + '\n' + log.read_text(errors='replace')[-6000:])
        time.sleep(.03)
    return '' if path.is_socket() else path.read_text()


class Pointer:
    def __init__(self, path):
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.settimeout(3)
        self.connection.connect(str(path))
        self.buffer = b''
        self.send(1, 1, struct.pack('<I', 2))
        self.send(1, 0, struct.pack('<I', 3))
        manager = None
        while True:
            obj, op, body = self.receive()
            if obj == 2 and op == 0:
                name, size = struct.unpack('<II', body[:8])
                interface = body[8:8 + size - 1]
                if interface == b'zwlr_virtual_pointer_manager_v1':
                    manager = name
            if obj == 3 and op == 0:
                break
        assert manager is not None, 'No synthetic pointer on isolated fixture'
        name = b'zwlr_virtual_pointer_manager_v1\0'
        self.send(2, 0, struct.pack('<II', manager, len(name)) + name +
                  b'\0' * (-len(name) % 4) + struct.pack('<II', 1, 4))
        self.send(4, 0, struct.pack('<II', 0, 5))

    def send(self, obj, op, body=b''):
        self.connection.sendall(struct.pack('<II', obj, ((8 + len(body)) << 16) | op) + body)

    def receive(self):
        while len(self.buffer) < 8:
            self.buffer += self.connection.recv(65536)
        obj, word = struct.unpack('<II', self.buffer[:8])
        size = word >> 16
        while len(self.buffer) < size:
            self.buffer += self.connection.recv(65536)
        body, self.buffer = self.buffer[8:size], self.buffer[size:]
        return obj, word & 65535, body

    def move(self, x, y, width, height):
        self.send(5, 1, struct.pack('<IIIII', 1, x, y, width, height))
        self.send(5, 4)
        time.sleep(.08)

    def button(self, state):
        self.send(5, 2, struct.pack('<III', 1, 272, state))
        self.send(5, 4)
        time.sleep(.08)


with tempfile.TemporaryDirectory(prefix='greyward-region-headless-') as temporary:
    base = Path(temporary)
    runtime = base / 'runtime'
    runtime.mkdir(mode=0o700)
    config = base / 'config'
    config.mkdir()
    (config / 'autostart').write_text('#!/bin/sh\n')
    (config / 'autostart').chmod(0o700)
    (config / 'rc.xml').write_text('<labwc_config/>\n')
    environment = dict(os.environ, XDG_RUNTIME_DIR=str(runtime),
                       WAYLAND_DISPLAY='wayland-0', GDK_BACKEND='wayland',
                       WLR_BACKENDS='headless', WLR_HEADLESS_OUTPUTS='2',
                       WLR_RENDERER='pixman', WLR_RENDERER_ALLOW_SOFTWARE='1')
    for key in ['DISPLAY', 'WAYLAND_SOCKET', 'DBUS_SESSION_BUS_ADDRESS']:
        environment.pop(key, None)
    compositor_log = base / 'compositor.log'
    with compositor_log.open('w') as log:
        compositor = subprocess.Popen(['/usr/bin/labwc', '-C', str(config)],
                                      env=environment, stdout=log, stderr=log)
    children = []
    try:
        wait_file(runtime / 'wayland-0', compositor, compositor_log)
        def layout(*args):
            return subprocess.run(['/usr/bin/wlr-randr', *args], env=environment,
                                  check=True, capture_output=True, text=True, timeout=5)
        layout('--output', 'HEADLESS-1', '--pos', '-1280,0',
               '--output', 'HEADLESS-2', '--pos', '0,0')
        results = {}
        for mode in ['drag', 'scaled-drag', 'screen-click', 'cancel', 'hotplug']:
            scale = 2 if mode == 'scaled-drag' else 1
            layout('--output', 'HEADLESS-2', '--on', '--scale', str(scale), '--pos', '0,0')
            case = base / mode
            case.mkdir()
            width, height, boundary = (3840, 1440, 2560) if scale == 2 else (2560, 720, 1280)
            child_log = case / 'selector.log'
            with child_log.open('w') as log:
                child = subprocess.Popen(['python3', '-I', '-c', CHILD,
                                          str(ROOT / 'environment/session/greyward-screenshot'),
                                          str(case), str(width), str(height), str(boundary)],
                                         env=environment, stdout=log, stderr=log)
            children.append(child)
            slurp_pid = int(wait_file(case / 'slurp-pid', child, child_log))
            time.sleep(.3)
            if mode in ['drag', 'scaled-drag', 'screen-click']:
                pointer = Pointer(runtime / 'wayland-0')
                extent = 1920 if scale == 2 else 2560
                pointer.move(1180, 100, extent, 720)
                pointer.button(1)
                if mode != 'screen-click':
                    pointer.move(1380, 200, extent, 720)
                pointer.button(0)
                pointer.connection.close()
            elif mode == 'cancel':
                os.kill(slurp_pid, signal.SIGTERM)
            else:
                layout('--output', 'HEADLESS-2', '--off')
            result = json.loads(wait_file(case / 'result.json', child, child_log))
            child.wait(timeout=3)
            if mode in ['drag', 'scaled-drag']:
                # Slurp includes both pointer endpoints in the rectangle.
                assert result.get('dimensions') == [201 * scale, 101 * scale], result
                assert result['firstPixel'] == [255, 0, 0, 255], result
                assert result['lastPixel'] == [0, 0, 255, 255], result
            elif mode == 'screen-click':
                assert result.get('dimensions') == [1280, 720], result
                assert result['firstPixel'] == result['lastPixel'] == [255, 0, 0, 255], result
            elif mode == 'cancel':
                assert result == {'cancelled': True}, result
            else:
                assert 'Display layout changed' in result.get('error', ''), result
            errors = child_log.read_text(errors='replace')
            assert 'Traceback' not in errors, errors
            results[mode] = result
        print(json.dumps(results, indent=2))
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=3)
        compositor.terminate()
        try:
            compositor.wait(timeout=3)
        except subprocess.TimeoutExpired:
            compositor.kill()
            compositor.wait(timeout=3)
