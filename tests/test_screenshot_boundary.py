"""Screenshot capability tests; opt-in native tests use only a nested headless display."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader('screenshot_receiver', str(ROOT / 'environment/session/greyward-screenshot'))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
RECEIVER = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(RECEIVER)
ARCHIVE = Path(os.environ.get('GREYWARD_LABWC_SOURCE', '/nonexistent'))
NATIVE = (os.name == 'posix' and ARCHIVE.is_file() and os.geteuid() == 0
          and all(shutil.which(x) for x in ('meson', 'ninja', 'unshare', 'patch', 'grim')))


class ScreenshotReceiverTests(unittest.TestCase):
    def test_forged_capture_argument_does_not_fall_back_to_public_socket(self):
        with patch.object(RECEIVER.socket, 'socket', side_effect=OSError('No inherited FD')):
            with patch.object(RECEIVER.subprocess, 'run') as run:
                with self.assertRaises(OSError):
                    RECEIVER.capture()
                run.assert_not_called()

    @unittest.skipUnless(hasattr(RECEIVER.socket, 'SO_PEERSEC'), 'Linux kernel peer labels')
    def test_ordinary_socket_peer_cannot_authorize_capture(self):
        class Channel:
            family = RECEIVER.socket.AF_UNIX
            type = RECEIVER.socket.SOCK_STREAM
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def getsockopt(self, *args):
                return b'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0'
        with patch.object(RECEIVER.socket, 'socket', return_value=Channel()):
            with patch.object(RECEIVER.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'physical Print Screen'):
                    RECEIVER.capture()
                run.assert_not_called()


@unittest.skipUnless(NATIVE, 'Explicit Fedora root/headless gate with GREYWARD_LABWC_SOURCE')
class ScreenshotNativeTests(unittest.TestCase):
    def test_native_capture_deadline_and_prebound_lock_revocation(self):
        self.assertEqual(hashlib.sha256(ARCHIVE.read_bytes()).hexdigest(),
                         '67fe996c4e5afd855fdbfbc3af0b05245667ec97666f463472a1961b46047f48')
        with tempfile.TemporaryDirectory(prefix='greyward-screenshot-build-') as temporary:
            base = Path(temporary)
            source = base / 'fixture'
            source.mkdir()
            with tarfile.open(ARCHIVE) as archive:
                archive.extractall(source, filter='data')
            for name in ('labwc-protected-input.patch', 'labwc-administration-indicator.patch',
                         'labwc-screenshot.patch'):
                contents = (ROOT / 'security-center/packaging/application-security/desktop' / name).read_bytes().replace(b'\r\n', b'\n')
                result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1'], cwd=source,
                                        input=contents, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
            server = source / 'src/server.c'
            contents = server.read_text()
            # Synthetic physical/lock events exist ONLY in this disposable test
            # build. Production has no signal, IPC or environment capture trigger.
            self.assertNotIn('greyward_fixture_signal', contents)
            hook = '''static int greyward_fixture_signal(int signal, void *data) {
 struct server *server=data;
 if (signal==SIGUSR1) greyward_screenshot_start(server);
 else greyward_screenshot_revoke(server);
 return 0;
}
'''
            contents = contents.replace('static bool\ngreyward_client_domain(', hook + 'static bool\ngreyward_client_domain(')
            contents = contents.replace('\tsession_lock_init(server);', '''\tsession_lock_init(server);
 wl_event_loop_add_signal(server->wl_event_loop,SIGUSR1,greyward_fixture_signal,server);
 wl_event_loop_add_signal(server->wl_event_loop,SIGUSR2,greyward_fixture_signal,server);''')
            # Model the real socketpair's trusted creator SID and one test lock
            # client, without loading a policy module into the build host.
            peer_fixture = ''' char context[256] = {0};
 if (greyward_capture_client(client))
  return !strcmp(expected,"greyward_guard_u:greyward_guard_r:greyward_as_display_t:s0");
 const char *path=getenv("GW_TEST_LOCK_PID_FILE");
 if (path) {
  FILE *file=fopen(path,"r"); long trusted=0;
  if (file) { if (fscanf(file,"%ld",&trusted)!=1) trusted=0; fclose(file); }
  pid_t pid; wl_client_get_credentials((struct wl_client *)client,&pid,NULL,NULL);
  if (trusted>0 && pid==trusted)
   return !strcmp(expected,"system_u:system_r:greyward_as_auth_t:s0");
 }
'''
            self.assertEqual(contents.count('\tchar context[256] = {0};'), 1)
            contents = contents.replace('\tchar context[256] = {0};', peer_fixture)
            server.write_text(contents)
            output = source / 'src/output.c'
            contents = output.read_text()
            contents = contents.replace('#include "output.h"', '#include "output.h"\n#include <unistd.h>')
            marker = 'handle_output_frame(struct wl_listener *listener, void *data)\n{'
            self.assertEqual(contents.count(marker), 1)
            contents = contents.replace(marker, marker + '''
 const char *freeze=getenv("GW_TEST_FREEZE_FRAMES");
 if (freeze && access(freeze,F_OK)==0) return;
''')
            marker = 'else if (event->state->committed & WLR_OUTPUT_STATE_BUFFER) output->screenshot_clean=true;'
            self.assertEqual(contents.count(marker), 1)
            contents = contents.replace(marker, marker + '''
 bool ready=manager && !manager->locked; size_t enabled=0;
 struct output *other;
 wl_list_for_each(other,&output->server->outputs,link) {
  if (other->wlr_output->enabled) { ++enabled; if (!other->screenshot_clean) ready=false; }
 }
 const char *ready_path=getenv("GW_TEST_READY_FILE");
 if (ready && enabled==2 && ready_path) { FILE *f=fopen(ready_path,"w"); if(f) { fputs("ready",f); fclose(f); } }
''')
            output.write_text(contents)
            commands = [
                ['meson', 'setup', str(source / 'build'), str(source), '--buildtype=release',
                 '--wrap-mode=nofallback', '-Dman-pages=disabled', '-Dtest=enabled'],
                ['ninja', '-C', str(source / 'build'), '-j2'],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout[-4000:] + result.stderr[-4000:])
            environment = dict(os.environ, GREYWARD_SCREENSHOT_NAMESPACE_TEST='1')
            result = subprocess.run(['unshare', '--mount', '--fork', 'python3',
                                     str(ROOT / 'tests/fixtures/screenshot-headless.py'), str(base)],
                                    env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            readback = json.loads((base / 'headless-readback.json').read_text())
            self.assertTrue(readback['success']['ordinaryCaptureDenied'])
            self.assertEqual(readback['success']['dimensions'], [2560, 720])
            self.assertTrue(readback['deadline']['disconnected'])
            self.assertTrue(readback['lock']['disconnected'])
            self.assertTrue(readback['lock']['staleFrameDenied'])
            self.assertTrue(readback['lock']['freshFrameAfterUnlock'])


if __name__ == '__main__':
    unittest.main()
