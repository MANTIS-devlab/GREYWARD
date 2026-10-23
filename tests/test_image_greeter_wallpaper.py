"""Exercise the actual greeter cache producer and its state contract."""
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
loader = SourceFileLoader('greeter_wallpaper', str(ROOT/'environment/production/greyward-sync-greeter-wallpaper'))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


@unittest.skipIf(os.name == 'nt', 'Cache ownership is validated on Fedora')
class GreeterWallpaperTests(unittest.TestCase):
    def test_new_cache_and_subsequent_refresh_select_the_copied_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root/'wallpaper.jpg'; cache = root/'cache'
            source.write_bytes(b'first-image')
            helper.sync(source, cache, os.getuid(), os.getgid())
            session = cache/'session.json'
            state = json.loads(session.read_text())
            self.assertEqual(Path(state['wallpaperPath']).read_bytes(), source.read_bytes())
            self.assertFalse(state['perMonitorWallpaper'])
            self.assertEqual(session.stat().st_mode & 0o777, 0o644)
            memory = cache / '.local/state/memory.json'
            self.assertEqual(json.loads(memory.read_text())['lastSessionDesktopId'], 'greyward-labwc.desktop')
            # A deliberate later selection survives background refresh/retry.
            memory.write_text(json.dumps({'lastSessionDesktopId': 'explicit.desktop'}))
            state['isLightMode'] = True
            session.write_text(json.dumps(state))
            source.write_bytes(b'updated-image')
            helper.sync(source, cache, os.getuid(), os.getgid())
            self.assertTrue(json.loads(session.read_text())['isLightMode'])
            self.assertEqual((cache/'greeter_wallpaper_override.jpg').read_bytes(), b'updated-image')
            self.assertEqual(json.loads(memory.read_text())['lastSessionDesktopId'], 'explicit.desktop')

    def test_greeter_keeps_saved_session_selection_enabled(self):
        production = (ROOT/'environment/production/provision.sh').read_text()
        self.assertNotIn('--no-save-session', production)
        self.assertIn('--no-save-username', production)

    def test_greeter_uses_reviewed_ui_and_hardware_appropriate_renderer(self):
        production = (ROOT/'environment/production/provision.sh').read_text()
        command = next(line for line in production.splitlines() if line.startswith('greeter_command='))
        self.assertIn('/usr/local/libexec/greyward-start-dms-greeter', command)
        self.assertIn('--shell-dir /usr/share/greyward/dms-greeter-ui', command)
        self.assertIn('command = "$greeter_command"', production)
        wrapper = (ROOT/'environment/production/greyward-start-dms-greeter').read_text()
        keys = ('WLR_RENDERER', 'LIBGL_ALWAYS_SOFTWARE', 'QT_QUICK_BACKEND',
                'QSG_RHI_BACKEND', 'QT_OPENGL')
        for virtual, render_node in ((False, True), (True, True), (False, False)):
            with self.subTest(virtual=virtual, render_node=render_node), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                vendor = root/'sys/class/dmi/id/sys_vendor'
                vendor.parent.mkdir(parents=True)
                vendor.write_text('Microsoft Virtual Machine' if virtual else 'Physical hardware')
                dri = root/'dev/dri'
                dri.mkdir(parents=True)
                if render_node:
                    (dri/'renderD128').touch()
                capture = root/'capture'
                capture.write_text('#!/usr/bin/python3\nimport os,json\nprint(json.dumps({k:os.environ.get(k) for k in ' + repr(keys) + '}))\n')
                capture.chmod(0o755)
                fixture = wrapper.replace('/sys/', str(root/'sys')+'/').replace('/dev/dri/', str(dri)+'/').replace('/usr/bin/dms-greeter', str(capture))
                result = subprocess.run(['sh', '-eu', '-c', fixture], check=True, capture_output=True,
                                        text=True, env={**os.environ, **{key: 'old-override' for key in keys}})
                observed = json.loads(result.stdout)
                if virtual or not render_node:
                    self.assertEqual(observed, dict(zip(keys, ('pixman', '1', 'rhi', 'opengl', 'software'))))
                else:
                    self.assertEqual(observed, dict(zip(keys, ('gles2', None, None, None, None))))

    def test_malformed_cache_and_symlink_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root/'wallpaper.jpg'; source.write_bytes(b'image')
            cache = root/'cache'; cache.mkdir(); session = cache/'session.json'
            for malformed in ('{broken', '[]'):
                session.write_text(malformed)
                with self.assertRaises(ValueError):
                    helper.sync(source, cache, os.getuid(), os.getgid())
                self.assertEqual(session.read_text(), malformed)
                self.assertFalse((cache/'greeter_wallpaper_override.jpg').exists())
            session.unlink(); victim = root/'private'; victim.write_text('{}')
            session.symlink_to(victim)
            with self.assertRaises(ValueError):
                helper.sync(source, cache, os.getuid(), os.getgid())
            self.assertEqual(victim.read_text(), '{}')


if __name__ == '__main__':
    unittest.main()
