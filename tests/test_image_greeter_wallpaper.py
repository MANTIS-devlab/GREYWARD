"""Exercise the actual greeter cache producer and its state contract."""
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
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
            state['isLightMode'] = True
            session.write_text(json.dumps(state))
            source.write_bytes(b'updated-image')
            helper.sync(source, cache, os.getuid(), os.getgid())
            self.assertTrue(json.loads(session.read_text())['isLightMode'])
            self.assertEqual((cache/'greeter_wallpaper_override.jpg').read_bytes(), b'updated-image')

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
