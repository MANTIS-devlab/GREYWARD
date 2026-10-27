"""Area selection must crop the frozen pixels and never save a cancelled desktop."""
from contextlib import nullcontext
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader('screenshot_region', str(ROOT / 'environment/session/greyward-screenshot'))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
RECEIVER = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(RECEIVER)
HAS_GI = importlib.util.find_spec('gi') is not None


class ScreenshotRegionGeometryTests(unittest.TestCase):
    def test_negative_origin_and_cross_screen_drag_at_double_scale(self):
        bounds = RECEIVER.canvas_bounds([(-1280, -200, 1280, 720), (0, 0, 1920, 1080)])
        self.assertEqual(bounds, (-1280, -200, 3200, 1280))
        self.assertEqual(RECEIVER.parse_selection('-100,100 300x200\n', bounds, (6400, 2560)),
                         (2360, 600, 600, 400))

    def test_fractional_scale_keeps_the_selected_edges(self):
        self.assertEqual(RECEIVER.pixel_rectangle((1, 3, 3, 2), (0, 0, 100, 80), (125, 100)),
                         (1, 3, 4, 4))

    def test_outside_empty_malformed_or_changed_layout_is_rejected(self):
        for text in ['-1,0 10x10', '90,0 11x10', '0,0 0x10', '0,0 10x10 extra', '0,0 10x10\n0,0 10x10']:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                RECEIVER.parse_selection(text, (0, 0, 100, 100), (100, 100))
        with self.assertRaises(RuntimeError):
            RECEIVER.pixel_rectangle((0, 0, 10, 10), (0, 0, 100, 100), (200, 100))
        for monitors in [[], [(0, 0, 0, 100)], [(0, 0, 100.0, 100)]]:
            with self.subTest(monitors=monitors), self.assertRaises(RuntimeError):
                RECEIVER.canvas_bounds(monitors)

    def test_cancel_does_not_save_or_start_editor(self):
        with (patch.object(RECEIVER.os, 'geteuid', return_value=1000, create=True),
              patch.object(Path, 'read_bytes', return_value=b'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0'),
              patch.object(sys, 'argv', ['screenshot', '--capture']),
              patch.object(RECEIVER, 'selection_lock', return_value=nullcontext(True)),
              patch.object(RECEIVER, 'capture', return_value=(object(), ())),
              patch.object(RECEIVER, 'select_region', return_value=None),
              patch.object(RECEIVER, 'save_selection') as save,
              patch.object(RECEIVER.subprocess, 'run') as launch):
            self.assertEqual(RECEIVER.main(), 0)
            save.assert_not_called()
            launch.assert_not_called()

    @unittest.skipUnless(hasattr(RECEIVER.socket, 'SO_PEERSEC'), 'Linux socket labels')
    def test_capture_authority_closes_before_png_decode_and_selection(self):
        class Channel:
            family = RECEIVER.socket.AF_UNIX
            type = RECEIVER.socket.SOCK_STREAM
            closed = False
            def __enter__(self): return self
            def __exit__(self, *_): self.close()
            def getsockopt(self, *_): return RECEIVER.DISPLAY_CONTEXT
            def close(self): self.closed = True
        channel = Channel()

        def grim(_args, **kwargs):
            kwargs['stdout'].write(b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + struct.pack('>II', 10, 10))
            return SimpleNamespace(returncode=0)

        def decode(*_):
            self.assertTrue(channel.closed)
            self.assertNotIn('WAYLAND_SOCKET', os.environ)
            return 'frozen pixels'

        with (patch.object(RECEIVER.socket, 'socket', return_value=channel),
              patch.object(RECEIVER, 'output_signature', return_value=('fixed layout',)),
              patch.object(RECEIVER.subprocess, 'run', side_effect=grim),
              patch.object(RECEIVER, 'decode_png', side_effect=decode),
              patch.dict(os.environ, {'WAYLAND_SOCKET': '3'})):
            self.assertEqual(RECEIVER.capture(), ('frozen pixels', ('fixed layout',)))


@unittest.skipUnless(HAS_GI, 'Native GdkPixbuf/GLib required')
class ScreenshotRegionPngTests(unittest.TestCase):
    def test_only_selected_pixels_are_saved_with_private_permissions(self):
        import gi
        gi.require_version('GdkPixbuf', '2.0')
        from gi.repository import GdkPixbuf, GLib
        image = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, True, 8, 6, 4)
        image.fill(0xff0000ff)
        selected = image.new_subpixbuf(2, 1, 2, 2)
        selected.fill(0x00ff00ff)
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(GLib, 'get_user_special_dir', return_value=temporary):
                path = Path(RECEIVER.save_selection(selected))
            saved = GdkPixbuf.Pixbuf.new_from_file(str(path))
            self.assertEqual((saved.get_width(), saved.get_height()), (2, 2))
            self.assertEqual(bytes(saved.get_pixels())[:4], b'\x00\xff\x00\xff')
            self.assertEqual(list(path.parent.iterdir()), [path])
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
