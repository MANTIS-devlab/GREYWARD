"""Imported public icon repair rejects aliases and protected labels."""
import ctypes
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

if os.name != 'posix':
    raise unittest.SkipTest('Linux descriptor and extended-label fixtures')

SOURCE = Path(__file__).resolve().parents[1] / 'tools/greyward-dev/flatpak-cache-label-repair.py'
SPEC = importlib.util.spec_from_file_location('public_cache_repair', SOURCE)
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)


class PublicCacheRepair(unittest.TestCase):
    def test_only_legacy_public_icons_change_and_second_pass_is_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            entries = home/'.var/app/org.example.Catalog/cache/org.example.Catalog/entry'
            labels = {}
            for name in ['public', 'protected', 'linked', 'alias', 'other']:
                (entries/name).mkdir(parents=True)
            public = entries/'public/icon-paintable.png'; public.write_bytes(b'public')
            protected = entries/'protected/icon-paintable.png'; protected.write_bytes(b'protected fixture')
            linked = entries/'linked/icon-paintable.png'; linked.write_bytes(b'linked')
            linked.with_name('second-link').hardlink_to(linked)
            (entries/'alias/icon-paintable.png').symlink_to(protected)
            other = entries/'other/private.dat'; other.write_bytes(b'other fixture')
            for file in [public, linked, other]:
                labels[file.stat().st_ino] = b'system_u:object_r:var_lib_t:s0'
            labels[protected.stat().st_ino] = b'system_u:object_r:greyward_protected_fixture_t:s0'
            def read(fd, *args):
                return labels.get(os.fstat(fd).st_ino, b'user_u:object_r:user_home_t:s0')
            def write(fd, name, value):
                labels[os.fstat(fd).st_ino] = value
            def expected(path, mode, output):
                output._obj.value = b'user_u:object_r:user_home_t:s0'
                return 0
            library = Mock(); library.matchpathcon.side_effect = expected
            with patch.object(repair.ctypes, 'CDLL', return_value=library), \
                 patch.object(repair.os, 'getxattr', side_effect=read), \
                 patch.object(repair.os, 'setxattr', side_effect=write):
                records = repair.repair(home, os.getuid())
                self.assertEqual([r['path'] for r in records], [str(public)])
                self.assertEqual(repair.repair(home, os.getuid()), [])
            self.assertIn(b'greyward_protected_fixture_t', labels[protected.stat().st_ino])
            self.assertIn(b'var_lib_t', labels[linked.stat().st_ino])
            self.assertIn(b'var_lib_t', labels[other.stat().st_ino])
