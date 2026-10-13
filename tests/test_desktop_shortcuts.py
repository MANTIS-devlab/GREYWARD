"""Shortcuts preserve installed commands and never overwrite unrelated files."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader('desktop_shortcut', str(ROOT / 'environment/session/greyward-desktop-shortcut'))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
MODULE = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(MODULE)
CONTENT = b'[Desktop Entry]\nType=Application\nName=Example\nExec=/usr/bin/example %U\nIcon=example\n'


class DesktopShortcutTests(unittest.TestCase):
    def test_unverified_identifiers_cannot_be_paths_or_commands(self):
        for identifier in ('../example', '/usr/bin/sh', 'example;sh', 'example\nExec=sh', ''):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                MODULE.installed_launcher(identifier, ())

    def test_missing_installed_launcher_is_unavailable(self):
        with self.assertRaisesRegex(ValueError, 'verified installed launcher'):
            MODULE.installed_launcher('io.example.Missing', ())

    @unittest.skipUnless(os.name == 'posix', 'directory descriptor creation requires Linux')
    def test_unchanged_shortcut_is_reused_without_duplication(self):
        with tempfile.TemporaryDirectory() as directory:
            path, created = MODULE.create_shortcut('example.desktop', CONTENT, Path(directory))
            again, duplicate = MODULE.create_shortcut('example.desktop', CONTENT, Path(directory))
            self.assertTrue(created)
            self.assertFalse(duplicate)
            self.assertEqual(path, again)
            self.assertEqual(path.read_bytes(), CONTENT)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    @unittest.skipUnless(os.name == 'posix', 'directory descriptor creation requires Linux')
    def test_conflicting_file_and_symlink_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            desktop = Path(directory)
            original = desktop / 'unrelated.txt'
            original.write_text('preserve me')
            (desktop / 'example.desktop').symlink_to(original)
            path, created = MODULE.create_shortcut('example.desktop', CONTENT, desktop)
            self.assertTrue(created)
            self.assertEqual(path.name, 'example-2.desktop')
            self.assertEqual(original.read_text(), 'preserve me')
            self.assertTrue((desktop / 'example.desktop').is_symlink())


if __name__ == '__main__':
    unittest.main()
