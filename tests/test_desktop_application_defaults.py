"""Factory desktop shortcuts and shared application artwork remain coherent."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('desktop_defaults', str(ROOT / 'environment/session/greyward-desktop-defaults'))
defaults = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(defaults)


class Launchers:
    def installed_launcher(self, identifier):
        return identifier + '.desktop', identifier, ('[Desktop Entry]\nType=Application\nExec=' + identifier + '\n').encode()


class DesktopApplicationDefaults(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'Linux ownership and symlink semantics')
    def test_factory_trust_only_exact_copies_and_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); desktop = base / 'Desktop'; desktop.mkdir()
            launcher = Launchers(); expected = []
            for identifier in defaults.APPLICATIONS:
                name, _, content = launcher.installed_launcher(identifier)
                path = desktop / name; path.write_bytes(content); path.chmod(0o700)
                expected.append(path)
            # A matching filename is insufficient, and symlinks are not approved.
            expected[1].write_bytes(b'custom Exec=evil')
            expected[2].unlink(); expected[2].symlink_to(expected[0])
            expected[3].unlink()  # A user deletion stays deleted.
            approved = []
            defaults.trust_defaults(base / 'state', desktop, launcher, approved.append)
            self.assertEqual(approved, [expected[0], expected[4], expected[5]])
            defaults.trust_defaults(base / 'state', desktop, launcher, self.fail)
            self.assertFalse(expected[3].exists())

    @unittest.skipIf(os.name == 'nt', 'Linux ownership semantics')
    def test_failed_trust_is_retried_without_completion_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); desktop = base / 'Desktop'; desktop.mkdir()
            name, _, content = Launchers().installed_launcher(defaults.APPLICATIONS[0])
            path = desktop / name; path.write_bytes(content); path.chmod(0o700)
            def fail(path):
                raise OSError('metadata unavailable')
            with self.assertRaises(OSError):
                defaults.trust_defaults(base / 'state', desktop, Launchers(), fail)
            self.assertFalse((base / 'state/greyward/desktop-default-trust-v1.json').exists())

    def test_native_shortcuts_and_six_installed_applications_seed_once(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config, state, desktop = (base / name for name in ('config', 'state', 'Desktop'))
            original = Path.read_text
            def read(path, *args, **kwargs):
                if path == Path('/usr/share/greyward/files/settings.conf'):
                    return (ROOT / 'environment/session/desktop/settings.conf').read_bytes().decode()
                return original(path, *args, **kwargs)
            with patch.object(Path, 'read_text', read):
                defaults.seed_defaults(config, state, desktop, Launchers())
            self.assertEqual(len(list(desktop.glob('*.desktop'))), 6)
            self.assertIn('DesktopShortcuts=Home, Trash\n', (config / 'pcmanfm-qt/greyward/settings.conf').read_text())
            removed = desktop / 'systems.mantis.greyward.Writer.desktop'
            removed.unlink()
            defaults.seed_defaults(config, state, desktop, Launchers())
            self.assertFalse(removed.exists(), 'A user deletion must survive later logins.')

    def test_existing_preferences_and_desktop_files_win(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); config = base / 'config'; desktop = base / 'Desktop'
            settings = config / 'pcmanfm-qt/greyward/settings.conf'; settings.parent.mkdir(parents=True)
            settings.write_bytes(b'[Desktop]\nDesktopShortcuts=\nDesktopIconSize=72\n')
            desktop.mkdir(); chosen = desktop / 'com.brave.Browser.desktop'; chosen.write_bytes(b'custom shortcut')
            defaults.seed_defaults(config, base / 'state', desktop, Launchers())
            self.assertEqual(chosen.read_bytes(), b'custom shortcut')
            self.assertEqual(settings.read_bytes(), b'[Desktop]\nDesktopShortcuts=\nDesktopIconSize=72\n')

    def test_missing_application_does_not_create_a_broken_launcher_or_finish_seed(self):
        class Missing:
            def installed_launcher(self, identifier):
                raise ValueError('not installed')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); config = base / 'config'
            settings = config / 'pcmanfm-qt/greyward/settings.conf'; settings.parent.mkdir(parents=True); settings.write_text('user')
            defaults.seed_defaults(config, base / 'state', base / 'Desktop', Missing())
            self.assertFalse(list((base / 'Desktop').iterdir()))
            self.assertFalse((base / 'state/greyward/desktop-defaults-v1.json').exists())

    def test_software_is_an_application_pin_not_a_factory_bar_widget(self):
        legacy = json.loads((ROOT / 'environment/session/dankmaterialshell/settings.json').read_text())
        self.assertNotIn('greywardSoftware', json.dumps(legacy.get('barConfigs', [])))
        experience = json.loads((ROOT / 'environment/session/dms-2.0-defaults/experience.json').read_text())
        for bar in experience['appearance']['barConfigs']:
            for section in ('leftWidgets', 'centerWidgets', 'rightWidgets'):
                self.assertNotIn('greywardSoftware', [x.get('id') if isinstance(x, dict) else x for x in bar[section]])
        self.assertIn('default_pins+=("io.github.kolunmi.Bazaar")',
                      (ROOT / 'environment/session/greyward-dms-session-migrate').read_text())

    def test_closed_svg_family_and_packaged_launcher_paths(self):
        for name in ('software', 'image-viewer', 'settings'):
            path = ROOT / ('branding/source/greyward-' + name + '.svg')
            tree = ET.fromstring(path.read_bytes())
            self.assertEqual(tree.attrib['viewBox'], '0 0 128 128')
            self.assertFalse(any(element.tag.endswith(('image', 'script', 'foreignObject')) for element in tree.iter()))
            self.assertIn('greyward-' + name + '.svg', (ROOT / 'packaging/greyward-branding/SPECS/greyward-branding.spec').read_text())
        asset = ROOT / 'branding/source/greyward-settings.svg'
        self.assertEqual(asset.read_bytes(), (ROOT / 'environment/session/dms-2.0/assets/greyward-settings.svg').read_bytes())
        pin = json.loads((ROOT / 'environment/production/dms-2.0-candidate.json').read_text())
        self.assertEqual(hashlib.sha256(asset.read_bytes()).hexdigest(), pin['shellAdditions']['files']['assets/greyward-settings.svg'])
        self.assertTrue(pin['build']['artworkUpdate']['requiresProtectedMigration'])


if __name__ == '__main__':
    unittest.main()
