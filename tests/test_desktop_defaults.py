"""An update must preserve user preferences and desktop positions."""
import hashlib
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader('files_seed', str(ROOT / 'environment/session/greyward-files-seed'))
MODULE = importlib.util.module_from_spec(importlib.util.spec_from_loader(LOADER.name, LOADER))
LOADER.exec_module(MODULE)


class DesktopDefaultsTests(unittest.TestCase):
    def test_factory_volume_keys_are_the_native_pcmanfm_keys(self):
        import configparser
        config = configparser.ConfigParser()
        config.read(ROOT / 'environment/session/desktop/settings.conf', encoding='utf-8')
        self.assertFalse(config.getboolean('Volume', 'MountOnStartup'))
        self.assertFalse(config.getboolean('Volume', 'MountRemovable'))
        self.assertFalse(config.getboolean('Volume', 'AutoRun'))
        self.assertNotIn('AutoMount', config['Volume'])
        self.assertNotIn('AutoMountOnStartup', config['Volume'])

    def test_existing_user_settings_are_preserved_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'settings.conf'
            customized = b'[Desktop]\nDesktopIconSize=64\n# my layout\n'
            config.write_bytes(customized)
            MODULE.seed(config, b'[Desktop]\nDesktopIconSize=48\n')
            self.assertEqual(config.read_bytes(), customized)

    def test_first_seed_does_not_replace_a_later_user_change(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'strata/settings.toml'
            MODULE.seed(config, b'theme = "greyward-obsidian"\n')
            self.assertEqual(config.read_bytes(), b'theme = "greyward-obsidian"\n')
            config.write_bytes(b'theme = "my-theme"\n')
            MODULE.seed(config, b'theme = "greyward-obsidian"\n')
            self.assertEqual(config.read_bytes(), b'theme = "my-theme"\n')

    def test_only_exact_factory_theme_updates_and_original_backup_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            theme = Path(directory) / 'theme.toml'
            original = b'old factory'
            theme.write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            MODULE.seed_managed(theme, b'new factory', digest)
            self.assertEqual(theme.read_bytes(), b'new factory')
            self.assertEqual(theme.with_name('theme.toml.pre-dms20').read_bytes(), original)
            theme.write_bytes(b'my custom theme')
            MODULE.seed_managed(theme, b'newer factory', digest)
            self.assertEqual(theme.read_bytes(), b'my custom theme')
            self.assertEqual(theme.with_name('theme.toml.pre-dms20').read_bytes(), original)

    @unittest.skipUnless(__import__('os').name == 'posix', 'Unix user symlink')
    def test_linked_theme_is_never_replaced_or_followed_for_update(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'custom.toml'
            target.write_bytes(b'factory')
            linked = Path(directory) / 'theme.toml'
            linked.symlink_to(target)
            MODULE.seed_managed(linked, b'new', hashlib.sha256(b'factory').hexdigest())
            self.assertTrue(linked.is_symlink())
            self.assertEqual(target.read_bytes(), b'factory')

    def test_unchanged_scan_action_upgrades_and_custom_action_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'action.toml'
            previous = b'factory scan action'
            destination.write_bytes(previous)
            digest = hashlib.sha256(previous).hexdigest()
            MODULE.seed_managed(destination, b'folder-capable action', digest, '.pre-clamav-arrivals')
            self.assertEqual(destination.read_bytes(), b'folder-capable action')
            self.assertEqual(destination.with_name('action.toml.pre-clamav-arrivals').read_bytes(), previous)
            destination.write_bytes(b'user edited')
            MODULE.seed_managed(destination, b'new action', digest, '.pre-clamav-arrivals')
            self.assertEqual(destination.read_bytes(), b'user edited')


if __name__ == '__main__':
    unittest.main()
