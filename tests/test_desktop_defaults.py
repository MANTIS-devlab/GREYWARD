"""An update must preserve user preferences and desktop positions."""
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


if __name__ == '__main__':
    unittest.main()
