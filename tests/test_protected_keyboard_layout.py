"""The protected Labwc seat must receive GREYWARD's canonical keyboard map."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SESSION_PATH = ROOT / 'security-center/packaging/application-security/desktop/session.py'
PRODUCTION_ENVIRONMENT = ROOT / 'environment/production/labwc-environment'
SPEC = importlib.util.spec_from_file_location('greyward_protected_session', SESSION_PATH)
session = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(session)


class ProtectedKeyboardLayout(unittest.TestCase):
    def test_protected_compositor_gets_canonical_french_azerty_defaults(self):
        canonical = {}
        for line in PRODUCTION_ENVIRONMENT.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                canonical[key] = value

        expected = {
            'XKB_DEFAULT_MODEL': 'pc105',
            'XKB_DEFAULT_LAYOUT': 'fr',
        }
        self.assertEqual({key: canonical[key] for key in expected}, expected)
        self.assertEqual(session.DISPLAY_XKB_DEFAULTS, expected)
        self.assertIn('env.update(DISPLAY_XKB_DEFAULTS)', SESSION_PATH.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
