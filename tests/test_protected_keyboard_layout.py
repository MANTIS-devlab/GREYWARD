"""Installed keyboard choice reaches greetd and the protected compositor."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / 'security-center/packaging/application-security/desktop'
KEYBOARD_PATH = DESKTOP / 'keyboard_config.py'
SESSION_PATH = DESKTOP / 'session.py'
PRODUCTION_ENVIRONMENT = ROOT / 'environment/production/labwc-environment'
PROVISION = ROOT / 'environment/production/provision.sh'
APPLICATION_SECURITY_SPEC = ROOT / 'security-center/packaging/application-security/greyward-application-security-experimental.spec'
COMPONENT_BUILDER = ROOT / 'environment/image/build-components.py'
ISO_BUILDER = ROOT / 'environment/image/build.sh'
SPEC = importlib.util.spec_from_file_location('greyward_keyboard_config_test', KEYBOARD_PATH)
keyboard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(keyboard)
SESSION_SPEC = importlib.util.spec_from_file_location('greyward_protected_session', SESSION_PATH)
session = importlib.util.module_from_spec(SESSION_SPEC)
SESSION_SPEC.loader.exec_module(session)


class InstalledKeyboardLayout(unittest.TestCase):
    def test_keyboard_helper_is_part_of_the_cached_security_rpm_used_by_iso_builds(self):
        package_spec = APPLICATION_SECURITY_SPEC.read_text(encoding='utf-8')
        component_builder = COMPONENT_BUILDER.read_text(encoding='utf-8')
        iso_builder = ISO_BUILDER.read_text(encoding='utf-8')

        # The source tar includes the complete Security Center tree, the RPM
        # payload installs the desktop Python sources, and the ISO builder
        # consumes the resulting Application Security RPM.
        self.assertIn('packaging/application-security/desktop/*.py', package_spec)
        self.assertIn("'security': ['security-center'", component_builder)
        self.assertIn('greyward-application-security-experimental', iso_builder)

    def test_reads_installer_selected_layout_model_variant_and_switch_options(self):
        source = '''\
Section "InputClass"
    Identifier "system-keyboard"
    MatchIsKeyboard "on"
    Option "XkbLayout" "us,fr"
    Option "XkbModel" "pc105"
    Option "XkbVariant" ",oss"
    Option "XkbOptions" "grp:alt_shift_toggle"
EndSection
'''
        self.assertEqual(keyboard.parse_localed_config(source), {
            'schema': 'greyward.keyboard-settings/v1',
            'model': 'pc105', 'layout': 'us,fr', 'variant': ',oss',
            'options': 'grp:alt_shift_toggle',
        })

    def test_auth_indicator_uses_the_validated_installer_layout(self):
        self.assertEqual(keyboard.display_layout_label({
            'schema': 'greyward.keyboard-settings/v1',
            'model': 'pc105', 'layout': 'fr', 'variant': '', 'options': '',
        }), 'FR · AZERTY')
        self.assertEqual(keyboard.display_layout_label({
            'schema': 'greyward.keyboard-settings/v1',
            'model': 'pc105', 'layout': 'us', 'variant': 'dvorak', 'options': '',
        }), 'US · DVORAK')
        self.assertEqual(keyboard.display_layout_label({
            'schema': 'greyward.keyboard-settings/v1',
            'model': 'pc105', 'layout': 'us,fr', 'variant': ',oss', 'options': '',
        }), 'US · QWERTY / FR · AZERTY')

    def test_rejects_ambiguous_or_unsafe_keyboard_records(self):
        duplicate = '''\
Section "InputClass"
 Identifier "system-keyboard"
 Option "XkbLayout" "fr"
 Option "XkbLayout" "us"
EndSection
'''
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            keyboard.parse_localed_config(duplicate)

        injected = '''\
Section "InputClass"
 Identifier "system-keyboard"
 Option "XkbLayout" "fr; touch /tmp/unsafe"
EndSection
'''
        with self.assertRaisesRegex(ValueError, 'Invalid XKB layout'):
            keyboard.parse_localed_config(injected)

    def test_same_selected_values_are_written_for_the_greeter_user_and_protected_seat(self):
        settings = {
            'schema': 'greyward.keyboard-settings/v1',
            'model': 'pc105', 'layout': 'us', 'variant': 'dvorak', 'options': '',
        }
        helper_bytes = KEYBOARD_PATH.read_bytes()
        manifest = {'files': {
            'keyboard.json': hashlib.sha256(keyboard.canonical_json(settings)).hexdigest(),
            'keyboard_config.py': hashlib.sha256(helper_bytes).hexdigest(),
        }}
        values = {
            session.BASE / 'desktop.json': json.dumps(manifest).encode(),
            session.BASE / 'keyboard.json': keyboard.canonical_json(settings),
            session.BASE / 'keyboard_config.py': helper_bytes,
        }

        def private_file(path, *_args, **_kwargs):
            return values[Path(path)]

        with patch.object(session, 'private_file', side_effect=private_file):
            self.assertEqual(session.protected_keyboard_environment(), {
                'XKB_DEFAULT_MODEL': 'pc105',
                'XKB_DEFAULT_LAYOUT': 'us',
                'XKB_DEFAULT_VARIANT': 'dvorak',
            })
            self.assertEqual(session.protected_keyboard_environment(), {
                'XKB_DEFAULT_MODEL': 'pc105',
                'XKB_DEFAULT_LAYOUT': 'us',
                'XKB_DEFAULT_VARIANT': 'dvorak',
            })

        protected_session = SESSION_PATH.read_text(encoding='utf-8')
        auth_worker = protected_session[protected_session.index("if kind == 'authentication':"):protected_session.index("elif kind == 'display':")]
        self.assertNotIn('GREYWARD_KEYBOARD_LAYOUT_LABEL', auth_worker)
        self.assertNotIn('protected_keyboard_configuration()', auth_worker)

        production_env = PRODUCTION_ENVIRONMENT.read_text(encoding='utf-8')
        provision = PROVISION.read_text(encoding='utf-8')
        self.assertNotRegex(production_env, r'(?m)^XKB_DEFAULT_LAYOUT=fr$')
        self.assertIn('keyboard_helper=/usr/share/greyward-application-security/desktop/keyboard_config.py', provision)
        self.assertIn('/usr/bin/python3 -I "$keyboard_helper" --write-installed', provision)
        self.assertIn('cat /etc/greyward/keyboard.env >> /etc/skel/.config/labwc/environment', provision)
        self.assertIn('cat /etc/greyward/keyboard.env >> "$production_home/.config/labwc/environment"', provision)
        self.assertIn('XKB_DEFAULT_MODEL=$XKB_DEFAULT_MODEL XKB_DEFAULT_LAYOUT=$XKB_DEFAULT_LAYOUT', provision)


if __name__ == '__main__':
    unittest.main()
