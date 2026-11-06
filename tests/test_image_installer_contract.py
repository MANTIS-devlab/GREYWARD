"""Reject regressions at the composed installer interaction boundary."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer_contract', ROOT / 'environment/image/installer-contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class InstallerContractTests(unittest.TestCase):
    def setUp(self):
        self.installer = (ROOT / 'environment/image/installer.ks.tmpl').read_text()
        self.configs = {'EFI/BOOT/grub.cfg': '''set default="0"
menuentry 'Install GREYWARD OS' {
linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=GREYWARD-INSTALLER-44 quiet inst.profile=greyward inst.ks=hd:LABEL=GREYWARD-INSTALLER-44:/installer.ks inst.updates=hd:LABEL=GREYWARD-INSTALLER-44:/updates.img
}
'''}
        self.branding = {
            contract.BRANDING[0]: (ROOT / 'packaging/greyward-branding/SOURCES/greyward-anaconda.conf').read_bytes(),
            contract.BRANDING[1]: b'known-good-stylesheet',
            contract.BRANDING[2]: b'known-good-logo',
        }
        self.expected = copy.deepcopy(self.branding)
        self.packages = '%packages --exclude-weakdeps\nbash\n-openssh-server\n%end\n'

    def check(self):
        return contract.validate(self.installer, self.configs, self.branding,
                                 self.expected, self.packages)

    def test_native_interactive_contract_passes(self):
        self.assertEqual(self.check()['state'], 'PASS')

    def test_non_english_default_rejected(self):
        self.installer = self.installer.replace('lang en_US.UTF-8', 'lang fr_FR.UTF-8')
        with self.assertRaisesRegex(ValueError, 'language must be English'):
            self.check()

    def test_later_language_override_rejected(self):
        self.installer = self.installer.replace('lang en_US.UTF-8',
                                                'lang en_US.UTF-8\nlang fr_FR.UTF-8')
        with self.assertRaisesRegex(ValueError, 'language must be English'):
            self.check()

    def test_keyboard_preanswer_rejected_even_for_us(self):
        for layout in ('us', 'fr'):
            with self.subTest(layout=layout):
                original = self.installer
                self.installer = 'keyboard --vckeymap=' + layout + '\n' + original
                with self.assertRaisesRegex(ValueError, 'Keyboard layout must remain interactive'):
                    self.check()
                self.installer = original

    def test_boot_keymap_bypass_rejected(self):
        self.configs = {p: s.replace(' quiet', ' quiet inst.keymap=fr')
                        for p, s in self.configs.items()}
        with self.assertRaisesRegex(ValueError, 'Boot keymap must not bypass'):
            self.check()

    def test_hidden_software_page_requires_real_explicit_packages(self):
        for value in ('', '%packages --exclude-weakdeps\n%end\n',
                      '%packages --exclude-weakdeps\n-openssh-server\n%end\n',
                      '%packages --exclude-weakdeps\n@^workstation-product-environment\n%end\n'):
            with self.subTest(value=value):
                self.packages = value
                with self.assertRaisesRegex(ValueError, 'explicit nonempty ISO-local packages'):
                    self.check()

    def test_hiding_keyboard_or_language_page_rejected(self):
        for setting, extra in ((b'hidden_spokes =', b'KeyboardSpoke'),
                               (b'hidden_webui_pages =', b'anaconda-screen-language')):
            with self.subTest(extra=extra):
                original = self.branding[contract.BRANDING[0]]
                self.branding[contract.BRANDING[0]] = original.replace(setting, setting + b' ' + extra)
                self.expected = copy.deepcopy(self.branding)
                with self.assertRaisesRegex(ValueError, 'pages suppressed'):
                    self.check()
                self.branding[contract.BRANDING[0]] = original

    def test_geolocation_cannot_replace_english_default(self):
        self.branding[contract.BRANDING[0]] = self.branding[contract.BRANDING[0]].replace(
            b'use_geolocation = False', b'use_geolocation = True')
        self.expected = copy.deepcopy(self.branding)
        with self.assertRaisesRegex(ValueError, 'GeoIP'):
            self.check()

    def test_predefined_account_rejected(self):
        self.installer = 'user --name=predefined --password=hash --iscrypted\n' + self.installer
        with self.assertRaisesRegex(ValueError, 'preseeded.*user'):
            self.check()

    def test_preseeded_encryption_rejected(self):
        self.installer = self.installer.replace('--type=btrfs --encrypted', '--type=btrfs --encrypted --passphrase=preset')
        with self.assertRaisesRegex(ValueError, 'autopart'):
            self.check()

    def test_changed_partition_flow_rejected(self):
        self.installer = self.installer.replace('--type=btrfs', '--type=lvm')
        with self.assertRaisesRegex(ValueError, 'autopart'):
            self.check()

    def test_additional_partition_recipe_rejected(self):
        self.installer = 'part / --fstype=ext4 --size=10000\n' + self.installer
        with self.assertRaisesRegex(ValueError, 'bypassed: part'):
            self.check()

    def test_foreign_include_rejected(self):
        self.installer = self.installer.replace(
            '/run/install/repo/greyward/production/offline/installer-packages.ks', '/answers.ks')
        with self.assertRaisesRegex(ValueError, 'Known-good.*%include'):
            self.check()

    def test_answer_media_routing_rejected(self):
        self.configs = {p: s.replace('inst.ks=hd:LABEL=GREYWARD-INSTALLER-44:/installer.ks',
                                    'inst.ks=hd:LABEL=GREYWARD-TEST-ANSWERS:/answers.ks')
                        for p, s in self.configs.items()}
        with self.assertRaisesRegex(ValueError, 'Wrong inst.ks'):
            self.check()

    def test_missing_updates_on_one_boot_path_rejected(self):
        self.configs['boot/grub2/grub.cfg'] = self.configs['EFI/BOOT/grub.cfg'].replace(
            ' inst.updates=hd:LABEL=GREYWARD-INSTALLER-44:/updates.img', '')
        with self.assertRaisesRegex(ValueError, 'Wrong inst.updates'):
            self.check()

    def test_disabled_plymouth_rejected(self):
        self.configs = {p: s.replace(' quiet', ' quiet plymouth.enable=0') for p, s in self.configs.items()}
        with self.assertRaisesRegex(ValueError, 'LUKS presentation disabled'):
            self.check()

    def test_hidden_account_page_rejected(self):
        self.branding[contract.BRANDING[0]] = self.branding[contract.BRANDING[0]].replace(
            b'hidden_spokes =', b'hidden_spokes = user')
        self.expected = copy.deepcopy(self.branding)
        with self.assertRaisesRegex(ValueError, 'pages suppressed'):
            self.check()

    def test_stale_or_missing_branding_rejected(self):
        self.branding[contract.BRANDING[2]] = b'stale-logo'
        with self.assertRaisesRegex(ValueError, 'differs from selected branding RPM'):
            self.check()
        del self.branding[contract.BRANDING[2]]
        with self.assertRaisesRegex(ValueError, 'Missing or unexpected'):
            self.check()

    def test_malformed_updates_archive_rejected(self):
        import gzip
        with self.assertRaisesRegex(ValueError, 'Missing archive trailer'):
            contract.archive_files(gzip.compress(b'broken'))


if __name__ == '__main__':
    unittest.main()
