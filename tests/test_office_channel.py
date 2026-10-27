import configparser
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('office_channel', ROOT / 'packaging/greyward-office/stage-channel.py')
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)


class OfficeChannelStaging(unittest.TestCase):
    def fixture(self, temporary, published=True):
        root = Path(temporary)
        source = root / 'packaging/greyward-office'
        source.mkdir(parents=True)
        for name in ('channel.json', 'greyward-office.repo.in'):
            shutil.copyfile(ROOT / 'packaging/greyward-office' / name, source / name)
        shutil.copytree(ROOT / 'packaging/greyward-office/keys', source / 'keys')
        policy = json.loads((source / 'channel.json').read_text())
        policy['published'] = published
        (source / 'channel.json').write_text(json.dumps(policy))
        return root, source, root / 'offline'

    def test_unpublished_channel_does_not_create_installed_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _, offline = self.fixture(temporary, False)
            self.assertFalse(channel.stage(root, offline))
            self.assertFalse(offline.exists())
            with self.assertRaisesRegex(ValueError, 'refuse an image'):
                channel.stage(root, offline, require_published=True)

    def test_published_channel_preserves_signature_checks_and_four_package_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, source, offline = self.fixture(temporary)
            self.assertTrue(channel.stage(root, offline))
            config = configparser.ConfigParser(interpolation=None)
            config.read(offline / 'update-repos/greyward-office.repo')
            repo = config['greyward-office']
            self.assertEqual([repo[k] for k in ('enabled', 'gpgcheck', 'repo_gpgcheck')], ['1', '1', '1'])
            self.assertEqual(repo['includepkgs'], channel.PACKAGES)
            self.assertEqual(repo['mirrorlist'], channel.MIRRORLIST)
            self.assertNotIn('baseurl', repo)
            self.assertEqual((offline / 'keys' / channel.KEY).read_bytes(), (source / 'keys' / channel.KEY).read_bytes())
            # The builder's online resolver must not receive this feed.
            self.assertFalse((offline / 'repos').exists())
            self.assertTrue(channel.stage(root, offline, require_published=True, verify=True))
            path = offline / 'update-repos/greyward-office.repo'
            original = path.read_bytes()
            path.write_bytes(original.replace(b'gpgcheck=1', b'gpgcheck=0'))
            with self.assertRaisesRegex(ValueError, 'stale'):
                channel.stage(root, offline, require_published=True, verify=True)
            path.write_bytes(original)
            with self.assertRaisesRegex(ValueError, 'already staged'):
                channel.stage(root, offline)

    def test_changed_key_or_weakened_repository_fails_before_writing(self):
        for field, old, new in (('key', b'PUBLIC KEY', b'ALTERED KEY'),
                                ('repo', 'gpgcheck=1', 'gpgcheck=0'),
                                ('repo', channel.PACKAGES, '*'),
                                ('repo', channel.MIRRORLIST, 'https://example.invalid/'),
                                ('repo', 'mirrorlist=', 'baseurl=')):
            with self.subTest(field=field, new=new), tempfile.TemporaryDirectory() as temporary:
                root, source, offline = self.fixture(temporary)
                if field == 'key':
                    path = source / 'keys' / channel.KEY
                    path.write_bytes(path.read_bytes().replace(old, new))
                else:
                    path = source / 'greyward-office.repo.in'
                    path.write_text(path.read_text().replace(old, new))
                with self.assertRaises(ValueError):
                    channel.stage(root, offline)
                self.assertFalse(offline.exists())

    def test_offline_builder_actually_stages_future_channel_but_excludes_it_from_resolution(self):
        spec = importlib.util.spec_from_file_location('office_offline_fixture', ROOT / 'environment/image/build-offline.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage, work, offline = (root / name for name in ('stage', 'work', 'offline'))
            for path in (stage, work, offline):
                path.mkdir()
            _, source, _ = self.fixture(stage / 'office-source')
            shutil.copyfile(ROOT / 'packaging/greyward-office/stage-channel.py', source / 'stage-channel.py')
            (stage / 'repositories.txt').write_text('')
            original_copy = shutil.copyfile
            def fedora_key(source_path, destination):
                if Path(source_path).as_posix() == '/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64':
                    Path(destination).write_bytes(b'isolated Fedora key fixture')
                else:
                    original_copy(source_path, destination)
            def execute(*args):
                subprocess.run([sys.executable, *map(str, args[1:])], check=True, capture_output=True)
            with patch.object(builder.shutil, 'copyfile', side_effect=fedora_key), patch.object(builder, 'run', side_effect=execute):
                resolver = builder.prepare_repositories(stage, work, offline)
            self.assertTrue((offline / 'update-repos/greyward-office.repo').is_file())
            self.assertTrue((offline / 'keys' / channel.KEY).is_file())
            self.assertEqual({p.name for p in resolver.glob('*.repo')}, {'fedora.repo', 'updates.repo'})
            policy_path = source / 'channel.json'
            policy = json.loads(policy_path.read_text()); policy['published'] = False
            policy_path.write_text(json.dumps(policy))
            unpublished_work, unpublished_offline = root / 'work-unpublished', root / 'offline-unpublished'
            unpublished_work.mkdir(); unpublished_offline.mkdir()
            with patch.object(builder.shutil, 'copyfile', side_effect=fedora_key), patch.object(builder, 'run', side_effect=execute):
                with self.assertRaises(subprocess.CalledProcessError):
                    builder.prepare_repositories(stage, unpublished_work, unpublished_offline)
            self.assertFalse((unpublished_offline / 'update-repos/greyward-office.repo').exists())


if __name__ == '__main__':
    unittest.main()
