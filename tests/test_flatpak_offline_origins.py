"""Explicit native offline-origin gate; creates only isolated toy deployments.

Set GREYWARD_TEST_FLATHUB_REPO to an already verified official .flatpakrepo.
No network or host Flatpak installation is used by the installation under test.
"""
import configparser
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR = Path(os.environ.get('GREYWARD_TEST_FLATHUB_REPO', '/nonexistent'))
ENABLED = (os.name == 'posix' and DESCRIPTOR.is_file() and
           shutil.which('flatpak') and shutil.which('unshare') and os.geteuid() == 0)


@unittest.skipUnless(ENABLED, 'Explicit root/Fedora Flatpak namespace gate')
class OfflineOriginTests(unittest.TestCase):
    def fixture(self, directory):
        stage = directory / 'stage'
        (stage / 'offline/flatpak/.ostree').mkdir(parents=True)
        (stage / 'artifacts').mkdir()
        repo = stage / 'offline/flatpak/.ostree/repo'
        env = dict(os.environ)
        for key, name in [('XDG_DATA_HOME', 'data'), ('XDG_CONFIG_HOME', 'config'),
                          ('XDG_CACHE_HOME', 'cache'), ('FLATPAK_SYSTEM_DIR', 'system'),
                          ('FLATPAK_SYSTEM_CACHE_DIR', 'system-cache'),
                          ('FLATPAK_USER_DIR', 'user')]:
            path = directory / name
            path.mkdir()
            env[key] = str(path)
        def run(*args):
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()
        runtime = directory / 'runtime'
        (runtime / 'files').mkdir(parents=True)
        (runtime / 'usr/share').mkdir(parents=True)
        (runtime / 'usr/share/origin-fixture').write_text('fixture\n')
        (runtime / 'metadata').write_text(
            '[Runtime]\nname=org.greyward.OriginRuntime\n'
            'runtime=org.greyward.OriginRuntime/x86_64/test\n'
            'sdk=org.greyward.OriginRuntime/x86_64/test\n')
        run('flatpak', 'build-export', '--runtime', '--arch=x86_64',
            '--collection-id=org.flathub.Stable', str(repo), str(runtime), 'test')
        app = directory / 'app'
        (app / 'files/bin').mkdir(parents=True)
        (app / 'export').mkdir()
        executable = app / 'files/bin/origin-fixture'
        executable.write_text('#!/bin/sh\nexit 0\n')
        executable.chmod(0o755)
        (app / 'metadata').write_text(
            '[Application]\nname=org.greyward.OriginProbe\n'
            'runtime=org.greyward.OriginRuntime/x86_64/test\ncommand=origin-fixture\n')
        run('flatpak', 'build-export', '--arch=x86_64',
            '--collection-id=org.flathub.Stable', str(repo), str(app), 'test')
        run('flatpak', 'build-update-repo', str(repo), '--collection-id=org.flathub.Stable')
        # Query local OSTree directly; remote-info would require remote setup.
        commit = run('ostree', '--repo=' + str(repo), 'rev-parse',
                     'app/org.greyward.OriginProbe/x86_64/test')
        baseline = {'schema': 'greyward.runtime-baseline/v1', 'fedora': '44',
                    'rpms': {'fixture': ['0', '1', '1']},
                    'flatpaks': {'org.greyward.OriginProbe': {
                        'ref': 'app/org.greyward.OriginProbe/x86_64/test', 'commit': commit}}}
        (stage / 'artifacts/runtime-baseline.json').write_text(json.dumps(baseline))
        shutil.copy2(DESCRIPTOR, stage / 'offline/flathub.flatpakrepo')
        for source, destination in [
                ('environment/image/baseline.py', 'baseline.py'),
                ('environment/production/install-offline-flatpaks.sh', 'install.sh')]:
            (stage / destination).write_bytes((ROOT / source).read_bytes().replace(b'\r\n', b'\n'))
        return stage, env, run, baseline

    def install(self, stage, env):
        return subprocess.run(['unshare', '--net', 'bash', str(stage / 'install.sh'),
                               str(stage), '--user'], env=env, capture_output=True,
                              text=True, timeout=45)

    def assert_online_trust_restored(self, env):
        config = configparser.ConfigParser(interpolation=None)
        config.read(Path(env['FLATPAK_USER_DIR']) / 'repo/config')
        remote = config['remote "flathub"']
        self.assertEqual(remote['url'], 'https://dl.flathub.org/repo/')
        self.assertTrue(remote.getboolean('gpg-verify'))
        self.assertFalse(remote.getboolean('xa.disable', fallback=False))
        self.assertNotIn('remote "greyward-offline"', config)

    def test_offline_deployments_keep_flathub_origin_and_online_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, env, run, baseline = self.fixture(Path(temporary))
            result = self.install(stage, env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_online_trust_restored(env)
            rows = run('flatpak', 'list', '--user', '--columns=ref,origin').splitlines()
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row.endswith('\tflathub') for row in rows), rows)

    def test_failed_transaction_also_restores_online_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, env, run, baseline = self.fixture(Path(temporary))
            entry = baseline['flatpaks'].pop('org.greyward.OriginProbe')
            entry['ref'] = 'app/org.greyward.Missing/x86_64/test'
            baseline['flatpaks']['org.greyward.Missing'] = entry
            (stage / 'artifacts/runtime-baseline.json').write_text(json.dumps(baseline))
            result = self.install(stage, env)
            self.assertNotEqual(result.returncode, 0)
            self.assert_online_trust_restored(env)


if __name__ == '__main__':
    unittest.main()
