"""Ordinary shell cache follows verified payload bytes, never fixed RPM mtimes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix', 'Linux packaged shell wrapper')
class DmsQmlCache(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('GREYWARD_QML_CACHE_NATIVE') == '1', 'explicit private Qt cache fixture')
    def test_native_qt_reads_changed_source_with_same_mtime_in_new_namespace(self):
        self.assertEqual(os.geteuid(), 0, 'child-only network isolation requires root')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for name in ('home', 'runtime', 'cache-a', 'cache-b'):
                (base / name).mkdir(mode=0o700)
            source = base / 'cache-proof.qml'
            source.write_text('import QtQuick\nimport Quickshell\nShellRoot { CacheValue { id:observed } Timer { interval:100; running:true; onTriggered: { console.info("CACHE_STATE="+observed.value); Qt.exit(0); } } }\n')
            dependency = base / 'CacheValue.qml'
            template = 'import QtQuick\nQtObject { property string value: "VALUE" }\n'
            dependency.write_text(template.replace('VALUE', 'OLD'))
            env = dict(os.environ, HOME=str(base / 'home'), XDG_RUNTIME_DIR=str(base / 'runtime'),
                       XDG_CONFIG_HOME=str(base / 'home/config'), XDG_CACHE_HOME=str(base / 'home/cache'),
                       QML_FORCE_DISK_CACHE='1', QML_DISK_CACHE_PATH=str(base / 'cache-a'),
                       QT_QPA_PLATFORM='offscreen', QT_QUICK_BACKEND='software',
                       DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent', DBUS_SYSTEM_BUS_ADDRESS='unix:path=/nonexistent')
            def run():
                result = subprocess.run(['unshare', '-n', 'qs', '-p', str(source)], env=env, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout)
                return result.stdout
            self.assertIn('CACHE_STATE=OLD', run())
            if not list((base / 'cache-a').glob('*.qmlc')):
                self.skipTest('This private Quickshell fixture did not emit disk-cache units; warm-cache coverage unavailable')
            stamp = dependency.stat().st_mtime_ns
            dependency.write_text(template.replace('VALUE', 'NEW')); os.utime(dependency, ns=(stamp, stamp))
            # Qt releases may invalidate more aggressively. Require correctness
            # in the new namespace, without requiring an upstream cache bug.
            old_namespace = run()
            print('NATIVE_QT_PRIOR_NAMESPACE_STALE', 'CACHE_STATE=OLD' in old_namespace)
            env['QML_DISK_CACHE_PATH'] = str(base / 'cache-b')
            self.assertIn('CACHE_STATE=NEW', run())
            self.assertTrue(list((base / 'cache-b').glob('*.qmlc')))

    def test_real_wrapper_namespaces_cache_by_receipt_and_preserves_old_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); runtime = base / 'runtime'; (runtime / 'bin').mkdir(parents=True)
            receipt = runtime / 'release.json'; receipt.write_bytes(b'first verified receipt\n')
            binary = runtime / 'bin/dms'
            binary.write_text('#!/usr/bin/python3\nimport json,os\nprint(json.dumps({key:os.environ.get(key) for key in ("QML_DISK_CACHE_PATH","DMS_SHELL_DIR")}))\n')
            binary.chmod(0o755)
            verifier = base / 'verify'; verifier.write_text('#!/bin/sh\nprintf "%s\\n" "' + str(runtime) + '"\n'); verifier.chmod(0o755)
            wrapper = base / 'greyward-dms'
            wrapper.write_bytes((ROOT / 'environment/session/greyward-dms').read_bytes().replace(b'/usr/libexec/greyward-dms-verify', str(verifier).encode()))
            wrapper.chmod(0o755)
            env = dict(os.environ, HOME=str(base / 'home'), XDG_CACHE_HOME=str(base / 'cache'), QML_DISK_CACHE_PATH=str(base / 'stale'))
            def run():
                return json.loads(subprocess.check_output([str(wrapper), 'run'], env=env, text=True))
            first = run(); expected = base / 'cache/greyward/dms-qml' / hashlib.sha256(receipt.read_bytes()).hexdigest()
            self.assertEqual(first['QML_DISK_CACHE_PATH'], str(expected))
            expected.mkdir(parents=True); saved = expected / 'retained.qmlc'; saved.write_bytes(b'old cache retained')
            self.assertEqual(run(), first)
            stamp = receipt.stat().st_mtime_ns
            receipt.write_bytes(b'other verified receipt\n'); os.utime(receipt, ns=(stamp, stamp))
            self.assertNotEqual(run()['QML_DISK_CACHE_PATH'], first['QML_DISK_CACHE_PATH'])
            self.assertEqual(saved.read_bytes(), b'old cache retained')
            env.pop('XDG_CACHE_HOME'); final = run()
            self.assertTrue(final['QML_DISK_CACHE_PATH'].startswith(str(base / 'home/.cache/greyward/dms-qml') + '/'))
            self.assertEqual(final['DMS_SHELL_DIR'], str(runtime / 'shell'))


if __name__ == '__main__':
    unittest.main()
