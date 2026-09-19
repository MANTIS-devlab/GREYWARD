"""Exercise Windows-source staging with a real Linux shell."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('stage_text', ROOT / 'environment/image/stage-text.py')
stage_text = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_text)


def has_working_bash():
    """Return whether the discovered Bash can actually execute on this host."""
    bash = shutil.which('bash')
    if not bash:
        return False
    try:
        return subprocess.run(
            [bash, '-c', 'exit 0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
    except OSError:
        return False


@unittest.skipUnless(has_working_bash(), 'Requires a working Linux Bash runtime')
class StageTextTests(unittest.TestCase):
    def test_windows_script_executes_after_staging_without_changing_artifacts(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            script = root / 'provision.sh'
            script.write_bytes(b'#!/bin/bash\r\nset -euo pipefail\r\nprintf ready\r\n')
            config = root / 'session.conf'
            config.write_bytes(b'key=value\r\n')
            binary = root / 'image.bin'
            binary.write_bytes(b'\0\r\n')
            (root / 'artifacts').mkdir()
            baseline = root / 'artifacts/runtime-baseline.json'
            baseline.write_bytes(b'{"original":true}\r\n')
            self.assertNotEqual(subprocess.run(['bash', str(script)], capture_output=True).returncode, 0)
            report = stage_text.prepare(root)
            result = subprocess.run(['bash', str(script)], capture_output=True, check=True)
            self.assertEqual(result.stdout, b'ready')
            self.assertEqual(config.read_bytes(), b'key=value\n')
            self.assertEqual(binary.read_bytes(), b'\0\r\n')
            self.assertEqual(baseline.read_bytes(), b'{"original":true}\r\n')
            self.assertEqual(len(report['normalized_files']), 2)
            self.assertEqual(stage_text.prepare(root)['normalized_files'], [])

    def test_invalid_shell_stops_staging(self):
        with tempfile.TemporaryDirectory() as name:
            script = Path(name) / 'broken.sh'
            script.write_bytes(b'if then\r\n')
            with self.assertRaises(subprocess.CalledProcessError):
                stage_text.prepare(name)
