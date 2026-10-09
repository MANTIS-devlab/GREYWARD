"""Synthetic PEP 517 backend: valid empty wheel plus a fixed credential probe."""
from pathlib import Path
import subprocess
import zipfile


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    subprocess.run(['/usr/bin/python3', '-I', '/usr/local/libexec/greyward-application-security-task-probe.py'],
                   check=True, timeout=5)
    name = 'greyward_synthetic_task-1.0.0-py3-none-any.whl'
    entries = {
        'greyward_synthetic_task-1.0.0.dist-info/METADATA': 'Metadata-Version: 2.1\nName: greyward-synthetic-task\nVersion: 1.0.0\n',
        'greyward_synthetic_task-1.0.0.dist-info/WHEEL': 'Wheel-Version: 1.0\nGenerator: synthetic-probe\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        'greyward_synthetic_task-1.0.0.dist-info/RECORD': '',
    }
    with zipfile.ZipFile(Path(wheel_directory) / name, 'w') as wheel:
        for entry, content in entries.items():
            wheel.writestr(entry, content)
    return name
