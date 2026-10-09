#!/usr/bin/python3
"""Fixed isolated Python entry to the extracted Fedora pip test input."""
import os
from pathlib import Path
import runpy
import sys

if os.getuid() != 1002 or Path.cwd() != Path('/home/greyward-guard-probe/deputy-probe/pip-project'):
    raise RuntimeError('Only the separately enrolled offline pip fixture is supported')
selected = Path('/usr/local/lib/greyward-development/pip-probe')
for directory in (selected, *selected.parents):
    metadata = directory.lstat()
    if not directory.is_dir() or directory.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError('Unsafe extracted test input')
sys.path.insert(0, str(selected))
sys.argv = ['pip', 'install', '--no-index', '--no-deps', '--no-build-isolation',
            '--disable-pip-version-check', '--no-cache-dir',
            '--target=/home/greyward-guard-probe/deputy-probe/pip-target', '.']
runpy.run_module('pip', run_name='__main__')
