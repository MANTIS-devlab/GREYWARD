#!/usr/bin/python3 -I
"""Explicit root assembly. Does not enroll, change PAM or restart a session."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

def trusted(path):
    for parent in [path, *path.parents]:
        metadata = parent.lstat()
        if parent.is_symlink() or metadata.st_uid or metadata.st_mode & 0o022:
            raise RuntimeError('Root-owned immutable inputs required')
    if not stat.S_ISREG(path.stat().st_mode):
        raise RuntimeError('Regular input required')
    return hashlib.sha256(path.read_bytes()).hexdigest()

def assemble(source, terminal, desktop, output):
    if os.getuid() or os.geteuid() or output.exists() or output.is_symlink():
        raise RuntimeError('New root-owned assembly required')
    trusted(desktop / 'desktop.json')
    for name in ['worker.py', 'fonts.conf']:
        trusted(source / name)
    trusted(terminal)
    password_helper = Path('/usr/bin/unix_chkpwd')
    trusted(password_helper)
    output.mkdir(mode=0o755,parents=True)
    for original, name in [(terminal,'terminal'),(source/'worker.py','worker.py'),(source/'fonts.conf','fonts.conf'),(password_helper,'unix_chkpwd')]:
        shutil.copyfile(original,output/name)
        (output/name).chmod(0o555 if name in {'terminal','unix_chkpwd'} else 0o444)
    subprocess.run(['/usr/bin/chcon','-t','greyward_admin_exec_t',str(output/'terminal')],check=True,timeout=5)
    subprocess.run(['/usr/bin/chcon','-t','greyward_admin_password_exec_t',str(output/'unix_chkpwd')],check=True,timeout=5)
    manifest = {'schema':'greyward.administration/v1','desktop':trusted(desktop/'desktop.json'),
                'files':{name:trusted(output/name) for name in ['terminal','worker.py','fonts.conf','unix_chkpwd']},
                'tools':{name:trusted(Path(name)) for name in ['/usr/bin/sudo','/usr/bin/bash','/usr/bin/unix_chkpwd']}}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (output/'manifest.json').chmod(0o444)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ['source','terminal','desktop','output']:
        parser.add_argument('--'+name,type=Path,required=True)
    options=parser.parse_args()
    assemble(options.source,options.terminal,options.desktop,options.output)
