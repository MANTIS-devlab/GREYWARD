#!/usr/bin/python3 -I
"""Reconcile only installed public service metadata; never application payload."""
import json
import os
from pathlib import Path
import re
import stat
import tempfile

ROOT=Path('/var/lib/flatpak')
TYPE=b'system_u:object_r:greyward_flatpak_service_t:s0'
TARGET=re.compile(r'app/[^/]+/[^/]+/[^/]+/[0-9a-f]{64}/export/share/dbus-1/services/[^/]+\.service')

def reconcile(journal):
    if os.getuid() or os.geteuid():
        raise RuntimeError('Trusted metadata reconciliation required')
    exports=ROOT/'exports/share/dbus-1/services'
    records=[]
    if journal.exists():
        meta=journal.lstat()
        if journal.is_symlink() or not stat.S_ISREG(meta.st_mode) or meta.st_uid or meta.st_mode&0o077 or meta.st_size>2*1024*1024:
            raise RuntimeError('Untrusted reconciliation journal')
        previous=json.loads(journal.read_text())
        if not isinstance(previous,list) or len(previous)>16384:
            raise RuntimeError('Unsupported reconciliation journal')
        for record in previous:
            path=Path(record['path'])
            if not path.is_relative_to(ROOT):raise RuntimeError('Journal outside provider installation')
            try: metadata=path.lstat()
            except FileNotFoundError:continue
            if (metadata.st_dev,metadata.st_ino)==(record['device'],record['inode']):records.append(record)
    def save():
        if len(records)>16384:raise RuntimeError('Excessive reconciliation journal')
        fd,name=tempfile.mkstemp(prefix='.metadata-',dir=journal.parent)
        try:
            with os.fdopen(fd,'w') as output:
                json.dump(records,output,indent=2);output.write('\n');output.flush();os.fsync(output.fileno())
            os.replace(name,journal)
        finally:
            Path(name).unlink(missing_ok=True)
    recorded={(r['path'],r['device'],r['inode']) for r in records}
    def label(path):
        metadata=path.lstat()
        if metadata.st_uid or metadata.st_mode & 0o022 and not path.is_symlink():
            raise RuntimeError('Untrusted public metadata')
        old=os.getxattr(path,'security.selinux',follow_symlinks=False)
        if old.rstrip(b'\0')!=TYPE:
            key=(str(path),metadata.st_dev,metadata.st_ino)
            if key not in recorded:
                records.append({'path':str(path),'device':metadata.st_dev,'inode':metadata.st_ino,'context':old.decode().rstrip('\0')})
                recorded.add(key)
                save()
            os.setxattr(path,'security.selinux',TYPE,follow_symlinks=False)
    if not exports.exists():return
    if exports.is_symlink():raise RuntimeError('Aliased exports directory')
    label(exports)
    entries=list(exports.iterdir())
    if len(entries)>4096:raise RuntimeError('Excessive service metadata')
    for entry in entries:
        if entry.suffix!='.service':continue
        target=entry.resolve(strict=True)
        relative=target.relative_to(ROOT).as_posix()
        if not TARGET.fullmatch(relative) or not target.is_file() or target.stat().st_size>65536:
            raise RuntimeError('Unsupported service export layout')
        for parent in [target,*target.parents]:
            if parent==ROOT:break
            meta=parent.lstat()
            if parent.is_symlink() or meta.st_uid or meta.st_mode&0o022:
                raise RuntimeError('Writable deployment metadata')
        # Only public service directories and the alias chain receive labels;
        # ordinary subjects already have traverse-only access to ancestors.
        label(target.parent);label(target);label(entry)
        parts=target.relative_to(ROOT).parts
        for alias in [ROOT/'app'/parts[1]/'current',ROOT/'app'/parts[1]/parts[2]/parts[3]/'active']:
            if alias.is_symlink():label(alias)
    save()

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--journal',type=Path,required=True)
    opts=parser.parse_args()
    if opts.journal.is_symlink() or not opts.journal.parent.is_dir() or opts.journal.parent.is_symlink() or opts.journal.parent.stat().st_uid or opts.journal.parent.stat().st_mode&0o077:
        raise RuntimeError('Root-private journal required')
    reconcile(opts.journal)
