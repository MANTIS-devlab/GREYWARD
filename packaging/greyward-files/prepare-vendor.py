#!/usr/bin/env python3
"""Archive Cargo's locked, offline vendor output for the source RPM.

Run `cargo fetch --locked` and `cargo vendor --locked --offline vendor` in the
verified source first. Cargo verifies file checksums again during the RPM build.
This archive contains dependencies only, never Cargo credentials or its cache.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        parser.error('Use an unprivileged builder')
    vendor = args.vendor.resolve(strict=True)
    if not vendor.is_dir() or not any(vendor.glob('*/.cargo-checksum.json')):
        parser.error('Expected Cargo vendor output')
    with args.destination.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0, compresslevel=9) as stream:
            with tarfile.open(fileobj=stream, mode='w') as archive:
                for path in [vendor, *sorted(vendor.rglob('*'))]:
                    if path.is_symlink():
                        raise ValueError('Unexpected symlink in Cargo vendor output')
                    info = archive.gettarinfo(path, 'vendor/' + path.relative_to(vendor).as_posix())
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    if info.isfile():
                        with path.open('rb') as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)
    with args.destination.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    print(json.dumps({'file': args.destination.name, 'sha256': digest}))


if __name__ == '__main__':
    main()
