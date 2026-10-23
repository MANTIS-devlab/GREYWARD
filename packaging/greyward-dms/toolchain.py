#!/usr/bin/env python3
"""Extract an exact reviewed Go toolchain into a new unprivileged build tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile


def prepare(manifest, archive, output):
    release = json.loads(Path(manifest).read_text())
    pin = release['build']['toolchain']
    source = release['inputs'][pin['input']]
    if output.exists() or output.is_symlink():
        raise ValueError('Toolchain output must be new')
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != source['sha256']:
            raise ValueError('Go toolchain archive checksum mismatch')
    if source['root'] != 'go' or pin['goVersion'] != f"go version {pin['version']} linux/amd64":
        raise ValueError('Unreviewed Go toolchain layout')
    output.mkdir(mode=0o700)
    with tarfile.open(archive) as stream:
        stream.extractall(output, filter='data')
    executable = output / 'go/bin/go'
    # This is build tooling, never installed in the runtime or the host PATH.
    environment = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off')
    actual = subprocess.check_output([str(executable), 'version'], text=True, env=environment).strip()
    if actual != pin['goVersion']:
        raise ValueError('Go executable version differs from the reviewed toolchain')
    return executable


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(prepare(args.manifest, args.archive, args.output))
