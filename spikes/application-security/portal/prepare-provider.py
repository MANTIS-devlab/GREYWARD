#!/usr/bin/python3
"""Prepare the pinned experimental provider; never install or select it."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source_archive', type=Path)
    parser.add_argument('output_directory', type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    receipt = json.loads((here / 'source.json').read_text())
    archive = args.source_archive.resolve(strict=True)
    if archive.stat().st_size > 50 * 1024 * 1024:
        parser.error('Provider source archive exceeds the experimental bound')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != receipt['source_sha256']:
        parser.error('Provider source archive does not match the recorded pin')
    patch = here / 'protected-named-export.patch'
    if hashlib.sha256(patch.read_bytes()).hexdigest() != receipt['patch_sha256']:
        parser.error('Patch receipt changed')
    output = args.output_directory.absolute()
    if output.exists():
        parser.error('Output already exists; never overwrite an earlier experiment')
    output.mkdir(mode=0o700)
    with tarfile.open(archive) as bundle:
        bundle.extractall(output, filter='data')
    source = output / ('xdg-desktop-portal-' + receipt['upstream_version'])
    target = source / 'document-portal' / 'document-portal.c'
    if hashlib.sha256(target.read_bytes()).hexdigest() != receipt['input_file_sha256']:
        parser.error('Provider source preimage changed; do not resolve automatically')
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                   cwd=source, check=True)
    if hashlib.sha256(target.read_bytes()).hexdigest() != receipt['output_file_sha256']:
        raise SystemExit('Provider result does not match the reviewed output')
    print('Experimental provider preimage/patch/result verified')


if __name__ == '__main__':
    main()
