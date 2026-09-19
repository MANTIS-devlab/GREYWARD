#!/usr/bin/env python3
"""Normalize staged source text for Linux without rewriting artifact inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def prepare(stage):
    stage = Path(stage)
    changed = []
    checked = 0
    for path in sorted(stage.rglob('*')):
        relative = path.relative_to(stage)
        # These are hash-bound inputs, not editable source files.
        if relative.parts[0] in {'artifacts', 'rpms', 'offline'}:
            continue
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        if b'\0' in data:
            continue
        try:
            data.decode('utf-8')
        except UnicodeDecodeError:
            continue
        normalized = data.replace(b'\r\n', b'\n')
        if normalized != data:
            path.write_bytes(normalized)
            changed.append({'path': relative.as_posix(),
                            'source_sha256': hashlib.sha256(data).hexdigest(),
                            'staged_sha256': hashlib.sha256(normalized).hexdigest()})
        first = normalized.split(b'\n', 1)[0]
        if path.suffix == '.sh' or (first.startswith(b'#!') and b'bash' in first):
            subprocess.run(['bash', '-n', str(path)], check=True)
            checked += 1
    return {'schema': 'greyward.staged-text/v1', 'normalized_files': changed,
            'shell_scripts_checked': checked}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True, type=Path)
    args = parser.parse_args()
    report = prepare(args.stage)
    destination = args.stage / 'artifacts/staged-text.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f"Linux stage: normalized {len(report['normalized_files'])} text files; "
          f"checked {report['shell_scripts_checked']} shell scripts")
