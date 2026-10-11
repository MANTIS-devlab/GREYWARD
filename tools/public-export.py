#!/usr/bin/env python3
"""Create a sanitized source snapshot; never copy Git history or delete sources."""
import argparse
import fnmatch
import json
import re
import shutil
import subprocess
from pathlib import Path


def excluded(path, policy):
    if path == '.env.example' or fnmatch.fnmatchcase(path, '.env.*.example'):
        return False
    return path != policy['retainedHistoryIndex'] and any(
        fnmatch.fnmatchcase(path, pattern) for pattern in policy['excludedPaths'])


def sanitized_text(text, relative, excluded_files):
    if relative == 'README.md':
        safe_image = 'docs/assets/screenshots/greyward-desktop-security-center.png'
        text = text.replace('docs/assets/screenshots/greyward-desktop-overview.gif', safe_image)
        text = re.sub(r'<p align="center">\s*<img src="docs/assets/screenshots/greyward-desktop-threat-notification.png"[^>]*>\s*</p>', '', text)
        text = re.sub(r'\| Desktop overview \| Everyday application use \|\s*\| :---: \| :---: \|\s*\| <img[^\n]+greyward-desktop-browser.png[^\n]+\|',
                      '![GREYWARD Security Center](' + safe_image + ')', text)
    if relative == 'docs/history/README.md':
        return ('# Development evidence\n\nInternal machine logs and dated development-session reports are retained privately.\n'
                'Public support and validation limits are documented in [current status](../STATUS.md)\n'
                'and the [documentation index](../INDEX.md). Source tests do not establish installed-system acceptance.\n')
    if relative.endswith('.md'):
        parent = Path(relative).parent
        def link(match):
            target = match.group(2).split('#')[0]
            if re.match(r'^[a-zA-Z]+:', target) or target.startswith('#'):
                return match.group(0)
            import posixpath
            resolved = posixpath.normpath((parent / target).as_posix())
            if resolved in excluded_files:
                return match.group(1) + ' (private development evidence)'
            return match.group(0)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', link, text)
        text = re.sub(r'`(?:F:|C:)\\[^`]+`', '`<local workspace>`', text)
        text = re.sub(r'F:/GREYWARD[^\s)`]*', '<local workspace>', text)
        text = text.replace('192.168.1.149', '<development-host>')
        text = text.replace('`.149`', '`<development-host>`')
        text = text.replace('GREYWARD-ALPHA-GEN2-20260828', '<development VM>')
        text = text.replace('GREYWARD ALPHA GEN2', '<development VM>')
        text = text.replace('antoi', '<local-user>')
        text = text.replace('stendev', 'example-user')
    if relative.endswith(('.md', '.json')):
        text = text.replace('/home/stendev', '/home/example-user')
    return text


def snapshot(source, destination):
    source, destination = source.resolve(), destination.resolve()
    if destination == source or source in destination.parents:
        raise ValueError('Destination must be outside the private source repository')
    if destination.exists() and any(destination.iterdir()):
        raise ValueError('Destination must be absent or empty')
    policy = json.loads((source / 'tools/publication-policy.json').read_text())
    raw = subprocess.check_output(['git', '-C', str(source), 'ls-files', '--cached', '--others', '--exclude-standard', '-z'])
    paths = sorted(set(p.decode('utf-8') for p in raw.split(b'\0') if p))
    omitted = {p for p in paths if excluded(p, policy)}
    destination.mkdir(parents=True, exist_ok=True)
    copied = []
    for relative in paths:
        src = source / relative
        if relative in omitted or not src.is_file():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        template = policy.get('publicTemplates', {}).get(relative)
        if template:
            shutil.copy2(source / template, target)
            copied.append(relative)
            continue
        data = src.read_bytes()
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            shutil.copy2(src, target)
        else:
            # Preserve non-document code, patch and manifest bytes exactly.
            cleaned = sanitized_text(text, relative, omitted)
            target.write_bytes(data if cleaned == text else cleaned.encode('utf-8'))
        copied.append(relative)
    missing = [p for p in policy['requiredPaths'] if not (destination / p).is_file()]
    if missing:
        raise ValueError('Incomplete public source snapshot: ' + ', '.join(missing))
    return {'schema': 'greyward.public-export/v1', 'files': len(copied),
            'excluded': sorted(omitted), 'sourceHistoryCopied': False}


def audit_public(source):
    source = source.resolve()
    policy = json.loads((source / 'tools/publication-policy.json').read_text())
    paths = subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z']).split(b'\0')
    forbidden = [p.decode() for p in paths if p and excluded(p.decode(), policy)]
    missing = [p for p in policy['requiredPaths'] if not (source/p).is_file()]
    if forbidden or missing:
        raise ValueError(json.dumps({'privateFiles': forbidden, 'missingPublicInputs': missing}))
    return {'schema': 'greyward.public-audit/v1', 'ok': True, 'trackedFiles': len(paths)-1}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--check-public', action='store_true')
    args = parser.parse_args()
    if not args.check_public and args.destination is None:
        parser.error('--destination is required for a snapshot')
    print(json.dumps(audit_public(args.source) if args.check_public else snapshot(args.source, args.destination), indent=2))
