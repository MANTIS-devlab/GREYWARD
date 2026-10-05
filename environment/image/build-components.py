#!/usr/bin/env python3
"""Build/reuse reviewed component RPMs, leaving existing builders in charge."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

REPO = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fingerprint(paths, toolchain):
    files = sorted({p for root in paths for p in ([root] if root.is_file() else root.rglob('*'))
                    if p.is_file() and not any(part in {'target', 'node_modules', '.git', '__pycache__'} for part in p.parts)
                    and p.suffix != '.pyc'})
    items = [(p.relative_to(REPO).as_posix(), digest(p)) for p in files]
    return hashlib.sha256(json.dumps([items, toolchain], separators=(',', ':')).encode()).hexdigest()


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def nevra(path):
    return run('rpm', '-qp', '--qf', '%{NEVRA}', path, capture_output=True, text=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--dms-inputs', type=Path, required=True)
    parser.add_argument('--only', default='dms,security,session,branding')
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    import fcntl
    lock = (output / '.lock').open('a'); fcntl.flock(lock, fcntl.LOCK_EX)
    toolchain = run('rpm', '-q', '--qf', '%{NEVRA}\n', 'rust', 'cargo', 'golang', 'python3', 'rpm-build',
                    'webkit2gtk4.1-devel', capture_output=True, text=True).stdout
    inputs = {'dms': ['packaging/greyward-dms', 'environment/production/dms-release.json',
                       'environment/patches/dms', 'environment/session/greyward-dms',
                       'environment/session/dankmaterialshell/plugins'],
              'security': ['security-center', 'environment/development/build-security-center.sh'],
              'session': ['packaging/greyward-session', 'environment/session',
                          'environment/production/greyward-start-labwc',
                          'environment/production/labwc-autostart', 'environment/production/labwc-environment'],
              'branding': ['packaging/greyward-branding', 'branding']}
    results = json.loads((output/'selected-components.json').read_text()) if (output/'selected-components.json').exists() else {}
    for name in args.only.split(','):
        if name not in inputs: parser.error('Unknown component: ' + name)
        key = fingerprint([REPO / p for p in inputs[name]], toolchain)
        entry = output / name / key; receipt_path = entry / 'receipt.json'
        started = time.monotonic()
        if receipt_path.is_file():
            receipt = json.loads(receipt_path.read_text())
            for relative, sha in receipt['files'].items():
                if digest(entry / relative) != sha: raise SystemExit('Corrupt cached component: ' + name)
            results[name] = dict(receipt, reused=True)
            continue
        if entry.exists(): raise SystemExit('Incomplete build retained: ' + str(entry))
        # Refuse known identity reuse before compiling. A changed downstream
        # input/toolchain needs a new package revision, even in development.
        specs = [REPO / 'security-center/packaging/greyward-security-center.spec', REPO / 'security-center/packaging/greyward-security-context.spec'] if name == 'security' else [REPO / {'dms':'packaging/greyward-dms/greyward-dms.spec', 'session':'packaging/greyward-session/greyward-session.spec', 'branding':'packaging/greyward-branding/SPECS/greyward-branding.spec'}[name]]
        identities = []
        for spec in specs:
            if name == 'dms':
                m=json.loads((REPO / 'environment/production/dms-release.json').read_text())
                identity='greyward-dms-' + m['releaseId'].removeprefix('v')
            else:
                text=spec.read_text(); fields={k:re.search(r'^'+k+r':\s*(\S+)',text,re.M)[1] for k in ('Name','Version','Release')}
                identity='-'.join(fields.values()).replace('%{?dist}','')
            claim=output / 'identities' / identity
            if claim.exists() and claim.read_text().strip() != key:
                raise SystemExit('Increment package revision; changed input reuses ' + identity)
            identities.append(claim)
        entry.mkdir(parents=True)
        if name == 'dms':
            import pwd
            user=pwd.getpwuid(os.getuid()).pw_name
            run('sudo', '-n', 'unshare', '--net', 'runuser', '-u', user, '--', 'bash', REPO/'packaging/greyward-dms/build.sh', args.dms_inputs.resolve(), entry/'build')
        elif name == 'session':
            run('bash', REPO/'packaging/greyward-session/build.sh', entry/'build')
        elif name == 'security':
            env=dict(os.environ, GREYWARD_SECURITY_CENTER_SOURCE=str(REPO/'security-center'), GREYWARD_SECURITY_CENTER_OUTPUT=str(entry/'rpms'))
            run('bash', REPO/'environment/development/build-security-center.sh', env=env)
        else:
            build=entry/'build'
            for folder in ('BUILD','BUILDROOT','SOURCES','SPECS','RPMS','SRPMS'): (build/folder).mkdir(parents=True, exist_ok=True)
            shutil.copytree(REPO/'packaging/greyward-branding/SOURCES', build/'SOURCES', dirs_exist_ok=True)
            for source in ('branding/generated/boot/greyward-symbol-256.png','branding/source/greyward-symbol.svg'):
                shutil.copyfile(REPO/source, build/'SOURCES'/Path(source).name)
            spec=REPO/'packaging/greyward-branding/SPECS/greyward-branding.spec'
            run('rpmbuild','--define','_topdir '+str(build),'-bb',spec)
        rpms = list(entry.rglob('*.rpm'))
        rpms = [p for p in rpms if '/SRPMS/' not in p.as_posix() and '-debug' not in p.name]
        if not rpms: raise SystemExit('No built RPMs: ' + name)
        receipt = {'component':name, 'input_sha256':key, 'build_seconds':time.monotonic()-started,
                   'packages':{p.relative_to(entry).as_posix():nevra(p) for p in rpms},
                   'files':{p.relative_to(entry).as_posix():digest(p) for p in rpms}}
        for p in entry.rglob('security-center-build-manifest.tsv'): receipt['files'][p.relative_to(entry).as_posix()]=digest(p)
        receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
        for claim in identities:
            claim.parent.mkdir(exist_ok=True); claim.write_text(key+'\n')
        results[name]=dict(receipt,reused=False)
    (output/'selected-components.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__ == '__main__': main()
