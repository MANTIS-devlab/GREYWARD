#!/usr/bin/env python3
"""Opt-in signed Office repository acceptance in disposable DNF/RPM roots.

Clones the installed RPM database read-only, never installs on the reference,
and never modifies host repository configuration, trust or graphical sessions.
Requires a complete prepared repository and its metadata signing authority.
The negative repository/key are private test artifacts, never publication inputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess

PACKAGES = ['greyward-writer', 'greyward-sheets', 'greyward-pdf', 'greyward-slides']


def run(argv, log=None, env=None, accepted=(0,)):
    result = subprocess.run(list(map(str, argv)), env=env, capture_output=True, text=True, timeout=600)
    if log:
        log.write_text(result.stdout + result.stderr, encoding='utf-8')
    if result.returncode not in accepted:
        raise RuntimeError(f'{argv[0]} exited {result.returncode}: {(result.stdout + result.stderr)[-2000:]}')
    return result


def rpm_root(directory, database, key):
    root = directory / 'root'
    target = root / database.relative_to('/')
    target.mkdir(parents=True)
    with sqlite3.connect((database / 'rpmdb.sqlite').as_uri() + '?mode=ro', uri=True) as source:
        with sqlite3.connect(target / 'rpmdb.sqlite') as destination:
            source.backup(destination)
    if Path('/sys/fs/selinux/enforce').exists():
        run(['chcon', '-R', '--reference=' + str(database), target])
    run(['rpm', '--root', root, '--import', key])
    return root


def transaction_test(directory, repository, key, database):
    directory.mkdir(mode=0o700)
    root = rpm_root(directory, database, key)
    repo_dir = directory / 'repos'; repo_dir.mkdir()
    (repo_dir / 'office.repo').write_text(
        '[office-test]\nname=Isolated Office test\nbaseurl=' + repository.as_uri()
        + '\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=' + key.as_uri()
        + '\nmetadata_expire=0\nskip_if_unavailable=False\nincludepkgs=' + ' '.join(PACKAGES) + '\n')
    config = directory / 'dnf.conf'
    config.write_text('[main]\ninstall_weak_deps=False\ngpgcheck=True\n')
    before = run(['rpm', '--root', root, '-q', *PACKAGES]).stdout
    command = ['dnf5', '--installroot=' + str(root), '--config=' + str(config), '--releasever=44', '-y',
               '--setopt=reposdir=' + str(repo_dir), '--setopt=cachedir=' + str(directory / 'cache'),
               '--setopt=system_cachedir=' + str(directory / 'system-cache'),
               '--setopt=logdir=' + str(directory / 'logs'), '--setopt=tsflags=test',
               'upgrade', *PACKAGES]
    result = run(command, directory / 'dnf.log', accepted=(0, 1))
    after = run(['rpm', '--root', root, '-q', *PACKAGES]).stdout
    if before != after:
        raise RuntimeError('The disposable transaction test unexpectedly changed installed headers')
    return result


def main(args):
    if os.geteuid() != 0:
        raise ValueError('Run this isolated RPM acceptance with root authority')
    if args.output.exists():
        raise ValueError('Use a fresh private output directory')
    args.output.mkdir(mode=0o700)
    repository = args.repository.resolve()
    key = repository / 'RPM-GPG-KEY-greyward-office'
    database = Path(run(['rpm', '--eval', '%{_dbpath}']).stdout.strip())
    valid = transaction_test(args.output / 'valid', repository, key, database)
    if valid.returncode:
        raise RuntimeError('Valid repository transaction failed; inspect valid/dnf.log')
    if not all(name in valid.stdout for name in PACKAGES):
        raise RuntimeError('Valid transaction did not advertise all four Office upgrades')
    negative = args.output / 'negative-repository'; negative.mkdir()
    for source in repository.glob('*.rpm'):
        shutil.copyfile(source, negative / source.name)
    writer = list(negative.glob('greyward-writer-*.x86_64.rpm'))
    if len(writer) != 1:
        raise ValueError('Exactly one Writer RPM is required')
    test_home = args.output / 'negative-key'; test_home.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(test_home))
    run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
         'GREYWARD Office negative-test ONLY', 'ed25519', 'sign', '1d'], env=env)
    text = run(['gpg', '--batch', '--with-colons', '--list-secret-keys', '--fingerprint'], env=env).stdout
    fingerprint = next(line.split(':')[9] for line in text.splitlines() if line.startswith('fpr:'))
    run(['rpmsign', '--delsign', writer[0]])
    run(['rpmsign', '--define', '_openpgp_sign_id ' + fingerprint, '--addsign', writer[0]], env=env)
    run(['createrepo_c', negative])
    # Trusted metadata with an untrusted package signature isolates the RPM check.
    run(['gpg', '--batch', '--armor', '--local-user', args.fingerprint, '--detach-sign',
         negative / 'repodata/repomd.xml'], env=dict(os.environ, GNUPGHOME=str(args.signing_home.resolve())))
    # A wrong metadata-signing argument must not turn a repository failure into
    # a false claim that the package-signature check was exercised.
    verify_home = args.output / 'metadata-trust'; verify_home.mkdir(mode=0o700)
    verify_env = dict(os.environ, GNUPGHOME=str(verify_home))
    run(['gpg', '--batch', '--import', key], env=verify_env)
    run(['gpg', '--batch', '--verify', negative / 'repodata/repomd.xml.asc',
         negative / 'repodata/repomd.xml'], env=verify_env)
    invalid = transaction_test(args.output / 'invalid', negative, key, database)
    if invalid.returncode == 0 or not any(word in (invalid.stdout + invalid.stderr).lower()
                                        for word in ('pgp', 'gpg', 'signature', 'public key')):
        raise RuntimeError('Untrusted RPM signature was not explicitly rejected; inspect invalid/dnf.log')
    result = {'schema': 'greyward.office-repository-acceptance/v1',
              'valid_four_package_transaction_test': True, 'untrusted_package_signature_rejected': True,
              'negative_repository_metadata_signature_verified': True,
              'disposable_office_headers_unchanged': True,
              'trusted_key_sha256': hashlib.sha256(key.read_bytes()).hexdigest()}
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--signing-home', type=Path, required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.absolute()
    main(args)
