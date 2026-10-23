"""Execute the spec's Cargo commands against an intentionally stale cache."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux RPM build contract')
class SecurityPackageBuilds(unittest.TestCase):
    def test_stale_first_party_outputs_are_rebuilt_and_dependencies_retained(self):
        for spec, binaries in (
            ('greyward-security-center.spec', ('greyward-security-center', 'greyward-security-posture', 'greyward-security-profile')),
            ('application-security/greyward-application-security-experimental.spec', ('greyward-application-security',)),
        ):
            with self.subTest(spec=spec), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / 'target'
                target.mkdir()
                (target / 'dependency-cache').write_text('retained')
                for name in binaries:
                    (target / name).write_text('old cached executable')
                cargo = root / 'cargo'
                cargo.write_text('''#!/usr/bin/python3
import os,sys
from pathlib import Path
t=Path(os.environ['CARGO_TARGET_DIR']);args=sys.argv[1:]
owners={'greyward-security-center':['greyward-security-center'],
        'greyward-security-backends':['greyward-security-posture','greyward-security-profile'],
        'greyward-application-security':['greyward-application-security']}
packages=[args[i+1] for i,arg in enumerate(args[:-1]) if arg=='-p']
if args[0]=='clean':
 assert '--release' in args
 for package in packages:
  for name in owners.get(package,[]):(t/name).unlink(missing_ok=True)
elif args[0]=='build':
 # Model a shared cache accepting old-mtime outputs: an existing executable
 # survives unless the actual spec removed it and explicitly selected bins.
 if '--bins' in args:
  for package in packages:
   for name in owners.get(package,[]):
    if not (t/name).exists():(t/name).write_text('current executable')
else: raise SystemExit('unexpected Cargo command')
''', encoding='utf-8')
                cargo.chmod(0o755)
                source = (ROOT / 'security-center/packaging' / spec).read_text(encoding='utf-8')
                build = source.split('%build\n', 1)[1].split('%check\n', 1)[0]
                commands = [line for line in build.splitlines()
                            if re.match(r'(?:/usr/bin/)?cargo (?:clean|build) ', line)]
                script = '\n'.join(re.sub(r'^(?:/usr/bin/)?cargo ', '"' + str(cargo) + '" ', line)
                                   for line in commands)
                subprocess.run(['bash', '-eu', '-c', script], check=True,
                               env={**os.environ, 'CARGO_TARGET_DIR': str(target)})
                self.assertEqual((target / 'dependency-cache').read_text(), 'retained')
                for name in binaries:
                    self.assertEqual((target / name).read_text(), 'current executable', name)
