#!/usr/bin/env bash
set -euo pipefail
# Run inside an isolated Fedora 44 builder with these inputs already present.
# No dependency/network resolution is allowed in rpmbuild.
repo=$(cd "$(dirname "$0")/../.." && pwd)
inputs=${1:?Usage: build.sh VERIFIED-INPUT-DIRECTORY NEW-OUTPUT-DIRECTORY}
output=${2:?Provide a new output directory}
manifest=${3:-$repo/environment/production/dms-release.json}
test ! -e "$output"
mkdir -p "$output"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
python3 - "$manifest" "$inputs" "$output/SOURCES" <<'PY'
import hashlib,json,pathlib,shutil,sys
m=json.load(open(sys.argv[1]))
for item in m['inputs'].values():
 if pathlib.PurePath(item['file']).name != item['file'] or '\\' in item['file']:
  raise SystemExit('Archive input must be a plain file name')
 p=pathlib.Path(sys.argv[2])/item['file']
 if hashlib.sha256(p.read_bytes()).hexdigest()!=item['sha256']: raise SystemExit('Input digest mismatch: '+str(p))
 shutil.copyfile(p,pathlib.Path(sys.argv[3])/item['file'])
PY
mkdir -p "$output/input-stage"
tar -C "$repo" -cf - \
  packaging/greyward-dms/assemble.py packaging/greyward-dms/verify.py packaging/greyward-dms/toolchain.py \
  packaging/greyward-dms/usbguard-approval.go packaging/greyward-dms/usbguard-approval-execute.go \
  packaging/greyward-dms/usbguard-approval_test.go \
  environment/production/dms-release.json \
  environment/session/greyward-dms \
  | tar -C "$output/input-stage" -xf -
# Candidate selection changes this package bundle, never the active manifest.
cp "$manifest" "$output/input-stage/environment/production/dms-release.json"
python3 - "$repo" "$manifest" "$output/input-stage/environment/patches/dms" <<'PY'
import hashlib,json,pathlib,shutil,sys
repo=pathlib.Path(sys.argv[1]).resolve(); m=json.load(open(sys.argv[2]))
patches=(repo/m.get('patchDirectory','environment/patches/dms')).resolve()
if not patches.is_relative_to(repo/'environment/patches') or not patches.is_dir():
 raise SystemExit('Candidate patches must be a reviewed repository patch directory')
shutil.copytree(patches,sys.argv[3])
plugins=(repo/m.get('firstPartyDirectory','environment/session/dankmaterialshell/plugins')).resolve()
if not plugins.is_relative_to(repo/'environment/session') or not plugins.is_dir():
 raise SystemExit('Candidate plugins must be a reviewed repository session directory')
if m.get('firstPartySources'):
 actual={p.relative_to(plugins).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in plugins.rglob('*') if p.is_file()}
 if actual != m['firstPartySources']: raise SystemExit('Changed first-party plugin inputs')
shutil.copytree(plugins,pathlib.Path(sys.argv[3]).parents[1]/'session/dankmaterialshell/plugins')
if m.get('shellAdditions'):
 assets=repo/'environment/session/dms-2.0'
 shutil.copytree(assets,pathlib.Path(sys.argv[3]).parents[1]/'session/dms-2.0')
PY
tar -C "$output/input-stage" -czf "$output/SOURCES/greyward-dms-inputs.tar.gz" .
python3 - "$manifest" "$repo/packaging/greyward-dms/greyward-dms.spec" "$output/SPECS/greyward-dms.spec" <<'PY'
import json,pathlib,re,sys
m=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')); version=m['dms']['tag'].removeprefix('v')
match=re.fullmatch(r'v'+re.escape(version)+r'-(\d+)',m['releaseId'])
if not match: raise SystemExit('Invalid canonical DMS package identity')
package_revision=m['build'].get('rpmRelease',match[1])
if not isinstance(package_revision,str) or not re.fullmatch(re.escape(match[1])+r'(?:\.[1-9][0-9]*)?',package_revision):
 raise SystemExit('Invalid DMS package-only revision')
pins={'dms-greeter' if k=='greeter' else k:v for k,v in m['compatibility'].items() if k in ('quickshell','greeter','labwc','uwsm')}
prefix=f'%global greyward_version {version}\n%global greyward_revision {match[1]}\n%global greyward_package_revision {package_revision}\n%global greyward_runtime /usr/lib/greyward/dms/{m["releaseId"]}\n'
values={'source_root':m['inputs']['source']['root'], 'vendor_root':m['inputs']['vendor']['root'],
        'vendor_archive':m['inputs']['vendor']['file'], 'minimum_go':m['build']['minimumGo'],
        'common_dir':m.get('commonDirectory','DankCommon'), 'commit':m['dms']['commit'],
        'build_time':m['build'].get('buildTime','2026-09-08_13:00:00')}
toolchain=m['build'].get('toolchain')
values['bundled_go']='1' if toolchain else '0'
if toolchain: values['go_archive']=m['inputs'][toolchain['input']]['file']
if any(not re.fullmatch(r'[A-Za-z0-9_.:+-]+',str(value)) for value in [*values.values(),*pins.values()]):
 raise SystemExit('Invalid RPM macro or dependency value')
prefix+=''.join(f'%global greyward_{name} {value}\n' for name,value in values.items())
prefix+=''.join(f'Requires: {name} = {value}\n' for name,value in sorted(pins.items()))
if 'rpmRelease' in m['build']:
 prefix+=f'Provides: greyward-dms = {version}-{match[1]}%{{?dist}}\n'
plugin_update=m['build'].get('pluginUpdate')
if plugin_update:
 predecessor=plugin_update.get('basePackage','')
 if (not re.fullmatch(r'greyward-dms-'+re.escape(version)+'-'+re.escape(match[1])+r'\.[1-9][0-9]*\.fc44\.x86_64',predecessor)
     or plugin_update.get('requiresProtectedMigration') is not False):
  raise SystemExit('Invalid ordinary-plugin predecessor compatibility')
 prefix+='Provides: greyward-dms = '+predecessor.removeprefix('greyward-dms-').removesuffix('.x86_64')+'\n'
pathlib.Path(sys.argv[3]).write_text(prefix+pathlib.Path(sys.argv[2]).read_text())
PY
rpmbuild --define "_topdir $(realpath "$output")" -ba "$output/SPECS/greyward-dms.spec"
