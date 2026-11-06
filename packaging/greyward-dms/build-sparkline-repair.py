#!/usr/bin/env python3
"""Build a closed protected-shell repair from a manifest-locked predecessor RPM.

Preserves all compiled executables and ordinary plugins. The only QML delta is
DSparkline's renderer selection and antialiasing. A new protected generation and
quiescent receipt migration are required. Normal full source builds still use
build.sh and the same exact-preimage patch in the canonical manifest.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('dms_assemble',ROOT/'packaging/greyward-dms/assemble.py')
assemble=importlib.util.module_from_spec(spec);spec.loader.exec_module(assemble)
NAME='DCommon/Widgets/DSparkline.qml'
OLD='        preferredRendererType: Shape.CurveRenderer'
NEW="""        // Qt 6.11.2 CurveRenderer crashes on valid sampled chart fills.
        // Keep GPU rendering, isolating the fallback to these small graphs.
        preferredRendererType: Shape.GeometryRenderer
        layer.enabled: true
        layer.samples: 4"""

def prepare(payload,m):
    pin=m['build']['sparklineRepair']
    before=pin['baseReleaseId'];after=m['releaseId']
    if not all(re.fullmatch(r'v2\.0\.0-[1-9][0-9]*',v) for v in (before,after)) or before==after or pin['requiresProtectedMigration'] is not True:
        raise ValueError('Repair needs distinct protected generations and quiescent migration')
    runtime=payload/'usr/lib/greyward/dms'/before
    receipt=json.loads((runtime/'release.json').read_text())
    if receipt['releaseId']!=before:raise ValueError('Predecessor generation mismatch')
    for key in ('dms','dankCommon','dankgo','inputs','firstPartySources','compatibility','shellAdditions'):
        if receipt.get(key)!=m.get(key):raise ValueError('Unreviewed source change: '+key)
    if receipt['patches']!=m['patches'][:-1]:raise ValueError('Unexpected patch history')
    files,digest=assemble.tree_receipt(runtime/'shell')
    if files!=receipt['shellFiles'] or digest!=pin['baseShellSha256']:raise ValueError('Predecessor shell mismatch')
    actual={p.relative_to(payload/'etc/xdg/quickshell/dms-plugins').as_posix():assemble.sha(p) for p in (payload/'etc/xdg/quickshell/dms-plugins').rglob('*') if p.is_file()}
    if actual!=m['firstPartySources'] or receipt['firstPartyFiles']!=actual:raise ValueError('Plugin change outside repair')
    for key,path in [('binarySha256',runtime/'bin/dms'),('usbguardApprovalSha256',payload/'usr/libexec/greyward-usbguard-approval'),('usbguardAuthApprovalSha256',payload/'usr/libexec/greyward-usbguard-auth-approval')]:
        if assemble.sha(path)!=receipt[key] or receipt[key]!=pin['executables'][key]:raise ValueError('Executable drift: '+key)
    patch=m['patches'][-1];source=ROOT/m['patchDirectory']/patch['file']
    if patch['file']!='greyward-sparkline-renderer.patch' or patch['preimages']!={NAME:files[NAME]} or assemble.sha(source)!=patch['sha256']:raise ValueError('Unexpected repair patch')
    original=(runtime/'shell'/NAME).read_text()
    if original.count(OLD)!=1:raise ValueError('Renderer preimage changed')
    if assemble.apply_exact(runtime/'shell',source.read_text())!=[NAME] or (runtime/'shell'/NAME).read_text()!=original.replace(OLD,NEW,1):raise ValueError('Repair exceeds renderer-only change')
    files,digest=assemble.tree_receipt(runtime/'shell')
    if digest!=m['shell']['sha256']:raise ValueError('Repaired shell mismatch')
    receipt.update(m);receipt['shellFiles']=files
    (runtime/'release.json').write_text(json.dumps(receipt,indent=2)+'\n')
    runtime.rename(runtime.with_name(after))
    selector=payload/'etc/greyward/dms-release'
    if selector.read_text().strip()!=before:raise ValueError('Unexpected selector')
    selector.write_text(after+'\n')
    launcher=payload/'usr/bin/dms'
    if not launcher.is_symlink() or str(launcher.readlink())!='/usr/lib/greyward/dms/'+before+'/bin/dms':raise ValueError('Unexpected DMS entrypoint')
    launcher.unlink();launcher.symlink_to('/usr/lib/greyward/dms/'+after+'/bin/dms')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base_rpm',type=Path);parser.add_argument('output',type=Path);args=parser.parse_args()
    if os.getuid()==0:parser.error('Use an unprivileged builder')
    m=json.loads((ROOT/'environment/production/dms-2.0-candidate.json').read_text());pin=m['build']['sparklineRepair']
    if assemble.sha(args.base_rpm)!=pin['baseRpmSha256']:parser.error('Predecessor artifact mismatch')
    if subprocess.check_output(['rpm','-qp','--scripts',str(args.base_rpm)],text=True).strip():parser.error('Unexpected scriptlets')
    args.output.mkdir();out=args.output.resolve()
    for name in ('BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS','tmp'):(out/name).mkdir()
    payload=out/'SOURCES/payload';payload.mkdir()
    stream=subprocess.Popen(['rpm2cpio',str(args.base_rpm.resolve())],stdout=subprocess.PIPE)
    try:subprocess.run(['cpio','-idm','--quiet','--no-absolute-filenames'],cwd=payload,stdin=stream.stdout,check=True)
    finally:stream.stdout.close()
    if stream.wait():raise ValueError('RPM extraction failed')
    prepare(payload,m)
    requirements=subprocess.check_output(['rpm','-qp','--requires',str(args.base_rpm)],text=True).splitlines()
    requirements=[r for r in requirements if not r.startswith(('rpmlib(','config('))]
    version,generation=m['releaseId'][1:].rsplit('-',1)
    content=f"""%global __os_install_post %{{nil}}
Name: greyward-dms
Version: {version}
Release: {generation}%{{?dist}}
Summary: GREYWARD pinned desktop with validated sparkline renderer repair
License: GPL-3.0-only AND MIT
AutoReqProv: no
"""+''.join('Requires: '+v+'\n' for v in requirements)+"""%description
Manifest-locked predecessor executables, plugins and protected shell with only
the reproduced Qt sparkline crash repaired. Requires protected-profile migration.
%prep
%build
%install
mkdir -p %{buildroot}
cp -a %{_sourcedir}/payload/. %{buildroot}/
%files
%defattr(-,root,root,-)
%config /etc/greyward/dms-release
/usr/bin/dms
/usr/libexec/greyward-dms-verify
/usr/libexec/greyward-usbguard-approval
/usr/libexec/greyward-usbguard-auth-approval
/etc/xdg/quickshell/dms-plugins
"""+'/usr/lib/greyward/dms/'+m['releaseId']+'\n'
    path=out/'SPECS/greyward-dms.spec';path.write_text(content)
    subprocess.run(['rpmbuild','--define','_topdir '+str(out),'--define','_tmppath '+str(out/'tmp'),'-bb',str(path)],check=True)

if __name__=='__main__':main()
