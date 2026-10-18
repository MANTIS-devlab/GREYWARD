Name: greyward-dms
Version: %{greyward_version}
Release: %{greyward_revision}%{?dist}
Summary: Verified GREYWARD DankMaterialShell runtime and generated shell
License: GPL-3.0-only AND MIT
URL: https://github.com/AvengeMedia/DankMaterialShell
Source0: dms-source.tar.gz
Source1: dms-cli-1.6.2.tar.gz
Source2: greyward-dms-inputs.tar.gz
BuildRequires: golang >= 1.26.5
BuildRequires: python3
BuildRequires: make
Requires: quickshell >= 0.3.1
Requires: greyward-security-context >= 0.1.0-104%{?dist}
Requires: python3
Requires: bash
Requires: jq
Requires: labwc
Requires: uwsm
%global debug_package %{nil}
# Go's linker already strips this binary (-s -w). Preserve its audited digest;
# RPM's ELF post-processing otherwise changes it after the receipt is written.
%global __brp_strip %{nil}
%global __brp_strip_comment_note %{nil}
%global __brp_strip_lto %{nil}
%global runtime %{greyward_runtime}

%description
Unchanged distribution backend with embedded vanilla diagnostics, a verified
release-matched generated shell, and four GREYWARD first-party system plugins.
This is a candidate; installation alone does not certify image or hardware gates.

%prep
%setup -q -c -T
tar -xzf %{SOURCE2}
python3 packaging/greyward-dms/assemble.py --manifest environment/production/dms-release.json --source %{SOURCE0} --vendor %{SOURCE1} --patches environment/patches/dms --output assembled
ln -s ../source/DankMaterialShell-1.6.2/quickshell assembled/vendor/quickshell

%build
GO111MODULE=off GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' \
    -o usbguard-approval packaging/greyward-dms/usbguard-approval.go
GO111MODULE=off GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' \
    -o usbguard-approval-auth packaging/greyward-dms/usbguard-approval-execute.go
python3 - <<'PY'
from pathlib import Path
interfaces=[line.split(':',1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
if any(name != 'lo' for name in interfaces): raise SystemExit('Build requires an isolated network namespace')
PY
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0
cd assembled/vendor/dms-cli-1.6.2
# Embed vanilla upstream QML using the unmodified upstream generator.
# Its pipeline creates .dankrev while find enumerates files. Supply the empty
# generated input before copying so it is always included, avoiding that race.
install -m0644 /dev/null ../../source/DankMaterialShell-1.6.2/quickshell/.dankrev
make sync-shell SHELL_SRC=../../source/DankMaterialShell-1.6.2/quickshell
go build -trimpath -tags 'distro_binary withshell' -ldflags '-s -w -buildid= -X main.Version=1.6.2 -X main.commit=2db7646fe3ab47fddfdb8723f2da07d61a0d47ac -X main.buildTime=2026-09-08_13:00:00' -o dms ./cmd/dms

%check
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0
GO111MODULE=off go test packaging/greyward-dms/usbguard-approval.go packaging/greyward-dms/usbguard-approval_test.go
export XDG_RUNTIME_DIR=$(mktemp -d)
mkdir -m0700 "$XDG_RUNTIME_DIR/danklinux"
trap 'rm -rf "$XDG_RUNTIME_DIR"' EXIT
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent-greyward-builder-bus
cd assembled/vendor/dms-cli-1.6.2
go test -tags distro_binary ./...
./dms --help > command-help.txt
! grep -Eq '^  update[[:space:]]' command-help.txt

%install
mkdir -p %{buildroot}%{runtime}/bin %{buildroot}/usr/bin %{buildroot}/etc/greyward
cp -a assembled/shell %{buildroot}%{runtime}/shell
install -m0755 assembled/vendor/dms-cli-1.6.2/dms %{buildroot}%{runtime}/bin/dms
install -D -m0755 usbguard-approval %{buildroot}/usr/libexec/greyward-usbguard-approval
install -D -m0755 usbguard-approval-auth %{buildroot}/usr/libexec/greyward-usbguard-auth-approval
cp assembled/release.json %{buildroot}%{runtime}/release.json
python3 - %{buildroot}%{runtime} <<'PY'
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]); p=root/'release.json'; m=json.loads(p.read_text())
m['binarySha256']=hashlib.sha256((root/'bin/dms').read_bytes()).hexdigest()
m['usbguardApprovalSha256']=hashlib.sha256(pathlib.Path('usbguard-approval').read_bytes()).hexdigest()
m['usbguardAuthApprovalSha256']=hashlib.sha256(pathlib.Path('usbguard-approval-auth').read_bytes()).hexdigest()
m['usbguardApprovalSourceSha256']=hashlib.sha256(pathlib.Path('packaging/greyward-dms/usbguard-approval.go').read_bytes()).hexdigest()
m['usbguardAuthApprovalSourceSha256']=hashlib.sha256(pathlib.Path('packaging/greyward-dms/usbguard-approval-execute.go').read_bytes()).hexdigest()
m['build']['packages']=subprocess.check_output(['rpm','-q','--qf','%%{NEVRA}\\n','golang','python3','make','rpm-build'],text=True).splitlines()
m['build']['goVersion']=subprocess.check_output(['go','version'],text=True).strip()
m['firstPartyFiles']={p.relative_to(pathlib.Path('environment/session/dankmaterialshell/plugins')).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('environment/session/dankmaterialshell/plugins').rglob('*') if p.is_file()}
p.write_text(json.dumps(m,indent=2)+'\n')
PY
printf 'v%{version}-%{greyward_revision}\n' > %{buildroot}/etc/greyward/dms-release
ln -s %{runtime}/bin/dms %{buildroot}/usr/bin/dms
install -D -m0755 packaging/greyward-dms/verify.py %{buildroot}/usr/libexec/greyward-dms-verify
mkdir -p %{buildroot}/etc/xdg/quickshell/dms-plugins
cp -a environment/session/dankmaterialshell/plugins/. %{buildroot}/etc/xdg/quickshell/dms-plugins/
find %{buildroot}%{runtime}/shell %{buildroot}/etc/xdg/quickshell/dms-plugins -type d -exec chmod 0755 {} +
find %{buildroot}%{runtime}/shell %{buildroot}/etc/xdg/quickshell/dms-plugins -type f -exec chmod 0644 {} +
mkdir -p %{buildroot}%{runtime}/licenses
cp assembled/source/DankMaterialShell-1.6.2/LICENSE %{buildroot}%{runtime}/licenses/DMS-LICENSE
find assembled/source/DankMaterialShell-1.6.2/quickshell/DankCommon -maxdepth 1 -iname '*license*' -exec cp {} %{buildroot}%{runtime}/licenses/ \;
cp assembled/vendor/dms-cli-1.6.2/vendor/modules.txt %{buildroot}%{runtime}/go-vendor-modules.txt
python3 - %{buildroot}%{runtime}/licenses <<'PY'
import pathlib,shutil,sys
base=pathlib.Path('assembled/vendor/dms-cli-1.6.2/vendor'); out=pathlib.Path(sys.argv[1])/'go-vendor'
for p in base.rglob('*'):
 if p.is_file() and (p.name.lower().startswith(('license','copying','notice'))):
  dest=out/p.relative_to(base); dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,dest)
PY

%files
%config /etc/greyward/dms-release
/usr/bin/dms
/usr/libexec/greyward-dms-verify
/usr/libexec/greyward-usbguard-approval
/usr/libexec/greyward-usbguard-auth-approval
%{runtime}
/etc/xdg/quickshell/dms-plugins

%changelog
* Sun Oct 18 2026 GREYWARD <build@mantis.systems> - 1.6.2-22
- Keep the confined desktop selector from reading the protected USB approval helper.
- Consume the private atomic USB availability projection; disable unnecessary Go cgroup CPU discovery.

* Sun Oct 18 2026 GREYWARD <build@mantis.systems> - 1.6.2-21
- Route taskbar USB trust through the active protected Polkit session.

* Sun Oct 18 2026 GREYWARD <build@mantis.systems> - 1.6.2-20
- Keep USBGuard approval alive through its Polkit prompt and require verified completion feedback.

* Sun Oct 18 2026 GREYWARD <build@mantis.systems> - 1.6.2-19
- Route USBGuard approval through a fixed, separately confined client.

* Sun Oct 11 2026 GREYWARD <build@mantis.systems> - 1.6.2-15
- Ship the current first-party shell plugin payload and verify it against source during ISO staging.

* Sun Oct 04 2026 GREYWARD <build@mantis.systems> - 1.6.2-1
- Verified offline candidate runtime with generated release-matched shell.
