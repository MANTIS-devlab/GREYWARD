Name: greyward-intelligence
Version: 1.7.1
Release: 6%{?dist}
Summary: Local GREYWARD behavioral sensor and read-only evidence provider
License: Apache-2.0 AND GPL-2.0-only AND BSD-2-Clause AND GPL-3.0-only
ExclusiveArch: x86_64
Source0: tetragon-v1.7.1-source.tar.gz
Source1: tetragon-v1.7.1-amd64.tar.gz
Source2: greyward-intelligence-integration.tar.gz
BuildRequires: golang
BuildRequires: python3
BuildRequires: patch
Requires: greyward-security-context >= 0.1.0-120
Requires: python3-dbus
Requires: python3-gobject-base
%global debug_package %{nil}
%global __brp_strip %{nil}
%global __brp_strip_static_archive %{nil}
%global __brp_strip_comment_note %{nil}
%global __brp_strip_lto %{nil}
%description
Observation-only Tetragon sensor with UID-scoped GREYWARD
correlation. No TCP control API, generic privileged actions or heuristic killing.
%prep
%setup -q -c -T
tar -xzf %{SOURCE0} --strip-components=1
mkdir upstream integration
tar -xzf %{SOURCE1} -C upstream --strip-components=1
tar -xzf %{SOURCE2} -C integration
patch -p1 --fuzz=0 < integration/btf-compat.patch
cp integration/go.mod go.mod
cp integration/go.sum go.sum
%build
export GOMAXPROCS=2
go build -mod=readonly -p 2 -trimpath -ldflags '-X github.com/cilium/tetragon/pkg/version.Version=v1.7.1-greyward.1' -o tetragon ./cmd/tetragon
%check
python3 - <<'PY'
from pathlib import Path
import json
m=json.loads(Path('integration/source.json').read_text())
assert m['ebpf_dependency']=='v0.22.0'
assert 'github.com/cilium/ebpf v0.22.0' in Path('go.mod').read_text()
assert 'FlushKernelSpec()' not in Path('pkg/bpf/detect_linux.go').read_text()
for unit in Path('integration').glob('*.service'):
 assert 'KillMode=none' not in unit.read_text()
PY
%install
install -Dm0755 tetragon %{buildroot}%{_libexecdir}/greyward-intelligence/tetragon
mkdir -p %{buildroot}%{_libexecdir}/greyward-intelligence/bpf
cp -a upstream/usr/local/lib/tetragon/bpf/. %{buildroot}%{_libexecdir}/greyward-intelligence/bpf/
install -Dm0755 integration/attest-sensor.py %{buildroot}%{_libexecdir}/greyward-intelligence/attest-sensor
install -Dm0755 integration/configure-policies.py %{buildroot}%{_libexecdir}/greyward-intelligence/configure-policies
install -Dm0644 integration/source.json %{buildroot}%{_datadir}/greyward/intelligence-source.json
install -Dm0644 integration/greyward-intelligence-sensor.service %{buildroot}%{_unitdir}/greyward-intelligence-sensor.service
install -Dm0644 integration/greyward-intelligence-provider.service %{buildroot}%{_unitdir}/greyward-intelligence-provider.service
install -Dm0644 integration/systems.mantis.greyward.Intelligence1.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/systems.mantis.greyward.Intelligence1.conf
%post
install -d -m0700 /var/lib/greyward/intelligence /var/lib/greyward/intelligence/sensor
%{_libexecdir}/greyward-intelligence/configure-policies
%systemd_post greyward-intelligence-sensor.service greyward-intelligence-provider.service
%preun
%systemd_preun greyward-intelligence-sensor.service greyward-intelligence-provider.service
%postun
%systemd_postun greyward-intelligence-sensor.service greyward-intelligence-provider.service
%files
%license LICENSE bpf/LICENSE.GPL-2.0 bpf/LICENSE.BSD-2-Clause integration/GREYWARD-LICENSE
%{_libexecdir}/greyward-intelligence
%{_datadir}/greyward/intelligence-source.json
%{_unitdir}/greyward-intelligence-sensor.service
%{_unitdir}/greyward-intelligence-provider.service
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/systems.mantis.greyward.Intelligence1.conf
%changelog
* Mon Nov 02 2026 MANTIS SYSTEMS - 1.7.1-6
- Keep generator receipts outside the sensor's policy parser directory.

* Mon Nov 02 2026 MANTIS SYSTEMS - 1.7.1-5
- Refresh unmodified generated policy after installer account creation.
- Preserve administrator policy edits and keep behavioral sensing optional to login.

* Thu Oct 29 2026 MANTIS SYSTEMS - 1.7.1-4
- Materialize the entire private evidence directory with explicit owner-only access.

* Thu Oct 29 2026 MANTIS SYSTEMS - 1.7.1-3
- Package fixed attachment attestation and retain upstream/GREYWARD license texts.

* Thu Oct 29 2026 MANTIS SYSTEMS - 1.7.1-1
- Local observation-only integration with BTF 7.1+ compatibility and private read-only evidence.
