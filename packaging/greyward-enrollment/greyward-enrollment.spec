Name: greyward-application-enrollment
Version: 0.1.0
Release: 18%{?dist}
Summary: GREYWARD protected-session installation inputs
License: GPL-2.0-only AND GPL-3.0-only AND MIT
Source0: %{name}-%{version}.tar.gz
Source1: labwc-0.9.6-canonical.tar
# The receipt identifies the exact private executable. Preserve these bytes
# through RPM processing instead of hashing an ELF that brp later strips.
%global debug_package %{nil}
%global __strip /bin/true
BuildRequires: gcc
BuildRequires: meson
BuildRequires: ninja-build
BuildRequires: selinux-policy-devel = 44.11-1.fc44
BuildRequires: python3
BuildRequires: pkgconfig(wlroots-0.19)
BuildRequires: pkgconfig(wayland-server)
BuildRequires: pkgconfig(wayland-protocols)
BuildRequires: pkgconfig(xkbcommon)
BuildRequires: pkgconfig(xcb-ewmh)
BuildRequires: pkgconfig(xcb-icccm)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(pangocairo)
BuildRequires: pkgconfig(libinput)
BuildRequires: pkgconfig(librsvg-2.0)
BuildRequires: pkgconfig(libsfdo-basedir)
BuildRequires: pkgconfig(libsfdo-desktop)
BuildRequires: pkgconfig(libsfdo-icon)
BuildRequires: gettext
BuildRequires: pkgconfig(cmocka)
Requires: greyward-application-security-experimental = 0.1.0-42%{?dist}
Requires: greyward-dms = 1.6.2-15%{?dist}
Requires: greyward-session >= 0.1.0-10
Requires: selinux-policy-targeted = 44.11-1.fc44
Requires: flatpak-selinux
Requires: greetd-selinux
Requires: policycoreutils-python-utils
Requires: python3-setools
Requires: cryptsetup
Requires: sudo

%description
Matched SELinux, protected compositor and authenticated offline-maintenance
inputs for the GREYWARD installer. Installation is inert: only the fixed
first-boot coordinator may enroll the root-attested installer accounts.
This candidate requires clean-install and recovery acceptance before promotion.
Generic Flatpak sensitive-resource grants are not supplied.

%prep
%autosetup
printf '67fe996c4e5afd855fdbfbc3af0b05245667ec97666f463472a1961b46047f48  %{SOURCE1}\n' | sha256sum --check --strict
mkdir compositor
tar -xf %{SOURCE1} -C compositor
patch --batch --fuzz=0 -d compositor -p1 < security-center/packaging/application-security/desktop/labwc-protected-input.patch
patch --batch --fuzz=0 -d compositor -p1 < security-center/packaging/application-security/desktop/labwc-administration-indicator.patch

%build
meson setup compositor/build compositor --buildtype=release --wrap-mode=nofallback -Dman-pages=disabled -Dtest=enabled
ninja -C compositor/build -j2
mkdir policy
for source in environment/production/selinux/greyward-application-*.te environment/production/selinux/greyward-administration.te environment/production/selinux/greyward-application-*.fc environment/production/selinux/greyward-administration.fc; do
  name=$(basename "$source")
  cp "$source" "policy/${name//-/_}"
done
cd policy
make -f /usr/share/selinux/devel/Makefile -j2
cd ..
python3 - <<'PY'
import hashlib,json,pathlib
binary=pathlib.Path('compositor/build/labwc')
pathlib.Path('inputs.json').write_text(json.dumps({'schema':'greyward.enrollment-inputs/v1',
 'labwcCommit':'12987307a5de32db5acbb3f59d41277373ab969e',
 'labwcSourceSha256':'67fe996c4e5afd855fdbfbc3af0b05245667ec97666f463472a1961b46047f48',
 'labwcSha256':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2)+'\n')
PY

%check
meson test -C compositor/build --print-errorlogs
python3 -m py_compile packaging/greyward-enrollment/enroll.py packaging/greyward-enrollment/installer-accounts.py security-center/packaging/application-security/maintenance.py
python3 -m py_compile packaging/greyward-enrollment/migrate-dms-shell.py
bash -n packaging/greyward-enrollment/build.sh

%install
base=%{buildroot}%{_datadir}/greyward-application-security/enrollment
install -d "$base/policy"
install -m0444 policy/*.pp environment/production/selinux/greyward-application-auth.cil environment/production/selinux/greyward-application-metadata.cil environment/production/selinux/greyward-administration.cil packaging/greyward-enrollment/runtime-boundary.cil "$base/policy/"
install -m0444 inputs.json "$base/"
install -m0444 packaging/greyward-enrollment/installer-accounts.py "$base/"
install -Dm0555 packaging/greyward-enrollment/enroll.py %{buildroot}%{_libexecdir}/greyward-enrollment
install -Dm0555 packaging/greyward-enrollment/migrate-dms-shell.py %{buildroot}%{_libexecdir}/greyward-migrate-protected-dms-shell
install -Dm0555 compositor/build/labwc %{buildroot}%{_libexecdir}/greyward-protected-labwc
install -Dm0555 security-center/packaging/application-security/maintenance.py %{buildroot}%{_libexecdir}/greyward-maintenance
install -Dm0644 security-center/packaging/application-security/greyward-maintenance.target %{buildroot}%{_unitdir}/greyward-maintenance.target
install -Dm0644 security-center/packaging/application-security/greyward-maintenance-console.service %{buildroot}%{_unitdir}/greyward-maintenance-console.service

%files
%license compositor/LICENSE
%{_datadir}/greyward-application-security/enrollment/
%{_libexecdir}/greyward-enrollment
%{_libexecdir}/greyward-migrate-protected-dms-shell
%{_libexecdir}/greyward-protected-labwc
%{_libexecdir}/greyward-maintenance
%{_unitdir}/greyward-maintenance.target
%{_unitdir}/greyward-maintenance-console.service

%changelog
* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-18
- Match DMS v1.6.2-15 runtime.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-17
- Match the refreshed Application Guard RPM source revision.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-16
- Refresh the authenticated startup worker and splash through explicit migration.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-15
- Reassemble the protected authentication shell with its startup backdrop.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-14
- Refresh the protected session worker and private Wayland socket alias during verified quiescent migration.
* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-13
- Require the matching application-security RPM and refresh its protected login profile during explicit quiescent migration.
* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-12
- Require the updated protected authentication readiness source for first login.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-11
- Match Application Security 0.1.0-37 for the current .149 package floor.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-10
- Declare the cmocka dependency required by the protected compositor's Meson tests.
- Match DMS v1.6.2-14 and Application Security 0.1.0-35.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-9
- Match the DMS v1.6.2-14 candidate built with the current signed Fedora toolchain.

* Sat Oct 10 2026 MANTIS SYSTEMS - 0.1.0-8
- Add an explicit quiescent migration for existing protected DMS shells.

* Sat Oct 10 2026 MANTIS SYSTEMS - 0.1.0-7
- Require the DMS build with capability-based monitor configuration readiness.

* Sat Oct 10 2026 MANTIS SYSTEMS - 0.1.0-5
- Explicitly finalize immutable program directory modes under enrollment umask 077.
- Keep policy, grant and authentication runtime storage private.

* Sat Oct 10 2026 MANTIS SYSTEMS - 0.1.0-4
- Create validated private installer-origin storage before broker preparation.
- Checkpoint prepared inputs and retain the original first-boot failure details.

* Sat Oct 10 2026 MANTIS SYSTEMS - 0.1.0-3
- Package matched protected-session inputs without changing the build host.
- Add installer-only preparation and authenticated offline fresh-install rollback.
