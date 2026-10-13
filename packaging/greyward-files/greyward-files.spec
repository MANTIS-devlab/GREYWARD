Name: greyward-files
Version: 1.0.0
Release: 11%{?dist}
Summary: GREYWARD Strata file manager and transparent desktop integration
License: MIT AND GPL-3.0-only AND GPL-2.0-or-later AND Apache-2.0 AND OFL-1.1 AND ISC AND LGPL-2.0-or-later AND LicenseRef-UnRAR AND LicenseRef-GREYWARD-Branding
URL: https://github.com/lgse/strata
ExclusiveArch: x86_64
Source0: strata-1.0.0-x86_64-unknown-linux-gnu.tar.gz
Source1: strata-source.tar.gz
Source2: greyward-files-inputs.tar.gz
Source3: pcmanfm-qt-2.4.1.tar.xz
BuildRequires: cmake
BuildRequires: gcc-c++
BuildRequires: qt6-qtbase-devel
BuildRequires: python3
BuildRequires: patch
BuildRequires: cmake(fm-qt6) >= 2.4.0
BuildRequires: cmake(lxqt2-build-tools) >= 2.4.0
BuildRequires: cmake(LayerShellQt)
BuildRequires: cmake(Qt6LinguistTools)
BuildRequires: qt6-qtbase-private-devel
Requires: pcmanfm-qt >= 2.4.1
Requires: python3
Requires: bubblewrap
Requires: gvfs
Requires: gvfs-smb
Requires: gvfs-fuse
Requires: udisks2
Requires: breeze-icon-theme
Requires: greyward-session >= 0.1.0-17
%global debug_package %{nil}
# Keep the upstream attested ELF intact rather than stripping it a second time.
%global __brp_strip %{nil}
%global __brp_strip_comment_note %{nil}
%global __brp_strip_lto %{nil}

%description
Verified upstream Strata with app-specific GREYWARD Obsidian defaults and a
desktop-only Qt style. PCManFM-Qt supplies transparent icons while DMS owns
wallpaper. No portal replacements or privileged file manager are installed.
Candidate package: installed workflow and clean-image validation remain pending.

%prep
%setup -q -c -T
tar -xzf %{SOURCE2}
python3 - %{SOURCE0} %{SOURCE1} %{SOURCE3} <<'PY'
import hashlib,json,pathlib,sys,tarfile
m=json.loads(pathlib.Path('packaging/greyward-files/source.json').read_text())
for key,path in zip(('binary','source','desktop'),sys.argv[1:]):
    if hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()!=m['inputs'][key]['sha256']:
        raise SystemExit('Input digest mismatch')
    with tarfile.open(path) as archive:
        archive.extractall(key,filter='data')
if pathlib.Path('binary/strata-1.0.0-x86_64-unknown-linux-gnu/SOURCE_COMMIT').read_text().strip()!=m['commit']:
    raise SystemExit('Binary generation mismatch')
for name,digest in m['inputs']['desktop']['patchPreimage'].items():
    if hashlib.sha256((pathlib.Path('desktop')/m['inputs']['desktop']['root']/name).read_bytes()).hexdigest()!=digest:
        raise SystemExit('Desktop patch preimage changed')
PY
patch --directory=desktop/pcmanfm-qt-2.4.1 -p1 --fuzz=0 < packaging/greyward-files/pcmanfm-desktop-only.patch

%build
python3 tools/generate-file-icons.py --catalog branding/source/greyward-icon-family.json --upstream source/lgse-strata-6662d8d --destination icons-build
cmake -S environment/session/desktop/style -B style-build -DCMAKE_BUILD_TYPE=Release
cmake --build style-build --parallel 2
cmake -S desktop/pcmanfm-qt-2.4.1 -B desktop-build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib64
cmake --build desktop-build --parallel 2

%install
binary=binary/strata-1.0.0-x86_64-unknown-linux-gnu
install -Dm0755 "$binary/strata" %{buildroot}/usr/libexec/greyward/files/strata
install -Dm0755 desktop-build/pcmanfm/pcmanfm-qt %{buildroot}/usr/libexec/greyward/files/pcmanfm-qt
install -Dm0755 environment/session/desktop/strata-launcher %{buildroot}/usr/bin/strata
install -Dm0755 style-build/libgreywarddesktop.so %{buildroot}%{_libdir}/greyward/desktop/qt/styles/libgreywarddesktop.so
for helper in greyward-files-seed greyward-desktop-icons greyward-desktop-shortcut; do
    install -Dm0755 environment/session/$helper %{buildroot}/usr/local/libexec/$helper
done
install -Dm0644 environment/session/greyward-desktop-icons.service %{buildroot}/usr/lib/systemd/user/greyward-desktop-icons.service
for asset in obsidian.toml transparent.svg settings.conf; do
    install -Dm0644 environment/session/desktop/$asset %{buildroot}/usr/share/greyward/files/$asset
done
install -d %{buildroot}/usr/share/icons %{buildroot}/usr/share/greyward/files
cp -a icons-build/theme/Greyward %{buildroot}/usr/share/icons/
cp -a icons-build/strata %{buildroot}/usr/share/greyward/files/strata-resources
install -Dm0644 icons-build/receipt.json %{buildroot}/usr/share/greyward/files/icons-receipt.json
install -Dm0644 environment/session/desktop/greyward-mimeapps.list %{buildroot}/etc/xdg/greyward-mimeapps.list
# Higher-priority local service directory avoids overwriting Nautilus's RPM file.
install -Dm0644 environment/session/desktop/org.freedesktop.FileManager1.service %{buildroot}/usr/local/share/dbus-1/services/org.freedesktop.FileManager1.service
install -Dm0644 "$binary/io.github.lgse.Strata.desktop" %{buildroot}/usr/share/applications/io.github.lgse.Strata.desktop
# GREYWARD owns the distribution icon; keep the upstream executable intact.
install -Dm0644 branding/source/greyward-files.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/greyward-files.svg
install -Dm0644 branding/source/greyward-files.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/io.github.lgse.Strata.svg
sed -i 's|^Icon=io.github.lgse.Strata$|Icon=/usr/share/icons/hicolor/scalable/apps/greyward-files.svg|' %{buildroot}/usr/share/applications/io.github.lgse.Strata.desktop
install -Dm0644 packaging/greyward-files/source.json %{buildroot}/usr/share/greyward/files/source.json
mkdir -p %{buildroot}%{_licensedir}/%{name}
cp "$binary/LICENSE" "$binary/THIRD_PARTY_LICENSES.md" "$binary/UnRAR.txt" %{buildroot}%{_licensedir}/%{name}/
cp -a source/lgse-strata-6662d8d/data/licenses %{buildroot}%{_licensedir}/%{name}/upstream
install -m0644 branding/LICENSE %{buildroot}%{_licensedir}/%{name}/GREYWARD-Branding-NOTICE
install -m0644 desktop/pcmanfm-qt-2.4.1/LICENSE %{buildroot}%{_licensedir}/%{name}/PCManFM-LICENSE
cp -a icons-build/LICENSES %{buildroot}%{_licensedir}/%{name}/icon-family

%check
python3 - <<'PY'
import pathlib,hashlib
source=pathlib.Path('binary/strata-1.0.0-x86_64-unknown-linux-gnu/strata')
installed=pathlib.Path('%{buildroot}/usr/libexec/greyward/files/strata')
if hashlib.sha256(source.read_bytes()).digest()!=hashlib.sha256(installed.read_bytes()).digest():
    raise SystemExit('Attested executable changed during packaging')
assert 'Exec=strata %%U' in pathlib.Path('%{buildroot}/usr/share/applications/io.github.lgse.Strata.desktop').read_text()
PY

%files
/usr/bin/strata
/usr/libexec/greyward/files/strata
/usr/libexec/greyward/files/pcmanfm-qt
%{_libdir}/greyward/desktop/qt/styles/libgreywarddesktop.so
/usr/local/libexec/greyward-files-seed
/usr/local/libexec/greyward-desktop-icons
/usr/local/libexec/greyward-desktop-shortcut
/usr/lib/systemd/user/greyward-desktop-icons.service
/usr/share/greyward/files
%config(noreplace) /etc/xdg/greyward-mimeapps.list
/usr/local/share/dbus-1/services/org.freedesktop.FileManager1.service
/usr/share/applications/io.github.lgse.Strata.desktop
/usr/share/icons/hicolor/scalable/apps/io.github.lgse.Strata.svg
/usr/share/icons/hicolor/scalable/apps/greyward-files.svg
/usr/share/icons/Greyward
%license %{_licensedir}/%{name}

%changelog
* Wed Oct 14 2026 MANTIS SYSTEMS - 1.0.0-11
- Cover the native GIO inode-directory name so ordinary folders use the shared family instead of a fallback.

* Wed Oct 14 2026 MANTIS SYSTEMS - 1.0.0-10
- Select the native icon theme in the desktop-only Qt style; use PCManFM's supported fallback setting.

* Wed Oct 14 2026 MANTIS SYSTEMS - 1.0.0-9
- Share one Obsidian/Platinum icon family through a native desktop theme and a scoped Strata SVG resource overlay; preserve the attested ELF.

* Tue Oct 13 2026 MANTIS SYSTEMS - 1.0.0-8
- Use ordinary shell readiness for icon ordering while retaining the full native-lock health check.

* Tue Oct 13 2026 MANTIS SYSTEMS - 1.0.0-7
- Keep FileManager1 ownership with the default file manager in desktop-only mode.

* Tue Oct 13 2026 MANTIS SYSTEMS - 1.0.0-6
- Resolve the canonical SVG directly so an active desktop cannot retain a missing theme-icon cache entry.

* Tue Oct 13 2026 MANTIS SYSTEMS - 1.0.0-5
- Use the canonical Obsidian/Platinum folder icon for Strata's installed launcher.

* Tue Oct 13 2026 MANTIS SYSTEMS - 1.0.0-4
- Wait for the existing DMS shell readiness check before mapping desktop icons.

* Tue Oct 13 2026 MANTIS SYSTEMS - 1.0.0-3
- Correct desktop startup ordering without changing the DMS or authentication services.

* Tue Oct 13 2026 MANTIS SYSTEMS - 1.0.0-2
- Restrict automatic desktop-icon startup to the GREYWARD Labwc session.

* Tue Oct 13 2026 MANTIS SYSTEMS - 1.0.0-1
- Package the verified upstream candidate with confined ordinary-user desktop integration.
