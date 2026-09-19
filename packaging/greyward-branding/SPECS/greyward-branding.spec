Name:           greyward-branding
Version:        0.1.0
Release:        15%{?dist}
Summary:        GREYWARD-owned shell, Anaconda, wallpaper, and Plymouth branding assets
License:        GPL-3.0-only AND LicenseRef-GREYWARD-Branding
BuildArch:      noarch
Requires:       plymouth-plugin-script
Requires:       plymouth-plugin-label
Source0:        greyward.plymouth
Source1:        greyward.script
Source2:        greyward-symbol-256.png
Source3:        greyward-update-status.service
Source4:        greyward-anaconda.css
Source5:        greyward-anaconda.conf
Source6:        greyward-symbol.svg
Source7:        greyward-cockpit-branding.css
Source8:        GREYWARD-Branding-NOTICE

%description
Canonical GREYWARD presentation assets. This package does not replace Fedora
release identity. The development-appliance installer selects the theme and
rebuilds initramfs; removal restores the prior theme when one was recorded.

%prep

%build

%install
install -d %{buildroot}%{_datadir}/greyward/branding
install -d %{buildroot}%{_datadir}/plymouth/themes/greyward
install -d %{buildroot}%{_datadir}/anaconda/pixmaps
install -d %{buildroot}%{_sysconfdir}/anaconda/profile.d
install -d %{buildroot}%{_sysconfdir}/cockpit/branding
install -d %{buildroot}%{_unitdir}/system-update.target.wants
install -m 0644 %{SOURCE0} %{buildroot}%{_datadir}/plymouth/themes/greyward/greyward.plymouth
install -m 0644 %{SOURCE1} %{buildroot}%{_datadir}/plymouth/themes/greyward/greyward.script
install -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/plymouth/themes/greyward/greyward-symbol-256.png
install -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/greyward/branding/greyward-symbol-256.png
install -m 0644 %{SOURCE3} %{buildroot}%{_unitdir}/greyward-update-status.service
install -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/anaconda/pixmaps/greyward-anaconda-logo.png
install -m 0644 %{SOURCE4} %{buildroot}%{_datadir}/anaconda/pixmaps/greyward-anaconda.css
install -m 0644 %{SOURCE5} %{buildroot}%{_sysconfdir}/anaconda/profile.d/greyward.conf
install -m 0644 %{SOURCE7} %{buildroot}%{_sysconfdir}/cockpit/branding/branding.css
install -m 0644 %{SOURCE6} %{buildroot}%{_sysconfdir}/cockpit/branding/greyward-symbol.svg
install -D -m 0644 %{SOURCE8} %{buildroot}%{_licensedir}/%{name}/GREYWARD-Branding-NOTICE
ln -s ../greyward-update-status.service %{buildroot}%{_unitdir}/system-update.target.wants/greyward-update-status.service

%files
%{_datadir}/greyward
%{_datadir}/plymouth/themes/greyward
%{_datadir}/anaconda/pixmaps/greyward-anaconda-logo.png
%{_datadir}/anaconda/pixmaps/greyward-anaconda.css
%config(noreplace) %{_sysconfdir}/anaconda/profile.d/greyward.conf
%config(noreplace) %{_sysconfdir}/cockpit/branding/branding.css
%config(noreplace) %{_sysconfdir}/cockpit/branding/greyward-symbol.svg
%{_unitdir}/greyward-update-status.service
%{_unitdir}/system-update.target.wants/greyward-update-status.service
%license %{_licensedir}/%{name}/GREYWARD-Branding-NOTICE

%changelog
* Sat Sep 19 2026 MANTIS SYSTEMS - 0.1.0-15
- Separate GPL scripts and configuration from reserved identity artwork

* Sat Sep 19 2026 MANTIS SYSTEMS - 0.1.0-14
- Record the superseded pre-publication GPL branding proposal

* Sun Sep 06 2026 MANTIS SYSTEMS - 0.1.0-13
- Show explicit update-mode copy and provider-reported Plymouth progress

* Sun Sep 06 2026 MANTIS SYSTEMS - 0.1.0-12
- Keep the installed desktop wallpaper collection limited to the two supplied JPGs

* Sat Sep 05 2026 MANTIS SYSTEMS - 0.1.0-11
- Keep GREYWARD account creation visible in both Anaconda UI generations

* Wed Sep 02 2026 MANTIS SYSTEMS - 0.1.0-10
- Make all Anaconda Web UI text and action states readable on dark surfaces
- Keep disabled, selected, hover, focus, dialog, and form text white

* Wed Sep 02 2026 MANTIS SYSTEMS - 0.1.0-8
- Load the stylesheet through an automatically detected Fedora-derived profile
- Keep the Fedora base identity while applying GREYWARD dark installer chrome

* Wed Sep 02 2026 MANTIS SYSTEMS - 0.1.0-9
- Brand the Anaconda Web UI through Cockpit's supported local branding path
- Use the canonical GREYWARD SVG and dark PatternFly installer chrome

* Tue Sep 01 2026 MANTIS SYSTEMS - 0.1.0-7
- Install the supported Anaconda product stylesheet and configuration hook

* Tue Sep 01 2026 MANTIS SYSTEMS - 0.1.0-6
- Reserve the canonical GREYWARD product branding slot in the installer

* Sun Aug 30 2026 MANTIS SYSTEMS - 0.1.0-5
- Require Fedora's Plymouth label plugin for scripted text rendering

* Sun Aug 30 2026 MANTIS SYSTEMS - 0.1.0-4
- Add the GREYWARD graphical LUKS unlock presentation
- Derive the Plymouth mark exclusively from the canonical symbol SVG

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-3
- Show an explicit update-in-progress status during system-update boots

* Tue Aug 18 2026 MANTIS SYSTEMS - 0.1.0-2
- Install the new GREYWARD symbol and wordmark in boot and unlock branding

* Mon Aug 17 2026 MANTIS SYSTEMS - 0.1.0-1
- Initial deterministic GREYWARD branding package
