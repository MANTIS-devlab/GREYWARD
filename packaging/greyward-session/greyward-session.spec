Name: greyward-session
Version: 0.1.0
Release: 34%{?dist}
Summary: GREYWARD static desktop session policy and factory defaults
License: GPL-3.0-only
BuildArch: noarch
Source0: greyward-session.tar.gz
Requires: greyward-dms
Requires: uwsm
Requires: labwc
Requires: wlr-randr
Requires: wlopm
Requires: python3
Requires: pam
Requires: xdg-desktop-portal-gtk
Requires: xdg-desktop-portal-wlr

%description
Package-owned routing, lock/idle policy, user units and immutable factory
defaults. Existing users' mutable preferences are not part of the RPM payload.

%prep
%setup -q -c -T
tar -xzf %{SOURCE0}

%install
for file in greyward-dms greyward-session-lock greyward-display-power; do
 install -Dm0755 environment/session/$file %{buildroot}/usr/local/bin/$file
done
for file in greyward-dms-session-migrate greyward-dms-state-migrate greyward-dms-runtime-check; do
 install -Dm0755 environment/session/$file %{buildroot}/usr/local/libexec/$file
done
install -Dm0755 environment/production/greyward-start-labwc %{buildroot}/usr/local/libexec/greyward-start-labwc
# A Windows-hosted source tree may carry CRLF into the tarball; Linux needs a byte-exact shebang.
sed -i 's/\r$//' %{buildroot}/usr/local/libexec/greyward-start-labwc
for unit in greyward-dms.service; do
 install -Dm0644 environment/session/$unit %{buildroot}/usr/lib/systemd/user/$unit
done
install -Dm0644 environment/session/greyward-labwc.desktop %{buildroot}/usr/share/wayland-sessions/greyward-labwc.desktop
install -Dm0644 environment/session/greyward-dms-lock.pam %{buildroot}/etc/pam.d/greyward-dms-lock
mkdir -p %{buildroot}/usr/share/greyward/defaults
cp -a environment/session/dankmaterialshell %{buildroot}/usr/share/greyward/defaults/
cp -a environment/session/dms-2.0-defaults %{buildroot}/usr/share/greyward/defaults/dms-2.0
install -Dm0644 environment/session/dankmaterialshell/greyward-obsidian.json %{buildroot}/usr/share/greyward/dms/greyward-obsidian.json
rm -rf %{buildroot}/usr/share/greyward/defaults/dankmaterialshell/plugins
cp -a environment/session/labwc %{buildroot}/usr/share/greyward/defaults/
install -m0644 environment/production/labwc-environment %{buildroot}/usr/share/greyward/defaults/labwc/environment
install -m0755 environment/production/labwc-autostart %{buildroot}/usr/share/greyward/defaults/labwc/autostart
install -m0644 environment/session/labwc/themerc %{buildroot}/usr/share/greyward/defaults/labwc/Greyward/themerc
mkdir -p %{buildroot}/usr/lib/systemd/user/hyprpolkitagent.service.d %{buildroot}/usr/lib/systemd/user/xdg-desktop-portal-gnome.service.d
printf '[Unit]\nConditionEnvironment=HYPRLAND_INSTANCE_SIGNATURE\n' > %{buildroot}/usr/lib/systemd/user/hyprpolkitagent.service.d/greyward-session-owner.conf
printf '[Unit]\nConditionEnvironment=XDG_CURRENT_DESKTOP=GNOME\n' > %{buildroot}/usr/lib/systemd/user/xdg-desktop-portal-gnome.service.d/greyward-session-owner.conf
install -Dm0644 environment/flatpak/greyward-portal-backends.conf %{buildroot}/usr/lib/systemd/user/xdg-desktop-portal.service.d/greyward-backends.conf
install -Dm0644 environment/flatpak/labwc-portals.conf %{buildroot}/etc/xdg-desktop-portal/greyward/labwc-portals.conf
for backend in gtk wlr; do
 ln -s /usr/share/xdg-desktop-portal/portals/$backend.portal %{buildroot}/etc/xdg-desktop-portal/greyward/$backend.portal
done

%files
%config(noreplace) /etc/pam.d/greyward-dms-lock
/usr/local/bin/greyward-*
/usr/local/libexec/greyward-*
/usr/lib/systemd/user/greyward-*.service
/usr/lib/systemd/user/hyprpolkitagent.service.d/greyward-session-owner.conf
/usr/lib/systemd/user/xdg-desktop-portal-gnome.service.d/greyward-session-owner.conf
/usr/lib/systemd/user/xdg-desktop-portal.service.d/greyward-backends.conf
/etc/xdg-desktop-portal/greyward
/usr/share/wayland-sessions/greyward-labwc.desktop
/usr/share/greyward/defaults
/usr/share/greyward/dms/greyward-obsidian.json

%changelog
* Fri Oct 23 2026 MANTIS SYSTEMS - 0.1.0-34
- Pin native Settings in fresh DMS 2.0 taskbars, preserving existing user choices.

* Fri Oct 23 2026 MANTIS SYSTEMS - 0.1.0-32
- Ship the observed reference Overview grid and darker native Obsidian surfaces.
- Own the installed shell theme so RPM verification covers visual drift.

* Thu Oct 22 2026 MANTIS SYSTEMS - 0.1.0-24
- Stage recoverable 2.0 directory migration and additive experience defaults.
- Preserve established layouts, pins, preferences and customized plugin copies.

* Wed Oct 21 2026 MANTIS SYSTEMS - 0.1.0-23
- Rebuild canonical LF defaults for exact installer payload verification.
- Retain native window snapping and the current session integration inputs.

* Mon Oct 19 2026 MANTIS SYSTEMS - 0.1.0-22
- Normalize the protected session launcher to LF so its shebang works in installed systems.

* Wed Oct 14 2026 MANTIS SYSTEMS - 0.1.0-21
- Keep the packaged migration byte-identical by using Fedora's Bash interpreter path.

* Wed Oct 14 2026 MANTIS SYSTEMS - 0.1.0-20
- Rebuild the Strata taskbar default migration from the verified desktop source.

* Wed Oct 14 2026 MANTIS SYSTEMS - 0.1.0-19
- Pin GREYWARD Files in fresh DMS taskbars and migrate only the unchanged old default.

* Wed Oct 14 2026 MANTIS SYSTEMS - 0.1.0-18
- Route enrolled desktop lock requests to the existing protected native DMS owner; preserve ordinary-session native locking.

* Tue Oct 13 2026 MANTIS SYSTEMS - 0.1.0-17
- Distinguish ordinary shell surface readiness from the full native-lock check.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-16
- Finalize the VM display fallback with byte-identical source packaging.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-15
- Apply the advertised 1920x1080 fallback to the exact VM output before DMS starts.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-14
- Seed first-session virtual display defaults and reuse Labwc's current output mode.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-13
- Rebuild current session sources above the installed .149 baseline.
