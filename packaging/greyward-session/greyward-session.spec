Name: greyward-session
Version: 0.1.0
Release: 7%{?dist}
Summary: GREYWARD static desktop session policy and factory defaults
License: GPL-3.0-only
BuildArch: noarch
Source0: greyward-session.tar.gz
Requires: greyward-dms
Requires: uwsm
Requires: labwc
Requires: wlopm
Requires: python3
Requires: pam

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
for unit in greyward-dms.service; do
 install -Dm0644 environment/session/$unit %{buildroot}/usr/lib/systemd/user/$unit
done
install -Dm0644 environment/session/greyward-labwc.desktop %{buildroot}/usr/share/wayland-sessions/greyward-labwc.desktop
install -Dm0644 environment/session/greyward-dms-lock.pam %{buildroot}/etc/pam.d/greyward-dms-lock
mkdir -p %{buildroot}/usr/share/greyward/defaults
cp -a environment/session/dankmaterialshell %{buildroot}/usr/share/greyward/defaults/
rm -rf %{buildroot}/usr/share/greyward/defaults/dankmaterialshell/plugins
cp -a environment/session/labwc %{buildroot}/usr/share/greyward/defaults/
install -m0644 environment/production/labwc-environment %{buildroot}/usr/share/greyward/defaults/labwc/environment
install -m0755 environment/production/labwc-autostart %{buildroot}/usr/share/greyward/defaults/labwc/autostart
install -m0644 environment/session/labwc/themerc %{buildroot}/usr/share/greyward/defaults/labwc/Greyward/themerc
mkdir -p %{buildroot}/usr/lib/systemd/user/hyprpolkitagent.service.d %{buildroot}/usr/lib/systemd/user/xdg-desktop-portal-gnome.service.d
printf '[Unit]\nConditionEnvironment=HYPRLAND_INSTANCE_SIGNATURE\n' > %{buildroot}/usr/lib/systemd/user/hyprpolkitagent.service.d/greyward-session-owner.conf
printf '[Unit]\nConditionEnvironment=XDG_CURRENT_DESKTOP=GNOME\n' > %{buildroot}/usr/lib/systemd/user/xdg-desktop-portal-gnome.service.d/greyward-session-owner.conf

%files
%config(noreplace) /etc/pam.d/greyward-dms-lock
/usr/local/bin/greyward-*
/usr/local/libexec/greyward-*
/usr/lib/systemd/user/greyward-*.service
/usr/lib/systemd/user/hyprpolkitagent.service.d/greyward-session-owner.conf
/usr/lib/systemd/user/xdg-desktop-portal-gnome.service.d/greyward-session-owner.conf
/usr/share/wayland-sessions/greyward-labwc.desktop
/usr/share/greyward/defaults
