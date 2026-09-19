Name:           greyward-security-context
Version:        0.1.0
Release:        52%{?dist}
Summary:        GREYWARD OpenSnitch control plane and Security Context session bus
License:        GPL-3.0-only
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       opensnitch
Requires:       GeoIP
Requires:       GeoIP-GeoLite-data
Requires:       python3-dbus
Requires:       python3-gobject-base
Requires:       python3-systemd
Requires:       python3-grpcio
Requires:       python3-protobuf
Requires:       clamd
Requires:       clamav
Requires:       clamav-update
Requires:       pipewire-utils
Requires:       wl-clipboard
Requires:       greyward-security-center
Requires:       NetworkManager
Requires:       systemd
Requires:       systemd-resolved
Requires:       dnf5daemon-server
Requires:       dnf5daemon-server-polkit
Requires:       btrfs-progs
Requires:       restic
Requires:       polkit
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
A narrow GREYWARD-owned OpenSnitch v1.8.0 gRPC/protobuf control plane and
Security Context session bus. Removable-media scans use a constrained system
D-Bus operation that accepts only caller-owned permitted paths and returns a
redacted typed result; it exposes no shell or raw clamd control.

%prep
%autosetup

%build

%install
install -Dm0644 data/greyward-security-status.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/greyward-security-status.svg
install -d %{buildroot}%{_prefix}/lib/greyward-security-context
cp -a security-context/greyward_security_context %{buildroot}%{_prefix}/lib/greyward-security-context/
install -Dm0755 security-context/greyward_opensnitch_daemon_configure.py %{buildroot}%{_prefix}/lib/greyward-security-context/greyward_opensnitch_daemon_configure.py
install -Dm0755 security-context/bin/greyward-opensnitch-control-plane %{buildroot}%{_libexecdir}/greyward-opensnitch-control-plane
install -Dm0755 security-context/bin/greyward-opensnitch-policy %{buildroot}%{_libexecdir}/greyward-opensnitch-policy
install -Dm0755 security-context/bin/greyward-opensnitch-daemon-configure %{buildroot}%{_libexecdir}/greyward-opensnitch-daemon-configure
install -Dm0755 security-context/bin/greyward-security-context-user %{buildroot}%{_libexecdir}/greyward-security-context-user
install -Dm0755 security-context/bin/greyward-security-context-session10 %{buildroot}%{_libexecdir}/greyward-security-context-session10
install -Dm0755 security-context/bin/greyward-clamav-scan %{buildroot}%{_libexecdir}/greyward-clamav-scan
install -Dm0755 security-context/bin/greyward-update-center %{buildroot}%{_libexecdir}/greyward-update-center
install -Dm0755 security-context/bin/greyward-update-action %{buildroot}%{_libexecdir}/greyward-update-action
install -Dm0755 security-context/bin/greyward-auto-update %{buildroot}%{_libexecdir}/greyward-auto-update
install -Dm0755 security-context/bin/greyward-recovery-point %{buildroot}%{_libexecdir}/greyward-recovery-point
install -Dm0755 security-context/bin/greyward-backup %{buildroot}%{_libexecdir}/greyward-backup
install -Dm0755 security-context/bin/greyward-secure-dns %{buildroot}%{_libexecdir}/greyward-secure-dns
install -Dm0755 security-context/bin/greyward-feodo-update %{buildroot}%{_libexecdir}/greyward-feodo-update
install -Dm0600 security-context/config/opensnitch-policy.json %{buildroot}%{_sysconfdir}/greyward/opensnitch-policy.json
install -Dm0644 security-context/systemd/greyward-opensnitch-control-plane.service %{buildroot}%{_unitdir}/greyward-opensnitch-control-plane.service
install -Dm0644 security-context/systemd/greyward-secure-dns.service %{buildroot}%{_unitdir}/greyward-secure-dns.service
install -Dm0644 security-context/systemd/greyward-security-context-user.service %{buildroot}%{_userunitdir}/greyward-security-context-user.service
install -Dm0644 security-context/systemd/greyward-clamav-scan.service %{buildroot}%{_unitdir}/greyward-clamav-scan.service
install -Dm0644 security-context/systemd/greyward-opensnitch-policy.service %{buildroot}%{_unitdir}/greyward-opensnitch-policy.service
install -Dm0644 security-context/systemd/greyward-feodo-update.service %{buildroot}%{_unitdir}/greyward-feodo-update.service
install -Dm0644 security-context/systemd/greyward-feodo-update.timer %{buildroot}%{_unitdir}/greyward-feodo-update.timer
install -Dm0644 security-context/systemd/greyward-auto-update.service %{buildroot}%{_unitdir}/greyward-auto-update.service
install -Dm0644 security-context/systemd/greyward-auto-update.timer %{buildroot}%{_unitdir}/greyward-auto-update.timer
install -Dm0644 security-context/systemd/greyward-update-center.service %{buildroot}%{_userunitdir}/greyward-update-center.service
install -Dm0644 security-context/dbus/systems.mantis.greyward.ClamAvScan1.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/systems.mantis.greyward.ClamAvScan1.conf
install -Dm0644 security-context/dbus/systems.mantis.greyward.SecurityContext1.service %{buildroot}%{_datadir}/dbus-1/services/systems.mantis.greyward.SecurityContext1.service
install -Dm0644 security-context/dbus/org.greyward.Update1.service %{buildroot}%{_datadir}/dbus-1/services/org.greyward.Update1.service
install -Dm0644 security-context/polkit/org.greyward.Update1.policy %{buildroot}%{_datadir}/polkit-1/actions/org.greyward.Update1.policy
install -Dm0644 security-context/polkit/org.greyward.RecoveryPoint.policy %{buildroot}%{_datadir}/polkit-1/actions/org.greyward.RecoveryPoint.policy
install -Dm0644 security-context/polkit/49-greyward-recovery.rules %{buildroot}%{_sysconfdir}/polkit-1/rules.d/49-greyward-recovery.rules
install -Dm0644 security-context/polkit/49-greyward-usbguard-read.rules %{buildroot}%{_sysconfdir}/polkit-1/rules.d/49-greyward-usbguard-read.rules
install -Dm0644 security-context/dbus/systems.mantis.greyward.ClamAvScan1.service %{buildroot}%{_datadir}/dbus-1/system-services/systems.mantis.greyward.ClamAvScan1.service
install -Dm0644 security-context/dbus/systems.mantis.greyward.OpenSnitchPolicy1.service %{buildroot}%{_datadir}/dbus-1/system-services/systems.mantis.greyward.OpenSnitchPolicy1.service
install -Dm0644 security-context/dbus/systems.mantis.greyward.OpenSnitchPolicy1.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/systems.mantis.greyward.OpenSnitchPolicy1.conf
install -Dm0644 security-context/dbus/systems.mantis.greyward.SecureDns1.service %{buildroot}%{_datadir}/dbus-1/system-services/systems.mantis.greyward.SecureDns1.service
install -Dm0644 security-context/dbus/systems.mantis.greyward.SecureDns1.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/systems.mantis.greyward.SecureDns1.conf
install -Dm0644 security-context/systemd/10-greyward-control-plane.conf %{buildroot}%{_unitdir}/opensnitch.service.d/10-greyward-control-plane.conf
install -Dm0644 security-context/tmpfiles.d/greyward-opensnitch.conf %{buildroot}%{_tmpfilesdir}/greyward-opensnitch.conf

%post
%systemd_post greyward-opensnitch-control-plane.service
%systemd_post greyward-opensnitch-policy.service
%systemd_post greyward-feodo-update.timer
%systemd_post greyward-auto-update.timer
%systemd_post greyward-clamav-scan.service
%systemd_post greyward-secure-dns.service
%systemd_user_post greyward-security-context-user.service
%systemd_user_post greyward-update-center.service

%preun
%systemd_preun greyward-opensnitch-control-plane.service
%systemd_preun greyward-opensnitch-policy.service
%systemd_preun greyward-feodo-update.timer
%systemd_preun greyward-auto-update.timer
%systemd_preun greyward-clamav-scan.service
%systemd_preun greyward-secure-dns.service

%postun
%systemd_postun_with_restart greyward-opensnitch-control-plane.service
%systemd_postun_with_restart greyward-opensnitch-policy.service
%systemd_postun_with_restart greyward-feodo-update.timer
%systemd_postun_with_restart greyward-auto-update.timer
%systemd_postun_with_restart greyward-clamav-scan.service
%systemd_postun_with_restart greyward-secure-dns.service
%systemd_user_postun_with_restart greyward-security-context-user.service
%systemd_user_postun_with_restart greyward-update-center.service

%files
%license LICENSE
%{_datadir}/icons/hicolor/scalable/apps/greyward-security-status.svg

%dir %{_prefix}/lib/greyward-security-context
%{_prefix}/lib/greyward-security-context/greyward_security_context
%{_prefix}/lib/greyward-security-context/greyward_opensnitch_daemon_configure.py
%{_libexecdir}/greyward-opensnitch-control-plane
%{_libexecdir}/greyward-opensnitch-policy
%{_libexecdir}/greyward-opensnitch-daemon-configure
%{_libexecdir}/greyward-security-context-user
%{_libexecdir}/greyward-security-context-session10
%{_libexecdir}/greyward-clamav-scan
%{_libexecdir}/greyward-update-center
%{_libexecdir}/greyward-update-action
%{_libexecdir}/greyward-auto-update
%{_libexecdir}/greyward-recovery-point
%{_libexecdir}/greyward-backup
%{_libexecdir}/greyward-secure-dns
%{_libexecdir}/greyward-feodo-update
%attr(0600,root,root) %{_sysconfdir}/greyward/opensnitch-policy.json
%{_unitdir}/greyward-opensnitch-control-plane.service
%{_unitdir}/greyward-opensnitch-policy.service
%{_unitdir}/greyward-feodo-update.service
%{_unitdir}/greyward-feodo-update.timer
%{_unitdir}/greyward-auto-update.service
%{_unitdir}/greyward-auto-update.timer
%{_userunitdir}/greyward-security-context-user.service
%{_userunitdir}/greyward-update-center.service
%{_unitdir}/greyward-clamav-scan.service
%{_unitdir}/greyward-secure-dns.service
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/systems.mantis.greyward.ClamAvScan1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/systems.mantis.greyward.OpenSnitchPolicy1.conf
%{_datadir}/dbus-1/services/systems.mantis.greyward.SecurityContext1.service
%{_datadir}/dbus-1/services/org.greyward.Update1.service
%{_datadir}/polkit-1/actions/org.greyward.Update1.policy
%{_datadir}/polkit-1/actions/org.greyward.RecoveryPoint.policy
%config(noreplace) %{_sysconfdir}/polkit-1/rules.d/49-greyward-recovery.rules
%config(noreplace) %{_sysconfdir}/polkit-1/rules.d/49-greyward-usbguard-read.rules
%{_datadir}/dbus-1/system-services/systems.mantis.greyward.ClamAvScan1.service
%{_datadir}/dbus-1/system-services/systems.mantis.greyward.OpenSnitchPolicy1.service
%{_datadir}/dbus-1/system-services/systems.mantis.greyward.SecureDns1.service
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/systems.mantis.greyward.SecureDns1.conf
%dir %{_unitdir}/opensnitch.service.d
%{_unitdir}/opensnitch.service.d/10-greyward-control-plane.conf
%{_tmpfilesdir}/greyward-opensnitch.conf


%changelog
* Sat Sep 19 2026 MANTIS SYSTEMS - 0.1.0-52
- Apply the GPL grant to the packaged GREYWARD status artwork.

* Fri Sep 18 2026 MANTIS SYSTEMS - 0.1.0-51
- Add the hardened two-day unattended system-update timer and desktop notification.

* Sun Sep 06 2026 MANTIS SYSTEMS - 0.1.0-46
- Add bounded Feodo recommended-feed threat blocking through OpenSnitch.

* Sun Sep 06 2026 MANTIS SYSTEMS - 0.1.0-45
- Ship the live privacy capsule D-Bus projection and change notification.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-44
- Restore NetworkManager DNS when Automatic secure probing fails without a snapshot.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-43
- Enable Automatic Secure DNS by default with an explicit read-only rollback marker.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-42
- Add the hardened per-link GREYWARD Secure DNS reconciler and Security Context contract.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-41
- Keep liveness probing compatible with the root-only OpenSnitch socket.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-40
- Reuse the authoritative liveness probe for idle and degraded snapshots.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-39
- Probe degraded snapshots that have no heartbeat timestamp.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-38
- Require control-socket liveness before reporting OpenSnitch link health.
