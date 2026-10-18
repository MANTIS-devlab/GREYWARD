Name:           greyward-application-security-experimental
Version:        0.1.0
Release:        55%{?dist}
Summary:        Experimental GREYWARD application-security runtime and Guard CLI
License:        GPL-3.0-only AND MIT
Source0:        %{name}-%{version}.tar.gz
%{!?greyward_cargo_target:%global greyward_cargo_target target}
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  python3
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(libseccomp)
BuildRequires:  pkgconfig(wayland-client)
BuildRequires:  wayland-devel
BuildRequires:  wayland-protocols-devel
BuildRequires:  pkgconfig(pangocairo)
BuildRequires:  pkgconfig(xkbcommon)
BuildRequires:  pkgconfig(vterm)
BuildRequires:  pkgconfig(librsvg-2.0)
BuildRequires:  libselinux-devel
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
Requires:       polkit
Requires:       sudo
Requires:       python3-dbus
Requires:       dbus-broker
Requires:       bubblewrap
Requires:       labwc
Requires:       squashfs-tools
Requires:       python3-setools
Requires:       greyward-session

%description
Internal development broker with authenticated owner-scoped inventory reads.
Coverage reads actual enrollment prerequisites; this package does not establish whole-session protection,
automatically install SELinux enrollment or activate grants. A separate explicitly
started provider supplies restrictive managed isolation for normal local users;
resource/grant changes still require the confined enrolled-owner boundary.
There is no preset or automatic activation, and generic application-guard
grants are not automatically activated. The RPM is included only as a
dependency for the separately packaged protected-session enrollment path; it
does not establish release acceptance for broader workload isolation.

%prep
%autosetup

%build
export CARGO_TARGET_DIR="%{greyward_cargo_target}"
export PATH=/usr/bin:/bin
export RUSTC=/usr/bin/rustc RUSTDOC=/usr/bin/rustdoc
/usr/bin/cargo build --release --locked --offline -p greyward-application-security --bins
python3 - <<'PY'
import hashlib
from pathlib import Path

source = Path('packaging/application-security/wayland/security-context-v1.xml')
actual = hashlib.sha256(source.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
expected = 'f4f8ba15ebd2df62db611b1de32e992f660a4aeeea83250cb88fa468da42ffcb'
if actual != expected:
    raise SystemExit('Wayland security-context protocol source hash mismatch')
PY
wayland-scanner client-header packaging/application-security/wayland/security-context-v1.xml security-context-v1-client-protocol.h
wayland-scanner private-code packaging/application-security/wayland/security-context-v1.xml security-context-v1-protocol.c
gcc %{build_cflags} -Wall -Wextra -Werror -I. packaging/application-security/wayland/context.c security-context-v1-protocol.c $(pkg-config --cflags --libs wayland-client) %{build_ldflags} -o greyward-wayland-context
wayland-scanner client-header %{_datadir}/wayland-protocols/staging/ext-session-lock/ext-session-lock-v1.xml ext-session-lock-v1-client-protocol.h
wayland-scanner private-code %{_datadir}/wayland-protocols/staging/ext-session-lock/ext-session-lock-v1.xml ext-session-lock-v1-protocol.c
python3 -I packaging/application-security/administration/embed-logo.py data/greyward-symbol.svg greyward-admin-logo.h
gcc %{build_cflags} -Wall -Wextra -Werror -I. packaging/application-security/administration/terminal.c ext-session-lock-v1-protocol.c $(pkg-config --cflags --libs wayland-client pangocairo xkbcommon vterm libselinux librsvg-2.0) -lutil %{build_ldflags} -o greyward-admin-terminal

%check
export CARGO_TARGET_DIR="%{greyward_cargo_target}"
export PATH=/usr/bin:/bin
export RUSTC=/usr/bin/rustc RUSTDOC=/usr/bin/rustdoc
/usr/bin/cargo test --locked --offline -p greyward-application-security -p greyward-security-domain -p greyward-security-backends

%install
install -d %{buildroot}%{_datadir}/greyward-application-security/administration
install -m0444 packaging/application-security/administration/*.py packaging/application-security/administration/fonts.conf \
    %{buildroot}%{_datadir}/greyward-application-security/administration/
install -m0555 packaging/application-security/administration/sudo-handoff \
    %{buildroot}%{_datadir}/greyward-application-security/administration/
install -Dm0555 packaging/application-security/administration/sudo-handoff %{buildroot}%{_bindir}/greyward-administration
install -Dm0555 greyward-admin-terminal %{buildroot}%{_libexecdir}/greyward-admin-terminal
install -d %{buildroot}%{_datadir}/greyward-application-security/desktop
install -m0444 packaging/application-security/desktop/*.py packaging/application-security/desktop/labwc-*.patch \
    %{buildroot}%{_datadir}/greyward-application-security/desktop/
install -Dm0444 packaging/application-security/authentication/assemble.py \
    %{buildroot}%{_datadir}/greyward-application-security/authentication/assemble.py
install -d %{buildroot}%{_libexecdir}
install -m0755 greyward-wayland-context %{buildroot}%{_libexecdir}/greyward-wayland-context
# Empty fail-closed mount target. Prepared code exists only in the unit's
# private mount namespace; direct execution of this file cannot launch it.
touch %{buildroot}%{_libexecdir}/greyward-guard-entry
chmod 0555 %{buildroot}%{_libexecdir}/greyward-guard-entry
install -Dm0755 "%{greyward_cargo_target}/release/greyward-application-security" \
    %{buildroot}%{_libexecdir}/greyward-application-security
install -Dm0755 "%{greyward_cargo_target}/release/greyward-application-security-development" \
    %{buildroot}%{_libexecdir}/greyward-application-security-development
install -Dm0755 "%{greyward_cargo_target}/release/greyward-guard" \
    %{buildroot}%{_bindir}/greyward-guard
install -Dm0755 "%{greyward_cargo_target}/release/greyward-native-worker" \
    %{buildroot}%{_libexecdir}/greyward-native-worker
install -Dm0644 packaging/application-security/greyward-application-security.service \
    %{buildroot}%{_unitdir}/greyward-application-security.service
install -Dm0644 packaging/application-security/greyward-application-security-workflows.service \
    %{buildroot}%{_unitdir}/greyward-application-security-workflows.service
install -Dm0644 packaging/application-security/greyward-flatpak-metadata.service \
    %{buildroot}%{_unitdir}/greyward-flatpak-metadata.service
install -Dm0644 packaging/application-security/greyward-flatpak-metadata.path \
    %{buildroot}%{_unitdir}/greyward-flatpak-metadata.path
install -Dm0644 packaging/application-security/systems.mantis.greyward.ApplicationSecurity1.conf \
    %{buildroot}%{_datadir}/dbus-1/system.d/systems.mantis.greyward.ApplicationSecurity1.conf
install -Dm0644 packaging/application-security/systems.mantis.greyward.ApplicationSecurity1.policy \
    %{buildroot}%{_datadir}/polkit-1/actions/systems.mantis.greyward.ApplicationSecurity1.policy
install -Dm0644 packaging/application-security/systems.mantis.greyward.ApplicationSecurityDevelopment1.conf \
    %{buildroot}%{_datadir}/dbus-1/system.d/systems.mantis.greyward.ApplicationSecurityDevelopment1.conf

%files
%{_datadir}/greyward-application-security/administration/
%{_libexecdir}/greyward-admin-terminal
%{_bindir}/greyward-administration
%{_datadir}/greyward-application-security/desktop/
%{_datadir}/greyward-application-security/authentication/
%license LICENSE
%license packaging/application-security/wayland/security-context-v1.xml
%doc packaging/application-security/README.md
%{_libexecdir}/greyward-application-security
%{_libexecdir}/greyward-application-security-development
%{_bindir}/greyward-guard
%{_libexecdir}/greyward-native-worker
%{_libexecdir}/greyward-wayland-context
%attr(0555,root,root) %{_libexecdir}/greyward-guard-entry
%{_unitdir}/greyward-application-security.service
%{_unitdir}/greyward-application-security-workflows.service
%{_unitdir}/greyward-flatpak-metadata.service
%{_unitdir}/greyward-flatpak-metadata.path
%{_datadir}/dbus-1/system.d/systems.mantis.greyward.ApplicationSecurity1.conf
%{_datadir}/polkit-1/actions/systems.mantis.greyward.ApplicationSecurity1.policy
%{_datadir}/dbus-1/system.d/systems.mantis.greyward.ApplicationSecurityDevelopment1.conf

%changelog
* Sun Oct 18 2026 MANTIS SYSTEMS - 0.1.0-55
- Preserve protected Polkit keyboard focus after late window activation.

* Sun Oct 18 2026 MANTIS SYSTEMS - 0.1.0-54
- Keep the generated USB approval result parser on one valid JavaScript line.
- Publish only bounded USB availability metadata in a dedicated, atomically written directory.

* Sun Oct 18 2026 MANTIS SYSTEMS - 0.1.0-53
- Route USBGuard review into the active protected authentication shell.

* Sun Oct 18 2026 MANTIS SYSTEMS - 0.1.0-52
- Accept the DMS 1.6.2-20 receipt for the verified USB approval wait and feedback fix.
- Normalize line endings before checking the pinned Wayland protocol input.

* Wed Oct 14 2026 MANTIS SYSTEMS - 0.1.0-51
- Align the production RPM source revision with the validated installed runtime.

* Mon Oct 12 2026 MANTIS SYSTEMS - 0.1.0-45
- Align the runtime RPM source with the rebuilt Security Center manifest set.

* Mon Oct 12 2026 MANTIS SYSTEMS - 0.1.0-44
- Apply the VM display fallback in the protected compositor's root-owned autostart.

* Mon Oct 12 2026 MANTIS SYSTEMS - 0.1.0-43
- Accept DMS v1.6.2-15 only with the existing exact shell receipt and auth-input pins.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-42
- Rebuild from the integrated post-R6 application-security sources.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-41
- Start a minimal trusted splash before initializing the full authentication shell.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-40
- Show a noninteractive GREYWARD startup backdrop while protected login readiness completes.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-39
- Seed the protected DMS auth profile at settings schema v18 to avoid replaying migrations on login.
* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-38
- Poll protected Polkit readiness quickly at login, then retain the low-rate heartbeat.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-37
- Rebuild the current application-security source above the installed .149 package floor.

* Sun Oct 11 2026 MANTIS SYSTEMS - 0.1.0-35
- Accept the matched DMS v1.6.2-14 candidate in authentication assembly.

* Sat Oct 10 2026 MANTIS SYSTEMS - 0.1.0-34
- Add root-attested installer origin and verified revision-8 authentication assembly.
- Keep activation outside runtime scriptlets in the explicit enrollment package.

* Sat Oct 10 2026 MANTIS SYSTEMS - 0.1.0-33
- Mark portal/deputy coverage unverified instead of asserting complete isolation.
- Include Administration visual sources; explicit assembly remains development-only.
- Keep experimental runtime and enrollment excluded from production image inputs.
- Correct concrete Fedora grant memberships and retain canonical prior contexts.

* Fri Oct 09 2026 GREYWARD <greyward@mantis.systems> - 0.1.0-32
- Label immutable compositor configuration and theme as static system data.

* Fri Oct 09 2026 MANTIS SYSTEMS - 0.1.0-31
- Retire only the admitted seat scope after protected worker loss.
- Verify and privately mount the Fedora password helper for protected administration.

* Fri Oct 09 2026 MANTIS SYSTEMS - 0.1.0-30
- Reconcile only public Flatpak service metadata after provider deployment-change notifications.

* Fri Oct 09 2026 GREYWARD maintainers <maintainers@mantis.systems> - 0.1.0-29
- Add protected Administration request/status, private terminal and trusted USBGuard reads.
- Keep enrollment/administration activation explicit and remove conflicting bus ownership.

* Thu Oct 08 2026 GREYWARD maintainers <maintainers@mantis.systems> - 0.1.0-27
- Project bounded historical executable basenames and PIDs from correlated enforcing audit records.

* Thu Oct 08 2026 GREYWARD maintainers <maintainers@mantis.systems> - 0.1.0-26
- Include canonical GREYWARD theme assets in the protected desktop closure.

* Thu Oct 08 2026 MANTIS SYSTEMS - 0.1.0-25
- Remove the competing lock password form during protected Polkit challenges.

* Thu Oct 08 2026 MANTIS SYSTEMS - 0.1.0-24
- Package actual confined desktop handoff and persistent resource readback.
- Retain protected Fedora authentication and reviewed tool restrictions.

* Thu Oct 08 2026 MANTIS SYSTEMS - 0.1.0-22
- Bind raw console input to the protected physical seat without changing ordinary PTYs.
- Verify actual kernel input denials and keep protected authentication logs private.
* Thu Oct 08 2026 MANTIS SYSTEMS - 0.1.0-21
- Add fixed authenticated seat admission and native protected lock routing.
- Verify live role/process/authentication coverage and retained resource labels.
- Remove common helper access to resources across the admitted ordinary role.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-20
- Report missing enrollment and an unconfined caller as unavailable from live evidence.
- Keep positive coverage gated by independent session, label and deputy verification.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-19
- Bind the private display helper to its validated workload UID instead of the private test account.
- Timestamp isolated inventory observations and document explicit installed workflows.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-18
- Preserve traversable private-root directories under the installed broker's 0077 umask.
- Remove the unused broker-side scratch home; PID 1 owns its disposable namespace.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-17
- Create the disposable home in PID 1's workload namespace, not the broker sandbox.
- Record actual managed-content observation timestamps.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-16
- Expose the existing typed dispatcher through explicit installed workflow activation.
- Permit restrictive managed isolation for normal local users without enrolling them.
- Keep resource/grant mutations behind the confined enrolled-owner boundary.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-15
- Require tested generation/revision/argument profiles for persistent grant reuse.
- Refuse generic legacy activation and discard sensitive inspection streams.
- Keep production enrollment and authentication activation disabled.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-14
- Add shared selected-document, fixed interpreter and confined Type-2 extraction.
- Add a private nested graphical display with a pinned security-context protocol.
- Retain explicit development enrollment; production activation remains separate.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-13
- Add descriptor label journals and reviewed development kernel grant preparation.
- Add owner-scoped resource reads and an immutable reviewed launch library.
- Add explicitly selected development mutation/operation transport and Guard CLI.
- Keep default activation and production enrollment disabled.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-12
- Bound read verification and prepare revision/generation-scoped policy lookup.
- Add descriptor-based disconnected native restrictions without a launch API.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-11
- Add per-member native inventory intake without source approval or grants.
- Bound provider startup with four workers and eight outstanding jobs.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-10
- Add internal generation-aware Flatpak registry intake without granting trust.
- Retain bounded child cleanup outside request waits; cap outstanding providers.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-9
- Collect fixed installed RPM metadata with a clean environment and shared deadline.
- Exercise backend provider contracts during the offline package check.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-8
- Require held root-owned ancestry and path membership for installed RPM evidence.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-7
- Share inventory and coverage wire types with the typed read-only facade.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-6
- Add bounded metadata catalogue and descriptor-bound installed RPM evidence.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-5
- Bind builds to the Fedora compiler; add metadata-only directory review leases.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-4
- Keep provider refreshes scoped; partial discovery cannot infer uninstall.
- Add separately executed root MAC and inherited descriptor boundary fixtures.
* Wed Oct 07 2026 MANTIS SYSTEMS - 0.1.0-3
- Add managed-content and fresh-owner authentication boundary tests; retain read-only scope.
* Tue Oct 06 2026 MANTIS SYSTEMS - 0.1.0-2
- Reject truncated existing policy storage; retain experimental read-only scope.
