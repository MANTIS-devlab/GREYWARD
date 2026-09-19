Name:           greyward-security-center
Version:        0.1.0
Release:        47%{?dist}
Summary:        GREYWARD local security posture and control application
License:        GPL-3.0-only AND Apache-2.0 AND OFL-1.1 AND CC0-1.0
Source0:        %{name}-%{version}.tar.gz
%{!?greyward_cargo_target:%global greyward_cargo_target target}

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  pkgconfig(webkit2gtk-4.1)
BuildRequires:  openssl-devel
BuildRequires:  libappindicator-gtk3-devel
BuildRequires:  librsvg2-devel
BuildRequires:  libxdo-devel
BuildRequires:  desktop-file-utils
BuildRequires:  gcc
BuildRequires:  pkgconfig(libnautilus-extension-4)
Requires:       webkit2gtk4.1
Requires:       libnotify
Requires:       nautilus
Requires:       python3-gobject-base
Requires:       gtk4

%description
Unprivileged Tauri 2 application for the GREYWARD Security Center, with a
focused GTK4 file-context companion and Nautilus menu integration. The Rust
domain and backend crates provide posture collection and evaluation; desktop
surfaces are limited to explicit typed Tauri or Security Context commands.

%prep
%autosetup

%build
build_started=$SECONDS
export CARGO_TARGET_DIR="%{greyward_cargo_target}"
cargo build --workspace --release --locked --features greyward-security-center/custom-protocol
printf 'GREYWARD_TIMING stage=rust-tauri-build seconds=%s\n' "$((SECONDS - build_started))"

%check
%if 0%{?greyward_skip_rust_tests}
printf 'GREYWARD_TIMING stage=rust-tests seconds=0 (already passed against staged source)\n'
%else
export CARGO_TARGET_DIR="%{greyward_cargo_target}"
test_started=$SECONDS
cargo test --workspace --locked
printf 'GREYWARD_TIMING stage=rust-tests seconds=%s\n' "$((SECONDS - test_started))"
%endif

%install
install -Dm0755 "%{greyward_cargo_target}/release/greyward-security-center" \
  %{buildroot}%{_bindir}/greyward-security-center
install -Dm0755 "%{greyward_cargo_target}/release/greyward-security-profile" \
  %{buildroot}%{_libexecdir}/greyward-security-profile
install -Dm0755 data/greyward-security-center-launch \
  %{buildroot}%{_bindir}/greyward-security-center-launch
install -Dm0755 data/greyward-security-center-route \
  %{buildroot}%{_bindir}/greyward-security-center-route
install -Dm0755 file-context/greyward-file-context \
  %{buildroot}%{_bindir}/greyward-file-context
install -Dm0755 file-context/greyward-file-context.py \
  %{buildroot}%{_libexecdir}/greyward-file-context
desktop-file-install \
  --dir=%{buildroot}%{_datadir}/applications \
  data/systems.mantis.greyward.securitycenter.desktop
install -Dm0644 data/greyward-security-center.png \
  %{buildroot}%{_datadir}/icons/hicolor/64x64/apps/greyward-security-center.png
install -Dm0644 data/greyward-symbol.svg \
  %{buildroot}%{_datadir}/greyward-security-center/greyward-symbol.svg
install -Dm0644 data/fonts/InterVariable.ttf \
  %{buildroot}%{_datadir}/fonts/greyward-security-center/InterVariable.ttf
install -Dm0644 data/fonts/MaterialSymbolsRounded.ttf \
  %{buildroot}%{_datadir}/fonts/greyward-security-center/MaterialSymbolsRounded.ttf
cc -shared -fPIC -o greyward-safe-open.so nautilus/greyward-safe-open.c \
  $(pkg-config --cflags --libs libnautilus-extension-4)
install -Dm0755 greyward-safe-open.so \
  %{buildroot}%{_libdir}/nautilus/extensions-4/libgreyward-safe-open.so

%files
%license LICENSE
%license vendor/tao-0.35.3/LICENSE
%license data/fonts/Inter-OFL-1.1.txt
%license data/fonts/Material-Symbols-Apache-2.0.txt
%doc THIRD_PARTY_NOTICES.md
%{_bindir}/greyward-security-center
%{_libexecdir}/greyward-security-profile
%{_bindir}/greyward-security-center-launch
%{_bindir}/greyward-security-center-route
%{_bindir}/greyward-file-context
%{_libexecdir}/greyward-file-context
%{_datadir}/applications/systems.mantis.greyward.securitycenter.desktop
%{_datadir}/icons/hicolor/64x64/apps/greyward-security-center.png
%{_datadir}/greyward-security-center/greyward-symbol.svg
%{_datadir}/fonts/greyward-security-center/InterVariable.ttf
%{_datadir}/fonts/greyward-security-center/MaterialSymbolsRounded.ttf
%{_libdir}/nautilus/extensions-4/libgreyward-safe-open.so
%post
/usr/bin/fc-cache -f >/dev/null 2>&1 || :
%postun
/usr/bin/fc-cache -f >/dev/null 2>&1 || :
%changelog
* Sat Sep 19 2026 MANTIS SYSTEMS - 0.1.0-47
- Record exact font receipts and apply the GPL grant to GREYWARD artwork.

* Sat Sep 19 2026 MANTIS SYSTEMS - 0.1.0-46
- Declare the standalone GTK file-context runtime and correct public metadata.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-45
- Restore and focus the Security Center window for shell update deep links.

* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-44
- Use an explicit rail/workspace grid to remove the duplicated navigation offset.
* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-43
- Tighten the top content inset so the main view sits directly below the context bar.
* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-42
- Remove the centered content max-width that left a large rail-to-content gap in the desktop render.
* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-41
- Recompose the Security Center shell, posture brief, protection register, and shared visual system.
- Improve readable contrast, desktop interaction states, and responsive hierarchy.
* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-40
- Tighten shell rail clearance and reclaim the left workspace for main content.
* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-39
- Correct the shell grid gutters and give the main desktop workspace more room.
* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-38
- Keep vendored identity marks readable on the dark GREYWARD theme.
* Tue Aug 25 2026 MANTIS SYSTEMS - 0.1.0-35
- Distinguish degraded OpenSnitch link health from a healthy connection.

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-34
- Rebalance the Security Center sidebar brand lockup for desktop readability

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-33
- Add an interactive OpenSnitch link probe and explicit idle health presentation

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-32
- Use the enlarged GREYWARD mark for the Tauri open-window taskbar icon

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-31
- Add balanced insets to Overview review content and actions

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-30
- Keep the compact 1100px sidebar logo centered without overflow

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-29
- Center the enlarged Security Center brand lockup and improve wordmark readability

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-28
- Stack the enlarged Security Center brand lockup for sidebar space


* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-27
- Double the GREYWARD branding scale again for Security Center and the launcher

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-26
- Increase the Security Center and DMS launcher GREYWARD logo scale

* Mon Aug 24 2026 MANTIS SYSTEMS - 0.1.0-25
- Add the shared Security Context privacy-profile helper for DMS shell controls

* Fri Aug 21 2026 MANTIS SYSTEMS - 0.1.0-10
- Add a scoped Tao override so Labwc provides native server-side decorations
* Fri Aug 21 2026 MANTIS SYSTEMS - 0.1.0-9
- Restore native Labwc decorations and controls
- Increase default window, shared text sizing, and GREYWARD SVG branding scale
* Fri Aug 21 2026 MANTIS SYSTEMS - 0.1.0-8
- Refine Tauri typography, quiet semantic states, GREYWARD branding, and integrated window chrome
* Fri Aug 21 2026 MANTIS SYSTEMS - 0.1.0-7
- Recompose the Tauri Security Center presentation with a premium local-first desktop UI
- Add differentiated overview and detail-page information hierarchies
* Fri Aug 21 2026 MANTIS SYSTEMS - 0.1.0-6
- Cut over the canonical Security Center frontend from GTK to Tauri 2
- Keep the existing application identity, launcher, desktop entry, and Rust backends
- Add a durable desktop launcher and graphical-session environment repair
* Fri Aug 21 2026 MANTIS SYSTEMS - 0.1.0-4
- Polish navigation icon treatment, translucent surfaces, and responsive desktop sizing
* Fri Aug 21 2026 MANTIS SYSTEMS - 0.1.0-3
- Rebuild Security Center presentation with canonical SVG branding and split Overview findings
* Fri Aug 21 2026 MANTIS SYSTEMS - 0.1.0-2
- Add GREYWARD Session 9 visual integration and launcher icon
* Thu Aug 20 2026 MANTIS SYSTEMS - 0.1.0-1
- Add read-only evidence adapters, deterministic posture integration, and Fedora validation
