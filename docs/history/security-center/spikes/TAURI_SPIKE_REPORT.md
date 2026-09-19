# GREYWARD Security Center — Tauri Migration Record

> Historical spike record. Current implementation is under `security-center/tauri/`.

## Historical spike outcome

The former Tauri 2 spike was approved and completed as the canonical GREYWARD
Security Center frontend. Its source moved to `security-center/tauri`; there is
no remaining spike directory and no GTK presentation crate in the workspace.

## Final classification

CANONICAL FRONTEND: TAURI

MIGRATION STATUS: COMPLETE

GTK FRONTEND: REMOVED

GTK VS TAURI DECISION: APPROVED — TAURI

## Preserved backend and IPC boundary

- Existing `greyward-security-domain` and `greyward-security-backends` logic
  remains the source of posture, evidence, privacy, and validated controls.
- The Tauri frontend exposes six pages: Overview, Network, Applications,
  Devices, Evidence, and Privacy.
- Registered typed commands remain limited to page reads, verified Network
  trust-zone changes, safe export, and bounded activity clearing.
- The webview has no arbitrary shell, filesystem, D-Bus, sudo, or generic
  command capability.

## Environment repair and dependencies

GREYWARD-DEV had valid routing but inherited a non-resolving DNS server
(private gateway redacted). The active NetworkManager profile was repaired to use
`1.1.1.1` and `8.8.8.8`; Fedora repositories and crates.io then responded.

Fedora 44 packages installed for the canonical build/runtime were:

- `webkit2gtk4.1-devel` and `webkit2gtk4.1`
- `openssl-devel`
- `libappindicator-gtk3-devel`
- `librsvg2-devel`
- `libxdo-devel`

The existing `cargo`, `rust`, `rustfmt`, `clippy`, `desktop-file-utils`, and
`rpm-build` packages were already present. `wtype` was installed only for the
one Wayland keyboard-validation pass; it is not a production dependency.

## Build, packaging, and runtime validation

| Gate | Status | Evidence |
| --- | --- | --- |
| Fedora production build | PASS | Locked Tauri release build completed inside `rpmbuild` |
| Workspace tests | PASS | RPM `%check` ran `cargo test --workspace --locked` |
| RPM | PASS | `greyward-security-center-0.1.0-6.fc44.x86_64.rpm` built and installed |
| Desktop identity | PASS | One validated entry: `systems.mantis.greyward.securitycenter.desktop` |
| DMS/Labwc launch | PASS | `/usr/bin/greyward-security-center` launched in the active Wayland DMS session |
| Pages/navigation | PASS | Overview, Network, Applications, Devices, Evidence, and Privacy captured through keyboard navigation |
| Network action | PASS | UI changed `eth0` to `trusted`, then restored it to `public`; `firewall-cmd` verified both states |
| Privacy actions | PASS | UI created `posture-latest.json` (mode `0600`) and cleared `activity.json` |
| Single instance | PASS | One running Security Center process after launch |
| Resource sample | PASS | Idle sample: RSS about 174 MiB, CPU about 3.1% shortly after launch |

The build initially exposed two genuine Tauri integration defects: CRLF in the
RPM spec and a missing/non-RGBA Tauri icon. The manifests/spec were normalized
to LF and `tauri/src-tauri/icons/icon.png` was added as an RGBA encoding of the
existing GREYWARD package icon. No Rust security boundary was weakened.

## Canonical final state

- One Security Center frontend: Tauri under `security-center/tauri`.
- One package: `greyward-security-center`.
- One desktop identity and launcher.
- No GTK presentation crate or obsolete Tauri spike duplicate.
- Existing Rust security backend/domain logic preserved.

The VM log contains non-fatal Hyper-V/Mesa EGL fallback warnings. The Tauri
application remained running and no Security Center panic or application error
was recorded during validation.

