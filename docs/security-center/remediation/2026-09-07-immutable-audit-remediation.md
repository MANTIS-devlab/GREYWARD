# 2026-09-07 immutable audit remediation

> **Historical record.** This audit predates the Fedora-native Black Box
> terminal migration. Its F01–F06 evidence remains useful context; its F07
> Tabby details are not current product architecture. See the current
> [Black Box remediation record](2026-09-07-f07-blackbox-terminal.md).

## Scope and evidence boundary

This record remediates findings F01-F07 from the immutable runtime audit in
`output/runtime-audit-20260906/AUDIT.md`. The `.149` VM is development evidence,
not a release image. Runtime checks used the development VM over the managed
GREYWARD SSH path; no real C2 address or destructive network fixture was used.

## Finding results

| Finding | Previous state and root cause | Correction | Status |
| --- | --- | --- | --- |
| F01 threat-policy mutation authorization | The system D-Bus default policy allowed `SetThreatException` and `SetThreatIntelEnabled`; payload validation was not an authorization boundary. | Removed those default-context allows. The existing wheel-group allow remains the explicit mutation boundary; `ListRules` remains readable. | **FIXED + RUNTIME VERIFIED** |
| F02 crypto baseline | Production and `.149` selected stock Fedora `FUTURE`, which rejected RSA-2048 third-party signing material and was not GREYWARD-owned. | Added `environment/production/crypto-policy/GREYWARD.pmod`, applied as `DEFAULT:GREYWARD`, retaining RSA-2048 while removing SHA-1, TLS CBC, static RSA key exchange, Camellia, and FFDHE-2048. | **FIXED + RUNTIME VERIFIED** |
| F03 Flatpak provider truthfulness | `flatpak remote-ls --updates` exit status 1 was accepted as an empty update list, allowing a false AVAILABLE/zero/complete result. | Flatpak update queries accept only exit 0; stderr becomes provider degradation and no update is inferred. The actual user-service environment reports `AVAILABLE` only when its query succeeds; the incomplete SSH environment reproduces the failure and the collector reports `DEGRADED`. | **FIXED + RUNTIME VERIFIED** |
| F04 global OpenSnitch projections | Runtime JSON projections and the daemon log were world-readable. | Runtime projections, root spool, and log use root:wheel with 0640 files and 0750 runtime directory; the OpenSnitch drop-in and tmpfiles rule converge the log mode. | **FIXED + RUNTIME VERIFIED** |
| F05 maintained text editor | The production package contract did not include a maintained graphical text editor or its MIME default. | Added Fedora `gnome-text-editor` and `text/plain=org.gnome.TextEditor.desktop`; the VM package, MIME query, and graphical launch fixture passed. | **FIXED + RUNTIME VERIFIED** |
| F06 OpenVPN backend | The production package contract omitted Fedora's NetworkManager OpenVPN plugin. | Added `NetworkManager-openvpn`; a temporary privileged NetworkManager import using a reserved fixture endpoint succeeded and the temporary profile was deleted. | **FIXED + RUNTIME VERIFIED** |
| F07 Tabby sandbox | The canonical launcher still passed `--no-sandbox`, and the upstream `chrome-sandbox` helper was mode 0755. Labwc and Hyprland session launchers also carried the flag. | Removed the flag from the desktop override and both canonical session launchers, selected the Labwc Wayland backend, and made the helper root-owned mode 4755 in production/development deployment. A fresh launcher stayed alive and created Chromium child processes. Tabby's upstream window configuration still uses `nodeIntegration: true` and `contextIsolation: false`, and its own relaunch path still adds `--no-sandbox`; no brittle vendor binary patch was introduced. | **PARTIAL — launcher FIXED + RUNTIME VERIFIED; upstream Tabby renderer/relaunch sandbox limitation remains** |

## F02 compatibility matrix

The applied policy reports `DEFAULT:GREYWARD` and `update-crypto-policies
--is-applied` succeeds. The generated OpenSSL backend retains TLS 1.2/1.3,
modern AEAD suites, RSA-2048-compatible signature algorithms, and FFDHE-3072+
groups. Runtime checks passed for the official Feodo HTTPS feed, a normal HTTPS
endpoint, refreshed DNF metadata, configured Flathub remotes, Secure DNS
resolution through Quad9 DoT, and the installed OpenVPN backend. The runtime
curl build exposes ngtcp2/nghttp3. OpenSnitch allowed the resulting UDP/443
attempts, but the external QUIC handshakes timed out on this VM/network path;
that is recorded as an environment limitation rather than attributed to the
crypto policy.

The following values are taken from the Fedora 44 policy files on `.149` and
the generated `/etc/crypto-policies/state/CURRENT.pol`:

| Property | Fedora DEFAULT | Fedora FUTURE | GREYWARD |
| --- | --- | --- | --- |
| RSA minimum | 2048 | 3072 | 2048 |
| DH minimum | 2048 | 3072 | 3072 |
| SHA-1 signatures | Legacy contextual allowances remain (for example RPM/DNSSEC) | Not permitted by the base profile | Removed globally by `-SHA1`, `-*-SHA1`, and the OpenSSL SHA-1 block; certificates still require `sha1_in_certs=0` |
| TLS baseline | TLS 1.2/1.3; AES-256-CBC remains | TLS 1.2/1.3; no TLS CBC suites | TLS 1.2/1.3; CBC removed |
| Other meaningful differences | Static RSA key exchange, Camellia, and FFDHE-2048 remain available | Static RSA, CBC, and lower DH/RSA sizes removed | Static RSA, Camellia, and FFDHE-2048 removed; RSA-2048 retained for interoperability |

The supported rollback is `sudo update-crypto-policies --set DEFAULT`; affected
applications must be restarted after a policy change. FUTURE remains available
as a manual administrator choice but is not the GREYWARD production contract.

## Regression and repository evidence

- Targeted Python tests: update-center and network-protection suites passed on
  the authoring host; provider-failure, authorization-policy, and Flatpak
  success/failure cases are covered.
- `tests/static.ps1` passed, including production package, MIME, Tabby, image
  staging, and crypto-policy checks.
- `.149` runtime: authorized threat mutation returned success without changing
  enablement; both valid and invalid unauthorized threat mutations returned
  D-Bus `Access denied`; the normal GREYWARD user read Network Activity while
  `nobody` could not read the projections or log; OpenSnitch and its control
  plane restarted successfully.
- The canonical Labwc and fallback Hyprland session launchers are now free of
  `--no-sandbox`; a fresh isolated Wayland launch stayed alive for the fixture
  interval. Existing historical Tabby processes were not killed to preserve
  user terminal work.
- The live session selects `/usr/local/share/applications/tabby.desktop` via
  `XDG_DATA_DIRS=/usr/local/share:/var/lib/flatpak/exports/share:/usr/share`.
  The upstream package entry in `/usr/share/applications/tabby.desktop` still
  contains its vendor `--no-sandbox` flag, but is shadowed by the GREYWARD
  override and was not edited in place because package updates would replace
  that change.
- `.149` has no maintained alternate terminal installed; Tabby is the only
  terminal package present. Because Tabby starts and remains usable with the
  GREYWARD launcher, replacing the supported terminal was not justified as a
  low-risk remediation. The upstream renderer limitation remains explicit in
  the F07 `PARTIAL` status.
- No test residue remains from the OpenVPN, editor, or isolated Tabby fixtures.

## Newly discovered adjacent defects

The development deployer had an adjacent audit validation defect: it searched
only for `key=identity`, while Fedora auditctl displayed the active rule as
`-k identity`. The check now accepts both spellings. The first full Security
Center rebuild was intentionally stopped after the VM entered heavy swap during
the unrelated Tauri/GTK frontend build; the context-only RPM was then built and
installed successfully. The application RPM was not changed by this pass.

The fixture QUIC attempts to Cloudflare, Google, and quic.rocks timed out. The
GREYWARD OpenSnitch/control-plane evidence recorded each UDP/443 attempt as
`ALLOWED`, and ordinary HTTPS succeeded, so this pass found no GREYWARD policy
denial. The remaining explanation is the VM/host/network path or the remote
endpoints; it remains a validation limitation rather than an unscoped firewall
change.

## Post-remediation reboot validation

The system-wide crypto-policy change was followed by an explicit guest reboot
request. The first observation stopped at the expected GREYWARD disk-unlock
prompt (`Unlock GREYWARD`) until the authorized passphrase was entered; no
crypto-policy boot failure was observed. After unlock, SSH returned with a new
boot ID, failed system and user unit lists were empty, and current-boot errors
were limited to the known host TDX capability message and the existing
optional `gkr-pam` control-file warning.

## Final stabilization verdict

F01-F06 are source-remediated and runtime-validated. F07's canonical launch
boundary is corrected and runtime-validated, but the upstream Tabby application
still creates an unsandboxed renderer and relaunches with its own flag; this is
recorded as `PARTIAL` rather than being hidden behind the desktop-entry fix.
F08-F12 were outside this pass and remain governed by the original audit record.

Daily-driver readiness is materially improved: privileged threat mutations are
protected, the threat feed is fresh, provider failures are truthful, telemetry
is constrained, text and OpenVPN workflows are present, and the production
Tabby launcher starts under Wayland without a GREYWARD-supplied
`--no-sandbox`. Stability is supported by an unlocked current boot with no
failed system/user units and no new coredumps. The security-distro assessment
is improved but not complete: the upstream Tabby renderer limitation, the
unresolved external QUIC path, and the untouched F08-F12 findings remain.
