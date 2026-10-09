# Normal-seat administration and desktop compatibility — 9 October 2026

Scoped development evidence on `.149`, not clean-image, physical-hardware or
production recovery acceptance. This follows the [earlier administration
receipt](2026-10-09-practical-administration.md). The current authorities remain
[enrollment](../../security-center/APPLICATION_SECURITY_ENROLLMENT.md) and
[privilege model](../../security-center/PRIVILEGE_MODEL.md).

## Activation and installed inputs

The user explicitly approved logout/login. The graphical seat was replaced
without rebooting, powering off or terminating SSH. Fedora PAM admitted the
normal development-user account into session 815. Its ordinary user manager retains
`greyward_guard_t`; the compositor and native authentication remain separate
protected domains. SELinux is Enforcing. Repeated trusted PID-1 coverage checks
return `{"verified":true}`.

Installed: Center 89, Context 81, experimental Application Security runtime 32,
session package 8; DMS 1.6.2-6, Labwc 0.9.6, Quickshell 0.3.1-5. The immutable
development desktop manifest is
`dfeacce4be31dec0f1b1d30d02e5dc2c9582585737689075f3ee7a06b4377c5d`.
SELinux and assembled desktop/Administration inputs remain explicit development
inputs; installing the experimental RPM alone does not enroll a machine.
Normal activation and Administration/grant exercises began on Center 88/runtime
31. The final matched installation is Center 89/runtime 32; its source build
checks pass, RPM verification is clean, and fresh live coverage returns true.
The previously running intermediate Center was replaced by restarting only
Security Center. PID-1 inspection confirms the running executable's SHA-256
matches the final installed binary; the selected-input receipt records that
process and digest. The graphical session and SSH remained running.
The latter revisions add main-window wake-up/chrome and static display labels;
they do not change the reviewed-grant engine or Fedora authentication policy.

Two existing first-party DMS development overlays matched current source but
their old package receipt hashes did not. After login, strict verification
therefore refused the shell. The root-owned development receipt was backed up
and reconciled for those two files; binary/shell/other-file verification remains
enabled. DMS starts and the normal taskbar is visible. This is documented
development package drift, not a reproducible or production DMS package receipt.

## Root causes and corrections

| Actual failure | Correction and adjacent boundary |
|---|---|
| Fresh user D-Bus failed to watch relabeled Flatpak service directories; the first normal login could not start desktop services | Permit `watch` on public activation directories. Add CIL removal of inherited ordinary-helper metadata writes; deployment payload/private data permissions are unchanged. |
| Old root-attached compositor/auth workers survived an abandoned logind scope | The admission guardian asks PID 1 to stop only the previously validated `session-ID.scope`, even if `loginctl terminate-session` times out. It never terminates the whole user or SSH sessions. The first failed login retired its workers correctly. |
| Proton VPN's Flatpak could not prepare the ordinary OpenVPN certificate mount | Allow ordinary `home_cert_t` directory mount preparation. Registered-resource labels still deny reads, including namespace aliases. No Proton-specific policy. |
| Device-enabled Flatpaks failed enumerating `/dev/udmabuf` | Allow ordinary device metadata/mount preparation; open/read/write/ioctl remain denied. No raw DMA or host capability grant. |
| Transient user jobs started but could not be stopped | Permit ordinary start/stop/reload on `user_tmp_t` unit metadata. The user manager retains its peer-UID checks. Actual job start/stop succeeds; unauthenticated system greetd control remains refused by Polkit. No administrator role or system authorization is granted. |
| Protected Labwc ignored the assembled configuration/theme and used defaults | Static assets inherited `var_lib_t` from staging. Label only the immutable Labwc subtree `usr_t`, retaining the no-op autostart's `bin_t`; persist those contexts in `greyward-application-display.fc` and preparation. Reload the verified compositor without terminating the session. Actual GREYWARD theme/workspaces and single application-owned Center chrome return. General `var_lib_t` reads remain denied. |
| Nested root sudo could not allocate its private PTY, then its shared Fedora password helper failed under ordinary-domain separation | Permit Fedora's confined nested sudo on the dedicated private PTY. Copy the unchanged Fedora helper into the immutable Administration generation, hash-match it to the package binary, and bind it read-only/nosuid only in the private mount namespace. Both sudo domains enter the dedicated password domain; ordinary entry and descriptors remain denied. Fedora PAM/authselect are unchanged. |
| Portal 1.22 Settings aggregation tried GNOME/Mutter despite Labwc GTK preferences | Session package 8 selects the root-owned GTK/wlroots backend set and existing Labwc configuration, avoiding vendor wildcard fallback. Ordinary portal subjects stay confined. |
| 500 historical public icon cache files retained `var_lib_t`, causing cache replacement denials | Explicit development descriptor-based repair restores only user-owned, singly linked public `icon-paintable.png` files with that legacy type. Protected labels, aliases, application data and other files are excluded. No blanket home relabel or `var_lib_t` write allowance. |

The cache repair's first bounded scan stopped after its metadata limit, after
repairing the public icons. It was narrowed to public catalogue entry directories
and rerun idempotently. The final count of legacy icon labels is zero. The repair
is a development migration tool, not a daemon or a production coverage claim.
Bazaar subsequently renders its actual catalogue with icons, but still attempts
to preserve deployment labels on refreshed cache entries. Those relabel requests
remain denied; the migration does not fix that recurring metadata-copy behavior.
Broad deployment-file writes/relabeling were not added to suppress these errors.

## Real installed-system checks

| Workflow | Actual result |
|---|---|
| Normal graphical terminal `sudo -i` | PASS: handoff, native review, fresh PAM, root `sysadm_t`, synthetic protected-fixture read; ordinary terminal receives no privileged input/output channel. |
| Nested sudo | PASS after the dedicated helper repair; kernel audit records successful account/session/command decisions. |
| Native DMS lock/unlock during Administration | PASS: exclusive native lock input, real unlock, Administration resumes; its prior authorization is invalidated while existing root work survives. |
| Administration close | PASS: native two-step End session confirmation closes the dedicated unit; ordinary desktop and SSH survive. |
| Normal terminal-scoped sudo cache | PASS: cached noninteractive sudo succeeds; after the last successful use at 10:20:00 UTC, the 10:22:38 UTC attempt requires a password and does not elevate. Normal Fedora cache reuse refreshes the two-minute window. |
| Brave Flatpak | PASS: real Fedora HTTPS page rendered on the normal desktop. |
| Proton VPN Flatpak | PASS: actual GUI opens; tunnel connection was not attempted because a route change could strand SSH. |
| Newly installed GNOME Calculator Flatpak | PASS: installed from configured Flathub and opens without application-specific policy. Arithmetic interaction is not asserted. |
| Collabora Office Flatpak | PASS: actual Home/templates surface renders. Document editing/printing is not asserted. |
| Native BlackBox and Firefox | PASS: normal terminal renders; native Firefox opens with a disposable existing-directory profile. The first Firefox probe mistakenly selected a nonexistent profile; creating its test directory fixed the probe without policy relaxation. |
| GTK FileChooser and Settings | PASS: real chooser selects the ordinary test document, response 0 and exact expected URI; Settings ReadAll returns appearance values without new GNOME activation errors. |
| Native development/files/background work | PASS: GCC compile and unknown native execution, git initialization, ordinary copy/rename/read, confined user service, DNS, HTTPS and NetworkManager/profile inventory reads. |
| USBGuard projection | PASS: fixed trusted provider returns its device list, empty on this VM. No physical admission/revocation test is claimed. |
| Explicit Flatpak filesystem bind | PASS: ordinary control file readable, protected fixture denied with `EACCES`; audit correlates the ordinary domain and registered resource label. An earlier `--filesystem=host` probe encountered private `/var/tmp` and is not counted as SELinux proof. |
| Reviewed grant and revocation | PASS: real protected Polkit authentication, revision 6→7 with verified readback; matching key-inspection launches and reuse exit 0 without new authentication; direct execution exits 255, another tool is refused. Fresh authenticated revocation commits revision 8; subsequent grant launch fails and the grant list is empty. No key contents or parser output were exported. |
| User background-job control | PASS: a fresh ordinary transient sleep unit starts and stops successfully. Unauthenticated system-service control is refused. |
| Security Center live integration | PASS: Applications and Protected Data visibly reflect the real provider, revision 8 and zero current grants. Covered-window navigation changes the requested page; Updates displayed eight actual available packages. No upgrade transaction was applied. Final-build screenshots confirm single application-owned chrome normally and maximized; Super+A restores the normal window. Bringing a covered window forward is not reliably achieved by the external request; ordinary Alt+Tab works. |
| Bazaar and Nautilus | Actual Bazaar catalogue/icons and the ordinary file-manager test directory render. Cache relabel errors remain explicit below; no installation through Bazaar is claimed. |
| Current kernel boundary | PASS: 937 current-kernel decisions across the ordinary closure, including administrator process/FD/helper/PTY separation, read-only public metadata, user-job control, mount preparation, static display-data reads and denied general state/DMA access. |

Grant changes briefly produced bounded provider deadline failures while kernel
policy was assembled. Requests failed closed; fresh coverage recovered. This
remains a responsiveness limitation, not evidence of a denied request succeeding.
Inventory/grant-list health remains UNKNOWN where the provider lacks complete
inventory evidence; it is not converted into global protection success.

Focused Linux fixtures pass: Administration 6, desktop 4, metadata 2, public-cache
repair 1. Frontend UX contracts pass 93 tests; both repository gates pass. Runtime 31
build checks exercise the existing domain/backend/runtime Cargo suites, and the
native terminal builds with warnings treated as errors. Repository gate results
and the final cache-expiry screenshot are recorded with the final validation
receipt, rather than inferred from these earlier checks. A trusted development
builder running as the enrolled UID outside the ordinary role correctly withdraws
coverage while active; it is not admitted as an ordinary or reviewed workload.

Screenshots and development logs are retained under
`output/compatibility-20261009/` locally and
`/var/tmp/greyward-compatibility-20261009/` on the guest. Root-owned selected-input
and rollback receipts live under
`/var/lib/greyward-development/application-security-live/administration-20261009/`.
`normal-compatibility-final.json` records selected RPM/binary/manifest/policy
digests and fresh coverage. The earlier activation receipt is retained before
recording the completed normal activation; desktop rollback remains pending.

The compatibility approach keeps the existing installed Fedora policy and
Flatpak provider ownership. Upstream [Flatpak permission semantics](https://docs.flatpak.org/en/latest/sandbox-permissions.html)
still govern each sandbox's exposed devices/files; GREYWARD's mandatory resource
labels remain an additional boundary. [Labwc's documented configuration lifecycle](https://labwc.github.io/labwc-config.5.html)
supports the fixed `-C` input and SIGHUP reload used here. Fedora's own
[confined-user manager report](https://github.com/fedora-selinux/selinux-policy/issues/3118)
also documents this category of compatibility work; the actual `.149` denials,
not that report, establish the specific fixes above.

## Limits and remaining gates

- Ordinary screen capture/sharing remains unavailable: wlroots portals cannot
  use protected compositor capture interfaces. Granting ordinary raw capture or
  running a generic portal as authentication would compromise the boundary.
  A protected-surface-aware, consented capture path requires further work.
- No actual VPN tunnel, physical USB/camera/audio, suspend, clean-image install,
  authenticated LUKS rescue boot or whole-desktop rollback rehearsal is claimed.
  Rehearsing desktop rollback requires a separately approved session boundary.
- Unsupported general IDE/SSH/GPG grants stay unavailable. The tested persistent
  profile is fixed, nonexporting OpenSSH key inspection, not arbitrary key access.
- Bazaar cache-copy relabel attempts and unsupported io_uring creation remain
  denied despite the rendered catalogue. Future unfamiliar applications still
  need representative workflow validation; GUI startup does not prove every
  provider operation or permission is compatible.
- Existing Update Center recovery-linked transaction evidence is preserved;
  this pass does not apply system upgrades merely to exercise it.
- External navigation updates the existing Center page, but Wayland focus/raise
  is not reliably granted for a covered window. This remains a usability issue;
  it does not prevent ordinary window switching or expose privileged input.
- Expanded compatibility, performance, hardware and exhaustive adversarial
  matrices remain **DEFERRED HARDENING**. The limitations above are explicit
  functional or acceptance gaps, not claims of completion.

Only inspected disposable compiler outputs were removed; source, packages,
snapshots, recovery and user data were retained. Free encrypted-root space rose
from 1.3 to about 5.9 GiB before subsequent small builds. Retained matched previous
desktop/Administration inputs and policy receipts support rollback preparation;
backup existence alone does not prove restoration.
