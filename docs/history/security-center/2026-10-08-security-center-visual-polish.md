# Security Center visual polish — 8 October 2026

Historical development evidence. Scope: the actual normal `.149` desktop,
not production enrollment, installer or release acceptance.

## Delivered presentation

The UI uses one canonical token/material layer in `materials.css`, loaded
after feature composition and workspace navigation. Obsidian fields, graphite
navigation, illuminated silver focal surfaces and readable semantic colors
are consistent across the application. The pass restores positive/review/
critical/uncertain distinctions rather than reducing all states to neutral.
Inputs, selects, disclosures, confirmations and focus treatment share the
same controls. No framework, alternate policy editor or mock backend is added.

Network Activity retains its dedicated destination, local application identities,
country metadata, chart, allowed/blocked distinctions, live/history modes,
pause and filters. At the minimum size, transport/time metadata moves to another
row instead of clipping. Unknown application identities use an honest generic
glyph rather than a randomly chosen recognizable application logo.

Overview waits for real session coverage before its initial posture is painted.
Cached navigation cannot reuse an expired positive lease. Device-history failure
explains unavailable observations rather than presenting an empty safe result.
Unchanged live coverage preserves the view and focus.

## Installed desktop review

Center 71 / Context 69 / runtime 26 passed actual native-window visual review
at 1440×900 and 1100×700. All 13 destinations were captured at the top and bottom:
Overview, Applications, Protected Data, Files, Network, System checks, Devices,
Threats, Network Activity, Security History, Updates, Recovery and Privacy.
No horizontal overflow was observed. The review corrected nested search borders,
select styling, header alignment and device-history uncertainty. Generated
captures are local, intentionally excluded from Git, under
`output/application-security/20261008-ux-polish/`.

Real no-mutation interactions passed: confirmation cancel and focus restoration,
resource detail open/close and focus restoration, Network Activity expansion,
live/history, pause/resume, search/clear and Security History category reset.
No resource, grant, network, update or recovery mutation was performed by this
visual audit. The resource and grant forms use actual typed installed backend
responses. Earlier authenticated registration and grant/revocation evidence is
in the [normal-session receipt](2026-10-08-application-security-normal-session.md).

Actual expiry still withdrew positive protection to UNKNOWN when observation
renewal was paused; fresh authoritative readback restored PROTECTED. Root
verification returned `{"verified":true}` with SELinux Enforcing. Ordinary
and root SSH, DMS, Context and the workflow broker remained operational.
No session, compositor or authentication-policy restart occurred.

## Final native locale correction

The French launch audit exposed WebKit retaining `en-US` despite the native
process receiving French LANG/LC_ALL. The final source uses WebKit's native
preferred-language API with GLib's desktop-language list before frontend startup.
The existing pinned WebKit dependency is reused; no new security API is added.
PASS: installed Center 72 reports `navigator.language=fr-FR` and catalog `fr`.
All 13 actual French destinations were captured and visually inspected at
1100×700 without horizontal overflow. The temporary French driver was closed;
the normal desktop language was restored without a session restart.

## Final installed package and checks

The final tuple is Center **0.1.0-72.fc44**, Context **0.1.0-69.fc44** and
Application Security experimental **0.1.0-26.fc44**. Context, enforcement,
resources, account mapping and the admitted compositor were unchanged.

| Artifact | SHA-256 |
|---|---|
| Center 72 RPM | `fffed5b4c478a2b4c77046d6bbd95a1afa307ffb56b7d8138d1822b14f4b22b6` |
| Installed Center executable | `250b6ddc13268f9c8e944313933c3f9df56b9aa7044ef99feee6aab15d724716` |
| Source archive | `b21a2bd8174381d003ac8aaac64936fb13b27128f3c1ec5ce062b4df91b147e0` |
| RPM specification | `e326aefdc8fca5f7350f64025c92b232bea45ab89de441e2c6e44c8682042887` |
| Protected desktop manifest | `5073490e79c72dda4c26bab442f5ea38da5615600b54b00b37a7f63946be6946` |

PASS: all three installed packages have clean `rpm -V`; the running Center was
reopened from the new installed executable. Its 13 English destinations pass
actual capture/layout checks at both sizes. Confirmation cancel/focus, resource
detail close/focus and Network Activity expand/collapse pass again. The actual
lease-expiry test changes PROTECTED to UNKNOWN, then restores PROTECTED only
after fresh backend evidence. Ordinary/direct and revoked-grant probes return
DENIED on UID 1001. Existing Brave reads ordinary data and cannot read the
protected key. Root PID-1 verification passes; DMS, Context, broker and SSH
remain available.

During cold background compilation, one 30-second Protected Data observation
contained a 156 ms UNKNOWN interval at real lease expiry; renewed evidence
restored protection. It was not masked as PROTECTED. Applications' 30-second
and Overview's 15-second observations had zero expired samples and no summary
replacement. This is not a performance acceptance claim.
After compilation finished, a repeated 30-second Protected Data observation
had zero expired samples, one stable text state and no summary-node replacement.
The settled Applications view includes the real Flatpak permission results.
Center is left open on Protected Data at 1440×900 in the normal desktop language,
with fresh protection and the actual registered resource visible.

Focused frontend checks pass **115 tests** and native posture checks pass
**3 tests**. Source formatting, scoped native all-targets Clippy with warnings
denied and both repository gates pass. Clippy used Fedora's explicit
`/usr/bin/cargo-clippy clippy` entry point to avoid the unrelated rustup helper
under Cargo's home mixing compiler metadata. The offline RPM
build succeeds using Fedora Rust 1.98.0. Disk preflight: 6.8 GiB free; final
build/check readback: 5.2 GiB. No data cleanup, reboot, logout or ISO mutation
occurred. The root-private active receipt records the final package/digest tuple.

## Limits and recovery

Native WebDriver did not support physical key injection. Semantic controls,
modal state, autofocus and focus restoration were checked; a human keyboard/
screen-reader walkthrough is not claimed. Pagination was not exercised because
no next-page control was available. Exhaustive provider/deputy matrices,
performance/reproducibility, physical-seat/suspend, automatic production lifecycle
and clean-image validation remain DEFERRED HARDENING.

Persistent sensitive grants remain limited to the tested nonexporting
`openssh-key-inspection/v1` READ profile. IDE/signing, unsupported tools,
WRITE and timed raw grants remain UNAVAILABLE. Inventory completeness remains
UNKNOWN separately from actual enrolled-session coverage.

Root-private RPMs and the prior active receipt are retained in
`/var/lib/greyward-development/application-security-live/ux-polish-20261008/`.
This presentation-only rollback restores the prior Center package and matched
receipt without removing protected resources or changing enrollment. Enrollment
and authentication recovery remain owned by the existing live rollback tooling
and earlier receipts; no new recovery path is introduced here.
