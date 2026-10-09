# Security plugin stability — development evidence, 8 October 2026

Scope: the actual normal `.149` desktop, not release/image acceptance.

## Diagnosis and implementation

User Context had 11 automatic restarts. Native coredump PID 719264 reports
`malloc(): unaligned tcache chunk detected`; a collector stack enters GLib
source allocation through dbus-python while the main thread runs GLib.
Both service entrypoints lacked required threading initialization before
observers. They now call `dbus.mainloop.glib.threads_init()` first.
This fixes a documented precondition and plausible crash cause; short observation
cannot establish long-duration crash elimination.

Confirmed unavailable posture intentionally expires the evidence/action lease.
The plugin incorrectly used that lease for explaining fresh negative observations.
An additive 30-second `display_fresh_until` now preserves that explanation,
without renewing positive evidence or authorizing actions. The recovery watchdog
runs every five seconds. Display-only renewal does not increment content revisions
or reconcile notifications. Missing detection source files leave active alerts;
history and unknown-source cases remain intact. Existing Center activation
recognizes the exact observed GTK and canonical application IDs.

## Installed artifacts and recovery

Tuple: Center 84 / Context 75 / Application Security runtime 27 / DMS 1.6.2-6.
Context RPM SHA-256:
`bfeb7c3314913043efb49d76e23106151644a6254b17db580867aeffca736d7d`.
System plugin QML development overlay SHA-256:
`73ada5155e8477ae66132cf86031975aad2e963d7cd383fac65fafa98dfdcf2c`.
This is an explicitly modified system-plugin file, not a rebuilt DMS package.

Root-only rollback copies are under
`/var/lib/greyward-development/application-security-live/plugin-stability-20261008`:
matched Context 72 RPM, previous selected receipt, plugin and changed modules.
Reinstall that retained RPM, restore plugin and receipt, restart only user Context
and reload only `greywardSecure` on the ordinary desktop DMS socket. Do not target
the separate protected authentication DMS or restart the compositor. Context
upgrade skipped unrelated network-service restart scriptlets.

## Validation

- Fedora Context suite: 308 tests pass, including startup ordering, expired
  action versus negative display lease, positive lease preservation, missing/unknown
  detections and deadline-only notification suppression.
- Frontend UX contracts: 93 pass. Repository static and documentation gates pass.
- Ordinary desktop DMS plugin reload returned `PLUGIN_RELOAD_SUCCESS`.
- VMConnect inspection: taskbar flyout displays Review needed and the malware
  definitions explanation; Security Center remains open.
- Thirty real session-bus samples at two-second intervals: only Review needed;
  minimum display lifetime 19.68 seconds; maximum evidence lifetime -2.05 seconds;
  content revision remained 1. No fabricated positive evidence.
- Context PID 1033993 remained active with zero automatic restarts during the check.
- Installed Context `rpm -V` reports no changes. Protected-desktop verifier
  reports `verified: true`; authentication/compositor processes were not restarted.

Provider visibility issues include firewall and USB unavailable reads, malware
definitions attention and a recorded application access block. These remain
visible; this change does not certify providers healthy. Long-duration crash
observation and packaged DMS overlay promotion remain deferred validation.
