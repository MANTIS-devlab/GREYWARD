# Security plugin / Center state parity — 8 October 2026

Development integration on normal `.149`, not release/image acceptance.

## Confirmed regression

The real Files & scans page displayed Ready to scan and CURRENT definitions;
`GetFileSecuritySummary` returned AVAILABLE, ClamAV 1.4.6, CURRENT definitions.
The plugin nevertheless raised definitions, firewall and USB provider warnings.
An aggregate unavailable USB detail observation forced otherwise independent shell
provider states unavailable. Firewall health was also incorrectly inferred from
privacy-profile availability instead of the shared network check.

## Canonical correction

The fixed read-only `greyward-security-posture` helper exposes evaluated check IDs,
states, requiredness and accepted-deviation flags from the same Rust evaluator and
per-user acceptance store used by Center. No raw evidence or resource paths are
exported. Context retains detail-source uncertainty but no longer reevaluates the
shared overall posture from those transport failures. The shell uses the explicit
network/device checks, not overall success, to decide if review is needed.
Missing checks still produce unavailable warnings; accepted exceptions remain
explained as Reviewed exception in details, without granting permissions.

Firewall/device Review opens the existing System checks (`evidence`) workflow,
where the actual condition and supported review actions live. Notification routing
admits that fixed destination. Malware readiness uses the exact File Security
ClamAV response used by Center; a real failure remains reviewable on Files & scans.
Detection history and existing notification replacement/closure remain intact.
Acceptance changes converge on the next bounded Context collection (normally
within ten seconds); no second acknowledgment store was added.

## Validation

- Fedora Context suite: 312 tests pass; route-specific notification suite: six pass.
- Rust backend suite: 47 pass, including evaluated-state/accepted-exception export.
- Frontend UX contracts: 93 pass.
- Backend Clippy with warnings denied passes using the pinned Fedora driver;
  the default Cargo subcommand initially selected an incompatible 1.99 driver.
- Installed Center 85 / Context 76 / runtime 27. Package integrity checks pass;
  protected desktop verifier reports `verified: true`.
- Actual normal desktop Files & scans shows Ready to scan / CURRENT definitions.
  System checks via the installed `evidence` route shows zero to review and 13
  protected checks. VMConnect shows the same Protected flyout with no three
  spurious provider warnings. Recorded blocked access remains informational.
- Eight real session-bus samples at two-second intervals: only Protected;
  shortest display lifetime 13.17 seconds; all three warning IDs absent.
  User Context active with zero restarts during this scoped check.

## Installed artifacts / rollback

Center RPM SHA-256:
`d6b66a679a0f554573f6403e10c4e4fbd1891e1a644049afa0584417ce4037c3`.
Context RPM SHA-256:
`7a9840d97a7ec52951535049a2b0d29aa148eb66fb32529a48c1ea525faed8e3`.
Root-only previous Center 84 / Context 75 RPMs and selected receipt are retained
under `/var/lib/greyward-development/application-security-live/plugin-parity-20261008`.
Rollback restores that matched pair and receipt, then restarts only user Context.
The compositor, account mapping, auth DMS and mandatory policies are untouched.

No authentication, mandatory access policy, DMS locking, account mappings,
network enforcement or compositor behavior is changed by this correction.
