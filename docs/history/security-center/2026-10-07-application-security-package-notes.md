# Historical experimental package notes

Status: HISTORICAL. Superseded README captured during the 7 October source
audit. Its chronological present-tense statements describe different source
revisions, not current package guarantees. Use the
[current plan](../../security-center/APPLICATION_SECURITY_PLAN.md).

# Application Security experimental package

Current source is revision 14. It adds the shared ELF/script/Type-2 AppImage
runner, private graphical Labwc/clipboard support and packaged pinned Wayland
security-context helper. Center/Context source supplies the matching typed GUI
registration, reviewed READ grant and reference-based revocation workflows.
Up to sixteen concurrent verified READ grants are retained; WRITE/timed access
is unavailable. The existing telemetry/publisher receives bounded root audit
denials, with UNKNOWN attribution and explicit truncation. Safe Open has no
standalone fallback; native handlers use the shared runner and configured
Flatpak handlers remain explicitly unavailable.

The archived revision-13 RPM below is historical. Revision 14 has not been
built/promoted as a production package. Installed Center 59 / Context 64 /
DMS v1.6.2-6 remain unchanged. Functional source validation uses the separate
enrolled UID-1002 account only. Public enrollment and coverage are not claimed;
extended test/performance/image matrices are DEFERRED HARDENING. Current
functional evidence is in the approved plan.

Source work after the archived revision-12 receipt now includes schema-three
descriptor label journals and a generation-bound reviewed kernel read-grant
provider. The fixed separate-account critical sequence passes actual
registration, deny/allow/revoke, private PAM/DMS/Labwc/Flatpak and rollback.
This does not retroactively change that package receipt. Revision-13 source adds
the Guard CLI and a separate explicitly started development workflow whose real
bus registration/native RPM launch/revocation sequence passes. The default
broker's mutations and production enrollment remain unactivated. Revision 13
now builds offline with ordinary package suites, root ownership and packaged
missing-provider/unprepared-worker refusal checks passing. Its receipt is in
the approved plan; it has not been installed or enrolled as production protection.
Additional cache/reproducibility and
release matrices are DEFERRED HARDENING under the active plan.

Authority: [approved plan](../../security-center/APPLICATION_SECURITY_PLAN.md).
This package is not a production protection implementation. Its default system
bus exposes only `ListApplications`, `GetApplication`, `GetCoverage`,
`ListProtectedResources`, `GetProtectedResource` and
introspection. Revision-13 source also packages
`greyward-application-security-development` and `greyward-guard`, using the
separate `systems.mantis.greyward.ApplicationSecurityDevelopment1` name. Its
fixed enrolled UID 1002 provider supports descriptor registration, persistent
read grant review, immutable reviewed launch and revocation after
fresh owner authentication. It is started explicitly, with no automatic service
activation or enrollment. It is excluded from current image composition.

The package also contains `greyward-native-worker`. The experimental
`greyward-guard --development run -- FILE [ARGS]` path uses a held ordinary ELF
selection, immutable root copy, disposable home, private PID/user/network/mount
namespaces and verified Landlock/seccomp readiness before exec. It has no host
display or session bus, no network and no Protected Data grant. Graphical,
AppImage/script and Safe Open integration are still implementation work.

Reviewed tools use `greyward-guard --development grant review /usr/EXEC
RESOURCE_REF`, followed by `run --grant GRANT_REF -- /usr/EXEC [ARGS]`.
Registration uses `resource register DIR`; revocation uses `grant revoke
GRANT_REF /usr/EXEC`. Each policy mutation displays its review and requires fresh
owner authentication. The CLI does not activate policy/enrollment prerequisites;
the separate-account test tooling owns that reversible development setup.

Reads use the kernel-bound bus sender and its UID. Inventory and provenance do
not establish protection; collection/coverage remain UNKNOWN. The production
storage location is fixed, root-owned and private. Corrupt or unsafe storage
stops the service rather than creating a fallback inventory.

### Historical foundation receipts

The paragraphs below describe the archived pre-workflow foundation. The current
development workflow above supersedes its missing mutation/launch statements;
the recorded package receipts remain historical.

The source schema-two migration preserves inventory and its revision while
adding resource/grant intention tables in the same policy database. Opaque
descriptor-bound reviews require fresh owner authentication and exact
peer/revision/generation revalidation before a transaction. These library
intentions remain UNKNOWN/pending; this package's bus has no mutation methods,
label installer, active grants or production protection claim. Startup rejects
corrupt records instead of inferring protection from persisted metadata.

The source's deterministic resource-denial compiler is restricted to the
separate development subject. Its synthetic label/alias/held-descriptor checks
pass, but it installs no production policy or resource labels and exposes no
protection claim. This compiler and schema-two source are outside the archived
revision-12 package receipt; rebuilding alone would not complete those gates.

Live type-policy readback additionally checks the actual SELinux filesystem,
enforcing/per-domain flags and kernel sequence. Absence and actual module
removal invalidate its private receipt. Object labels and session membership
remain separate requirements; this adds no method to the experimental bus.

Freshly authorized source commits retain an opaque directory lease through root
preparation; removal or revision/object/actor changes invalidate it. The fixed
critical provider now verifies descriptor label application and schema-three
journaling with real fresh authentication. These source additions are outside
the archived revision-12 package receipt and do not activate production labels.

Historical revision-13 launch boundary (now included in revision-14 source):
It adds a root-owned empty `greyward-guard-entry` mount target. Direct execution
fails; the reviewed launch library mounts the still-held immutable generation
there only inside its generated unit. Unit context, UID, environment and limits
are fixed by root preparation. This development provider remains UID-1002-only,
disconnected/headless and outside public mutation/launch dispatch. It creates no
whole-session protection badge. Release/cache matrices remain DEFERRED HARDENING.

`ListApplications(u limit, b has_revision, t expected_revision, s after)`
returns a JSON projection. Limit is 1–100. An empty cursor starts a page; later
pages require the returned revision and opaque installation cursor.
`GetApplication(s installation_ref)` returns the caller's matching record or
null for both foreign and missing records. `GetCoverage()` currently returns
unknown enforcement. All responses use `greyward.application-security/v1`.
Resource reads use the same bounded revision/cursor contract with resource
references and policy revisions. They disclose only owned metadata, never
object IDs/private paths, and reject any stored Protected coverage claim.

The library's bounded metadata catalogue and installed-RPM content checks are
internal groundwork. They are not connected to inventory population, protected
resource registration or launch APIs. The source requires held,
root-owned ancestry and matching path membership for installed RPM evidence.
Symlinks/mount aliases and changed ancestors invalidate that evidence. It
remains an experimental read broker; coherent content does not authorize grants.
The internal one-executable collector uses a fixed RPM query, clean environment,
bounded pipes and one shared metadata/content deadline. Full native inventory
and approved-source verification are still absent. Filesystem verification
requires an independent worker deadline; this collector is not a launch worker.
The internal Flatpak intake preserves owner/provider scope, partial observations
and generation/revision transactions. Its provenance remains UNKNOWN and it is
not connected to a production population API. Shared provider cleanup caps
running/retained children at 32; one background reaper holds unreaped identities
and admission slots without blocking request cleanup on a killed child. This
uses four fixed startup workers and at most eight outstanding jobs, including
queued or stalled work after caller timeout. Expired queued requests never
start; saturation fails explicitly. This bounds caller waits even when provider
spawn blocks before a child exists. It does not cancel kernel-stalled work or
bound the separate descriptor/content filesystem verifier, and does not contain
hostile code that escapes a process group. Independent launch workers remain
required. Overload produces provider failure, not a successful empty inventory.
Inventory/coverage wire types are shared with the domain and validated source
Context/Tauri read boundary. Center/Context packages and production providers
are separate, still-open gates; this RPM does not install their source changes.

The callback rejects extra fields, deadlines, stale revisions and oversized
projections. Admission allows eight valid requests per connection per second
and 32 globally, with bounded sender state. This is not a libdbus ingress memory
limit; the unit separately bounds memory to 128 MiB. Overload must not be
interpreted as protection success. Production denial-burst/performance gates
are still required.

Build the spec in an unprivileged isolated Fedora builder with the exact lock
and pre-acquired dependency cache. Both build and check use `--locked --offline`;
the spec invokes `/usr/bin/cargo` and fixes `PATH=/usr/bin:/bin`,
`RUSTC=/usr/bin/rustc` and `RUSTDOC=/usr/bin/rustdoc`. Record those versions,
not just installed RPMs. Cargo may search its home for external commands before
PATH: invoke `/usr/bin/cargo-fmt fmt` and `/usr/bin/cargo-clippy clippy` directly
for validation, with `CARGO=/usr/bin/cargo`. Missing dependencies fail.
No RPM scriptlet enables the experimental service or
changes SELinux mappings/labels. The fixed Polkit actions use fresh owner/admin
authentication and are not yet connected to public mutation operations.

The fixed development builder `tools/greyward-dev/build-application-security-experimental.sh`
creates a cold, offline build with receipts. Its `--warm` mode rebuilds the
same archived input/spec against that build's private Cargo cache, compares
extracted binaries and restores the original validated RPM path. It does not
install either artifact or claim reproducible RPM headers. Revision 11 passes
this check: cold build/check 4 min 16.666 s, warm build/check 11.719 s and an
identical broker binary. Center/Context cold/warm and release budgets remain
separate open gates. The detailed receipts are in the approved plan.

The read transport test uses an in-memory synthetic registry and a temporary
bus policy in a bounded root transient unit. It never creates the production
database. Build the test as the ordinary builder and copy its executable into
root-owned libexec before running its exact root test. Do not run Cargo as root.
Remove the temporary policy and reload bus configuration afterward; no bus or
desktop restart is needed. See [probe instructions](../../../spikes/application-security/README.md).

Current revision-12 source additionally includes pure policy preparation and
`native_restrictions.rs`. It still installs only the read broker, not the
fixed native integration example or a general launch service. Landlock and
libseccomp inputs are pinned in Cargo.lock; `pkgconfig(libseccomp)` is an
explicit build requirement. No package scriptlet activates confinement or
changes account mappings. The current build must be checked separately from
the archived revision-11 cache receipt above. Warm builds additionally verify
the copied spec digest, and new receipts include the libseccomp runtime/headers.
