# Repository consolidation and ISO preparation — 10 October 2026

Status: **SOURCE CONSOLIDATION; ISO BUILD NO-GO**. This is dated preparation
evidence, not clean-install acceptance or production enrollment approval.
No ISO, release tag, installed package, live policy, service, grant, snapshot or
desktop lifecycle was changed during this task. SSH and SELinux Enforcing remain
available. Local compiler/test dependencies were installed only in the authoring
WSL environment.

## Repository and publication boundary

The engineering baseline is `codex/dms-1.6-migration` at
`d800c6ce73ed900f544b80d6d04bb3bd5f791da9`, initially 492 working-tree entries
and no staged files or remote. That private history must not be pushed.
The existing public checkout uses `main` and
`https://github.com/MANTIS-devlab/GREYWARD.git`. Its initial HEAD was `c65623d`;
a clean fast-forward preserved four upstream commits through `2c1315f`.
There was no local/remote history divergence. Public-only screenshots and release
records are preserved; the existing download link is retained.

An initial byte comparison identified 398 differing/new publication candidates
across Security Center/Context, experimental Application Security, session and
policy sources, branding, developer probes and their documentation. No public
file deletion was proposed. Private attachments, credentials, generated builds,
packages, databases and ISO outputs are excluded. Publication copies of dated
receipts redact private account identifiers; engineering receipts remain intact.
Dev helpers now derive the home or require an explicit recovery account instead
of embedding the operator's account. Legacy forbidden-account checks in static
tests are negative fixtures, not installed credentials. RFC1918 addresses in
country-display tests are synthetic fixtures.

Final commit/push evidence and remaining source-validation outcomes are recorded
in the completion section below. Never infer GitHub synchronization from a local
commit. The [publication authority](../../PUBLICATION.md) remains canonical.

## Security and package coherence

| Area | Source truth and release treatment |
|---|---|
| ClamAV status | Root cause: confined metadata failures appeared as missing definitions, while an active updater implied initialization. The existing trusted scanner service now supplies bounded, fresh, read-only metadata; unavailable/error stays unavailable/error. Service activity alone proves neither updating nor real-time protection. Implemented, not deployed or live-validated in this task. |
| Security claims | Accepted limitations retain measured check states. VPN tunnel/DNS-route observations do not prove encryption, leaks or kill switch. Portal/deputy isolation is explicitly unverified. A baseline badge is not a universal no-bypass claim. |
| Grants | Descriptor-bound registration and the tested restricted key-inspection provider exist in development. Arbitrary IDE/script/Flatpak raw-resource Allow/Deny is not delivered. Historical AVCs cannot authorize a recipient. |
| D-Bus correction | Explicit unpackaged development inspection-denial overlay. Earlier bounded kernel/probe evidence is historical; origin association and the hybrid Flatpak gates remain blocked. Excluded from the production image; not silently promoted. |
| Administration | Protected terminal/authentication/domain separation remains authoritative. The visual overlay is source, not a rebuilt installed RPM. No session or authentication experiment was run here. |
| Enrollment and recovery | Experimental runtime is excluded from image inputs. Automatic production admission, full desktop rollback and authenticated installed LUKS rescue remain release gates. Do not copy development login mappings, SSH access or policy state into an ISO. |

The detailed ClamAV before/after behavior and pending live checks remain in the
[truthfulness receipt](../security-center/2026-10-09-security-truthfulness.md).
Ship matched Center and Context: an older strict Center decoder must not consume
the expanded new Context metadata. No database migration is introduced.

| Component | Installed development evidence | Next source candidate, not built |
|---|---|---|
| DMS | 1.6.2-6 | 1.6.2-7; changed first-party plugins need a distinct identity |
| Session | 0.1.0-8 | 0.1.0-8 |
| Branding | 0.1.0-15 | 0.1.0-15 |
| Security Center | 0.1.0-89 | 0.1.0-90 |
| Security Context | 0.1.0-81 | 0.1.0-82 |
| Application Security experimental | 0.1.0-32 plus explicit overlays | 0.1.0-33, excluded from image |

Read-only runtime checks also record Quickshell 0.3.1-5, Labwc 0.9.6-1, UWSM
0.24.3-1, DMS Greeter 1.6.2-1, Flatpak 1.18.4-1 and SELinux policy 44.11-1
on Fedora 44. The DMS manifest pins the shell/backend and compatibility tuple;
`versions.json` points to it. Rust source CI is pinned to the observed Fedora
1.98.1 toolchain rather than drifting to new unrelated lints. These versions are
development evidence, not an accepted clean-install tuple.

## Validation and corrections

- Repository static/documentation and branding checks pass before consolidation.
- Context: 331 tests, 302 passed and 29 skipped. Frontend: 141 tests, 138 passed
  and three actual-window tests skipped. Skips are not runtime acceptance.
- Repository Python: 129 tests, 119 passed and ten skipped after correcting the
  Administration unit fixture to use synthetic immutable tool generations.
  Its former hardcoded Fedora helper path failed on Ubuntu. Real PAM is unchanged.
- Domain/backend Rust tests pass (84 passed, one host test ignored).
- The initial unrestricted workspace run fails when Ubuntu/AppArmor cannot
  supply the real SELinux execution context required by a broker fixture.
  Source CI explicitly excludes ten context-dependent checks and one
  installed-Fedora-RPM identity control; their tests
  remain intact and mandatory on Fedora. No fake SELinux identity is introduced.
- Six TE modules compile locally against copied Fedora 44.11 development
  headers: administration, session, authentication, display, grants and metadata.
  No module was installed. Header duplicate-interface warnings are recorded as
  upstream development-header noise, not evidence of policy linking.
- Compilation found a genuine grants-source error: Fedora NSS/NetLabel/kernel
  state interfaces accept concrete types, not the shared tool attribute.
  Their memberships now belong to the broker-generated concrete grant context.
  This expresses the intended interfaces; it adds no resource permission or
  ordinary-to-grant transition. Full policy linking and live readback of this
  candidate remain required. The development CIL deny overlays require the
  compatible Fedora compiler; their new full-link validation is pending.
  Retention accepts only exact old/new generated context schemas, rejecting
  injected allow rules and arbitrary memberships; the regression test passes.
- CI now installs the runtime's libseccomp development dependency. Current-tree
  secrets/artifact review excludes attached images and raw runtime evidence.

No Fedora real-window, clean-image, physical-device, suspend, lock, enrollment,
grant or recovery acceptance was rerun. Those claims must not be inferred from
local unit tests. Broader edge/performance matrices remain DEFERRED HARDENING;
mandatory enrollment/authorization/rollback gates do not.

## Read-only storage assessment

Measurements are rounded GiB, 10 October. The VM root and home share the same
61.40 GiB Btrfs/LUKS device: 54.18 GiB used, 5.10 GiB available, virtually no
unallocated device space. Three recovery snapshots remain present. Directory
apparent sizes overlap Btrfs extents and cannot be summed as reclaimable space.
Measured consumers: 20 GiB application-security build tree, 43 GiB development
cache (39 GiB package Cargo target and 3.9 GiB another Cargo target), 1.6 GiB
root Go cache, and 368 MiB package/system cache. No container directory or
separate `/srv` build volume was present. `/tmp` is a 3.9 GiB tmpfs, not disk
headroom. Nothing was cleaned.

The build script refuses less than 40 GiB free at source/work/output locations.
That is a floor, not a demonstrated worst-case budget. Existing host installer
ISOs measure 4.63–4.82 GiB and the pinned Fedora base 1.13 GiB.

| Peak consumer | Planning allowance, GiB | Basis / uncertainty |
|---|---:|---|
| Verified downloads and RPM/Flatpak closure | 8–15 | Exact future closure is not solved yet |
| Extracted installer/root/staging trees | 8–15 | Multiple full copies; not a single ISO-size budget |
| Cold component build targets and overlays | 15–30 | Current development targets demonstrate substantial compiler storage |
| Intermediate/compressed images and final ISO | 10–15 | Two to three copies near observed 4.7 GiB media |
| Temporary acquisition/validation/logs | 3–5 | Retained failure trees can increase this |
| Safety reserve | 20 | Separate from the provisional 44–80 GiB peak |

Reserve at least **100 GiB actually free** on the dedicated Linux workspace and
its backing host volume; recalculate after exact closure/build receipts exist.
This is a conservative planning envelope, not a measured clean-build peak.

| Candidate location | Measured free | Peak + reserve target | Decision |
|---|---:|---:|---|
| Development VM root/home | 5.10 | Up to 80 + 20 | NO-GO; active remote LUKS desktop |
| Existing WSL filesystem | 899 virtual | Up to 80 + 20 | NO-GO as-is: sparse virtual capacity is not backing-volume free space; Ubuntu is not the canonical Fedora builder |
| Host C volume | About 72 before local compiler-cache growth | Up to 80 + 20 | NO-GO for preferred cold-build envelope; remeasure backing capacity |
| Host D volume | 65.14 | Up to 80 + 20 | NO-GO for preferred cold-build envelope |
| Host F volume | 152.92 | Up to 80 + 20 | Capacity suitable, conditional on a dedicated Fedora Linux filesystem/host; do not compose on a Windows-mounted source tree |

Recommended: a separately provisioned Fedora 44 builder with a Linux work volume
backed by host F or another host with at least 100 GiB genuinely free. Builder
creation/storage allocation is a future action, not performed here. Leave the
existing remote development VM, recovery snapshots and previous ISOs intact.

## Exact future sequence — not executed

1. Resolve pending source/package and mandatory production-scope gates. Decide
   explicitly whether the candidate is a conventional internal alpha with the
   experimental runtime excluded; it cannot promise production Protected Data.
   Validate the matched truthfulness tuple in an authorized separate Fedora
   package/session environment. Do not restart the active development desktop.
2. Provision the separate Fedora builder, record actual filesystem/backing free
   space, source commit and complete input inventory. Use the existing
   [quickstart](../../architecture/ISO_REBUILD_QUICKSTART.md) and
   [installer contract](../../architecture/ISO_INSTALLER_COMPATIBILITY.md).
3. Verify the Fedora Everything 44-1.7 base against `versions.json` SHA-256
   `bd285201494dd0ba09b54d05ac707de1401668b8512a573edb5922dcf9d7067e` and
   verified upstream DMS source/vendor archives against the release manifest.
   Review a portable baseline, not a copy of the VM filesystem/private policy.
4. Run `environment/image/build-components.py --output /srv/greyward-build/components
   --dms-inputs /srv/greyward-build/inputs/dms` in that builder. Read its selected
   receipts; select exactly one DMS 1.6.2-7, session 0.1.0-8, branding 0.1.0-15,
   Center 0.1.0-90 and Context 0.1.0-82 RPM. Record actual NEVRA/digests and the
   security build manifest; never select by an ambiguous glob. Experimental
   runtime 33 and the D-Bus overlay are excluded. A changed input/toolchain must
   not reuse an already claimed package identity.
5. Resolve/pin OpenSnitch and all RPM/Flatpak refs through the canonical offline
   closure. Use the reviewed acquisition cache and explicit Flatpak seed receipt
   when needed. A new solve/deployment still verifies cached content.
6. After separate ISO-build authorization, run this existing command, with each
   variable an exact verified immutable input path, and a new output filename:

   ```bash
   GREYWARD_ISO_WORK_ROOT=/srv/greyward-build \
   GREYWARD_ACQUISITION_CACHE=/srv/greyward-build/acquisition \
   bash environment/image/build-iso.sh \
     --base-iso "$FEDORA_ISO" --base-sha256 "$VERIFIED_BASE_SHA256" \
     --baseline "$PORTABLE_BASELINE" \
     --branding-rpm "$BRANDING_RPM" --dms-rpm "$DMS_RPM" \
     --session-rpm "$SESSION_RPM" \
     --security-rpm "$CENTER_RPM" --security-rpm "$CONTEXT_RPM" \
     --security-build-manifest "$SECURITY_MANIFEST" \
     --production-rpm "$OPENSNITCH_RPM" \
     --output /srv/greyward-build/output/greyward-installer-20261010-candidate.iso
   ```

7. Verify output checksum, provenance sidecars, volume ID and embedded
   `production/payload.sha256`. Extract the actual production payload and run
   `environment/image/validate-production-stage.sh` and the existing ISO artifact
   validator. Assert development access/accounts/overlays are absent. Inspect
   the Anaconda updates image and product Kickstart; no answer media or preseeded
   account/encryption may replace intentional installer interactions.
8. Install that exact ISO into a **new separate test VM**, using interactive
   account creation, expected storage/LUKS and branding. Verify first-boot
   completion and networkless closure, then the normal installed network.
   Verify SELinux Enforcing, normal RPM/Flatpak launches, truthful unavailable
   Application Security state when excluded, scanning/status, updates and DNS.
9. Explicitly inspect both historical regressions: greetd must visibly show the
   GREYWARD background and the new account must receive the canonical wallpaper.
   Source uses the packaged black-art JPG, skel/default wallpaper paths and the
   persistent greeter override producer; required files and tests exist, but
   source/path checks do not prove an actual clean installed background.
10. Remove installer media and validate reboot/login/recovery **only on the new
    test target with its unlock path arranged**. Never use the active remote VM
    for this. Record installer, account, encryption/storage, handoff, backgrounds,
    desktop/status/network results individually as PASS/FAIL/NOT RUN. An ISO
    compose alone is not acceptance. Retain previous media/package receipts.

## Rollback and final decision

This task needs no runtime rollback because it deploys nothing. Source changes
are scoped; private engineering history and existing public history are retained.
Future deployment must back up matched old Center/Context/runtime packages and
the scanner read policy, keep grants/labels/enrollment/detection history intact,
and explicitly authorize activation. Whole-desktop rollback and authenticated
LUKS rescue are still unvalidated production gates, not current guarantees.

**NO-GO to build now:** no exact new built/validated package input set, no approved
adequately provisioned Fedora build volume, pending full policy/live truthfulness
validation and clean-install acceptance. **No public release/tag is authorized.**

## Completion evidence

Final portable Rust workspace: **197 passed, 22 ignored, eleven explicitly
filtered Fedora-dependent checks, no failures**, including Tauri tests. This run
used local Rust 1.99; the matched Fedora 1.98.1 workspace Clippy gate also passes
with `-D warnings`. Six existing warnings in the vendored Tao dependency remain
upstream/capped dependency warnings, not a clean vendor warning claim.
Formatting, Python/frontend suites, both repository gates and publication-copy
gates pass. Staged whitespace checks preserve upstream unified-patch context
through scoped attributes. No installed Fedora or CIL full-link pass is claimed.

The reviewed public candidate contains 411 changed files; 412 inventoried paths
include the preserved, unchanged public README. The binary change is the 9,037-byte
canonical Security Center icon; other changes are source/documentation/configuration.
Private account names are redacted in 19 publication documents. Pattern scanning
found no private key, token, operator path or private VM identity in the candidate;
the existing static-test forbidden-account marker is an intentional negative
fixture. This is bounded publication review, not a repository security certification.

**PUBLICATION BLOCKED — configured commit-signing authentication failed.**
Git could not decrypt/unlock the existing SSH signing key and reported
`incorrect passphrase supplied to decrypt private key`, followed by
`fatal: failed to write commit object`. No new commit was created and no push was
attempted. Signing was not disabled and no key/configuration was modified.
The 411 reviewed changes remain staged in the existing public checkout.
Its HEAD and verified remote `main` remain
`2c1315f4b4f9c012eeb5c85378029f599b64408b`; the new source is **not on GitHub**.
Read access to the remote worked; write authentication was not exercised.
Fifteen pre-existing untracked screenshots/release sidecars remain untouched.
The private engineering working tree remains preserved and uncommitted (493 final working-tree entries versus 492 at entry).

Resume only after the configured signing key/agent is unlocked. Recheck staged
content and remote HEAD, make logical signed commits, normal-push the existing
branch and verify remote hashes. Stop again on divergence, conflicts or failed
authentication. Do not force-push or disable signing to bypass this blocker.
