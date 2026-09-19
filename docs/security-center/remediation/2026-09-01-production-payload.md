# SECURITY_CENTER_PRODUCTION_PAYLOAD_01

Date: 2026-09-01

Status: historical production-input stage evidence. The account/first-boot and
Anaconda branding conclusions in this record are superseded by
[`2026-09-01-production-iso-pipeline.md`](2026-09-01-production-iso-pipeline.md).
The previously composed ISO remains historical and was not rebuilt here.

## Scope

This follow-up checked that the production image boundary carries the complete
Security Center payload and its non-Fedora production inputs, while keeping
the disposable Hyper-V renderer and developer overlay out of the staged
production inputs.

## Findings and root causes

### Medium

- The local production-input cache contained the pinned OpenSnitch RPM but not
  the pinned Tabby RPM. `build.sh --require-complete` would therefore refuse a
  complete image stage. The root cause was an incomplete local external-input
  cache, not a missing declaration: `environment/production/external-rpms.txt`
  already declared both files and their hashes.
- The image stager copied the complete `environment/session` Labwc subtree
  into the production stage. That subtree contains the disposable VM's
  `Virtual-1`, software-renderer, and VM autostart behavior. The production
  provisioner used separate hardware-neutral files, so the active installed
  path was not directly affected, but the image input boundary was ambiguous
  and could ship development-only material.
- The development overlay looked for Labwc and DMS below
  `/tmp/greyward-production/session/`, while the Packer factory stages those
  payloads at `/tmp/greyward-production/labwc` and
  `/tmp/greyward-production/dankmaterialshell`. A fresh factory rebuild could
  skip or fail to apply the VM overlay instead of reproducing the intended
  Alpha environment.
- Update Center was D-Bus activatable and worked on demand, but production
  provisioning did not globally enable its user unit alongside Security
  Context. This left first-login startup dependent on a later D-Bus request.

## Fixes

- Retrieved `tabby-1.0.235-linux-x64.rpm` from its declared upstream URL and
  verified SHA256 `0dd56a3c2a43547e5ae23cd87a8a205b3b91d3bf6685cd8e380c79cf1154a0c9`.
- Changed `environment/image/build.sh` to curate the production stage: it
  copies shared Labwc compositor/theme assets only, and keeps the production
  `labwc-environment` and `labwc-autostart` as the authoritative session
  inputs. VM-only files remain available to the development factory.
- Corrected the development overlay's Labwc and DMS stage paths and added
  static checks to prevent the old nested-path contract from returning.
- Globally enabled `greyward-update-center.service` wherever the production
  provisioner enables the finished user Security Context.
- Updated the production/image architecture documentation to record the
  boundary and the first-setup startup guarantee.

## Production stage validation

The following complete stage was generated with `build.sh --require-complete`:

`output/greyward-production-inputs-complete-20260901-r3`

Its manifest reports:

- `production_inputs_complete: true`;
- one branding RPM: `greyward-branding-0.1.0-7`;
- both Security Center RPMs: center `-45`, context `-44`;
- both pinned external RPMs: OpenSnitch `1.8.0-1` and Tabby `1.0.235`;
- no staged `labwc/environment` or `labwc/autostart` VM files.

The stage contains the production provisioner, first-boot finalizer,
acceptance gate, session/DMS/Labwc assets, Flatpak definitions and portals,
branding, DMS patches, external RPMs, and both Security Center packages.

## Alpha runtime validation

On `GREYWARD-DEV`, reached through the managed development alias after the Security Center RPM deployment,
and the final provisioning alignment:

- `tools/greyward-dev/health.ps1` returned `RESULT: HEALTHY`;
- `greyward-security-center-0.1.0-45`,
  `greyward-security-context-0.1.0-44`, branding `-7`, OpenSnitch, and
  `/opt/Tabby/tabby` were present;
- greetd, firewalld, NetworkManager, resolved, OpenSnitch, USBGuard, ClamAV,
  Secure DNS, DNF5 daemon, and all GREYWARD provider units were active;
- DMS, Security Context, and Update Center were enabled and active for the
  user session;
- Update Center returned only `DNF5`, `Flatpak`, `freshclam/ClamAV`, and
  `fwupd`, all `AVAILABLE`; `rpm-ostree` was correctly omitted on Fedora;
- the installed posture diagnostic returned `PROTECTED` with 12 protected
  checks, no review-needed findings, and one optional firmware-HSI limitation;
- the installed D-Bus Security Context exposed the scan, detection,
  quarantine/restore/delete, network, privacy, USB, telemetry, history,
  export, recovery, and Safe Open methods.

## Automated validation

- Security Context Python suite: **116 tests passed**, 22 environment-gated
  skips.
- Frontend UX contract: **60 passed**, 0 failed.
- Real Tauri interaction suite: one environment-gated skip because no
  WebDriver endpoint was configured in this host invocation.
- Fedora guest Rust workspace tests during the canonical deployment:
  **27 passed**, 0 failed.
- `tests/static.ps1`: passed.
- `tools/validate-repository.ps1`: passed.
- Shell syntax checks for the production, image, account-handoff, and
  development-overlay scripts: passed.
- `git diff --check`: passed.

## Internal Alpha ISO composition

Using the Fedora Everything netinst base on `GREYWARD-DEV` at
the managed GREYWARD-DEV alias, `environment/image/build-iso.sh` completed the real
Lorax/livemedia-creator and Anaconda image path after the Labwc stage contract
was corrected. The resulting internal artifact is:

`output/greyward-alpha-composed-20260901.iso`

- size: 4,348,116,992 bytes;
- SHA256: `ebdaaf00e7d82c09211e02db637ef8dcf2e77974ca5ef399a0c2a6d8f080c399`;
- ISO9660 with El Torito boot records and MBR/GPT boot metadata;
- EFI and BIOS GRUB both default to the normal live boot entry rather than the
  media test entry;
- the embedded LiveOS squashfs contains GDM/Initial Setup, greetd, the account
  handoff, production Labwc assets, Tabby, OpenSnitch, and the Security Center
  binaries/context payload.

The local copy's SHA256 was compared with the Alpha-produced hash. This proves
composition and payload presence, not yet a clean-machine boot/install/user
creation/reboot acceptance cycle.

## Remaining limitations

The artifact is an internal Alpha ISO, not a release artifact. A fresh
Anaconda install, first-user creation, account hand-off, reboot, and post-reboot
production acceptance were not rerun in this pass.
The Alpha VM intentionally contains the development overlay and therefore is
runtime evidence for the installed Security Center and integration services,
not proof that the clean production image contains no developer artifacts.
Physical USB hardware, firmware HSI capability, and hardware-specific Labwc
rendering remain unavailable on this VM.

## Observed first-reboot defect

During manual testing of the composed ISO in `GREYWARD-ISO-TEST-20260901`,
the first reboot was reported to leave GNOME Initial Setup displaying an
`Initializing...` loop. At that point the initial account/setup process should
already have completed and the installed system should transition to the
production greetd → DMS Greeter → Labwc path. This is recorded as a blocking
post-installation workflow defect; it is not considered fixed by the ISO's
successful composition or by the presence of the account-handoff service.

Required follow-up is to capture the first-boot journal and unit state, then
trace the Initial Setup process, account-handoff path unit/service, display
manager selection, and first-login completion marker across the reboot before
changing the handoff logic.

The same manual run also observed that the temporary default `greyward` user,
created for the onboarding session, was still present after the real user was
created. This is a separate high-severity handoff defect: the bootstrap
identity must be removed or otherwise provably retired before the installed
system is considered complete. Follow-up must verify the account list,
ownership of the live-session home, sudo/PAM entries, AccountsService records,
and the handoff completion marker after reboot.

The post-install test also reported that Security Center did not match the
known-good Alpha development VM: it displayed `GREYWARD Security — Unavailable`
with security providers unavailable, and the installed Security Center was
several revisions behind the development version. This is a high-severity
production-payload/coherence defect. The release package set, installed RPM
versions, user/system service activation, D-Bus provider ownership, and
post-handoff readback must be compared before the ISO can be considered a
functional mirror of the development baseline. A plausible UI state is not
accepted as evidence until the provider services report their authoritative
readiness.
