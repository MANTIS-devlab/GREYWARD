# Enrollment ISO candidate — 10 October 2026

This is manual-test candidate evidence, not production acceptance. `.149` is the
build host only. No candidate package, policy, service or login mapping is
activated there. Fresh installation and authenticated encrypted recovery belong
on the separate empty Hyper-V test VM; the user performs installation.

**Subsequent clean-install result: FAIL.** First boot reaches broker account
preparation but revision 3 omitted the required root-owned `account-origins`
directory. The broker refuses, leaving the transaction PREPARING and login gated.
Retries reported an incomplete transaction and truncated the text log; the
persistent journal retained the original failed broker command. Installed rescue
inspection confirms the missing directory. The r3 ISO is not accepted.

Revision 4 validates private broker and origin storage before starting preparation,
checkpoints immutable prepared inputs, rejects changed inputs/mappings on
continuation, preserves bounded command diagnostics and retains first-boot logs
across retries. The rebuilt RPM contains the exact corrected coordinator. Eleven
focused lifecycle tests pass. The actual packaged runtime-34 broker in a
synthetic clean root reproduces missing-origin and non-private-store refusals
(exit 1, no enrollment),
then succeeds using revision 4's fresh-directory preparation (exit 0, one PREPARED
record and a root-owned origin receipt). This verifies the reported failure
and fix, not live kernel enforcement or an enrolled desktop.

The deliverable is a replacement ISO, not an ad hoc rescue repair. The r3 test
installation and unused repair media are retained as failure evidence. Revision
4 was built through the established workflow on the build host; the new
empty VM is `GREYWARD-ISO-ENROLLMENT-R4-20261010`. No candidate package, mapping,
policy or service is activated on `.149`. Clean installation and graphical
admission remain mandatory acceptance checks after the new build.

## Revision-3 input identity (historical)


The DMS build receipt required Fedora Python 3.14.7 while the recorded builder
supplied 3.14.8. The candidate pins the observed 3.14.8 input explicitly, retains
dependency verification, and builds unchanged upstream distribution backend
sources offline. Authentication assembly now accepts the verified revision-8
payload using the same exact source/preimage checks.

Installer enrollment previously lacked a complete installable policy/session
closure. The candidate enrollment RPM packages six compiled SELinux modules,
four bounded CIL boundaries, the verified protected compositor and the existing
authentication, administration and recovery components. RPM installation is
inert. First boot validates root-owned installer account origins and completes
preparation before login admission; it does not infer PROTECTED from preparation.
Persistent executable contexts include the protected compositor and authentication
and administration helpers. An earlier candidate missing the compositor's
persistent context is superseded by enrollment package revision 3.

| Component | Candidate |
|---|---|
| Security Center | 0.1.0-91.fc44 |
| Security Context | 0.1.0-83.fc44 |
| Application Security runtime | 0.1.0-34.fc44 |
| Installer enrollment | 0.1.0-3.fc44 |
| Session | 0.1.0-10.fc44 |
| Branding | 0.1.0-15.fc44 |
| DMS | 1.6.2-8.fc44 |

Public source base: `182650322e47c86b2140ea8d91e4d0a52233568c`, with scoped
uncommitted candidate changes. Security Center's packaged source-tree fingerprint:
`e05b7c6ddbf63862622ec29dda2742cbbf9d370d1a1d8ea9cb4b3ef1370692f6`.
Do not describe the candidate as a clean build of that base commit.

## Completed checks

- Repository static and documentation gates pass.
- 208 Rust tests pass, with 22 ignored; format and Clippy checks pass.
- 331 Security Context and 95 frontend tests pass.
- 62 image and six installer lifecycle tests pass.
- Four authentication and four protected-desktop assembly tests pass.
- DMS offline rebuild and 50 upstream tested Go packages pass.
- Enrollment package compilation and compositor tests pass. A copied SELinux
  store links all candidate modules with neverallow checking enabled; all six
  checked executable contexts survive persistent-context lookup. The active
  host policy was not changed. Linking is not live kernel enforcement evidence.

Detailed logs and input receipts are retained under
`output/pre-release-execution/release-20261010-8a5ede6/` and the corresponding
`.149` build workspace `/mnt/greyward-build/build-20261010-8a5ede6/`.

The established netinst/Anaconda `updates.img` workflow is retained, including
interactive account creation and encrypted storage, branding, first-boot handoff
and offline dependency verification. Build validation does not replace visual
installer or installed-system acceptance.

## Remaining acceptance and limitations

Clean installation, first-boot enrolled login, actual kernel coverage, protected
authentication/Administration and authenticated LUKS rescue/rollback remain
pending on the empty test VM. No installed-system pass is claimed.

Generic Flatpak protected-resource permission and first-use portal authorization
remain unimplemented. Unsupported tool grants remain unavailable. Initial
enrollment rollback refuses existing resource/grant/label state; post-use policy
rollback, upgrade migration and supported account-management enrollment remain
unfinished. This candidate is not approved for production promotion.

Existing validated artifacts are retained. Completed compiler scratch was moved
to a recorded retention directory; no user/system/recovery data was deleted.
The dedicated build disk was expanded online from 56 to 88 GiB, preserving its
partition start, filesystem identity and `.149`'s independent encrypted boot disk.

## Revision-3 built artifact (rejected after installation)

Rejected candidate: `output/iso/greyward-installer-20261010-enrollment-r3.iso`
(5,216,010,240 bytes). SHA-256:
`a232b87ae2e564a609bea394ebf77b9c741e592316a918b8a3b0ee7a20e2e9b5`.
The Windows copy matches the build hash. Its provenance sidecar records that
installer dependency resolution was tested and the installed system was not.
Extracted payload checks, production-stage validation and fresh offline Flatpak
installation of all six bundled applications pass.

The separate generation-2 VM `GREYWARD-ISO-ENROLLMENT-20261010`
(`714fbb50-c6c2-47ec-a6c9-786870d15778`) uses an empty 64 GiB test disk and this
ISO. No unattended installation, predefined user or encryption password is
provided. `.149` retains Center 89 / Context 81 / runtime 32 / session 9 /
DMS 1.6.2-6 with SELinux Enforcing.

VMConnect inspection confirms the candidate boots into Anaconda and offers its
account-creation screen. The user began configuring the installer; automation
stopped without submitting any installation or authentication decision. This
observation does not establish completed storage/encryption, branding on every
installer screen, first boot or enrolled desktop acceptance.

## Revision-4 replacement ISO

The corrected enrollment RPM is `greyward-application-enrollment-0.1.0-4.fc44`;
SHA-256 `82e57fd1eb24e7c0444612204e63ebe491218c52ec50244ec40ccce25c30ff6d`.
Its broker state directory and installer-origin storage are both created with
validated root ownership and mode 0700. The additional state-directory gap was
found in source and reproduced with the packaged broker; it was fixed before
this ISO was composed. An earlier in-progress composition was stopped and is
not a candidate. Failed build/experiment logs remain historical evidence.

The other inputs remain Center 91, Context 83, runtime 34, Session 10,
Branding 15 and DMS 1.6.2-8, against the source base and candidate modifications
recorded above. Eleven installer lifecycle and 62 image tests pass. Packaged
broker checks refuse missing origin storage and non-private broker storage, then
prepare one synthetic account with the corrected packaged coordinator. The ten
policy files are byte-identical to the previously linked r3 inputs; the private
compositor matches its packaged receipt. No live host enrollment was performed.

Built ISO: `output/iso/greyward-installer-20261010-enrollment-r4.iso`,
5,216,010,240 bytes. SHA-256:
`8f06748636a40ce0903498fcc70e82959946860bf274ab3a2125a3179d9f0fa6`.
The Windows copy matches. Offline dependency resolution, fresh installation of
six bundled Flatpaks, extracted production validation, complete payload hashes
and the Anaconda recursive-copy boundary pass. Network is not required for
installation; the provenance explicitly records `installed_system_tested: false`.

The new empty VM `GREYWARD-ISO-ENROLLMENT-R4-20261010`
(`244fc33e-6a4c-4e49-8677-ccc968afddb9`) is running this exact ISO from DVD.
Its branded GRUB menu and GREYWARD-branded Anaconda installation progress are
observed through the exact VMConnect console. No
unattended installation or account/encryption approval was performed. The failed
r3 installation is preserved. Full installation, first boot, protected graphical
admission, Administration and encrypted recovery remain pending manual
acceptance; successful image composition is not proof of installed enforcement.

### Revision-4 installed login acceptance: FAIL

The user reports completed installation but cannot log in after manually selecting
GREYWARD Labwc; the default was Hyprland (uwsm-managed). The exact test console
confirms the greeter exposes both Hyprland entries alongside GREYWARD Labwc.
The installed VM refuses SSH. Only this new test VM was approved for rescue
restart; its journal and login failure remain under investigation. No policy
relaxation or runtime change was made on .149. R4 is not accepted.

### Revision-4 rescue diagnostics (10 October)

User-supplied installed journal evidence confirms the greeter selects the
canonical launcher and desktop/session.py aborts with `Seat display unavailable`.
The copied compositor is labelled `greyward_as_display_exec_t`; the installed
`ldd` check reports no missing libraries. The bounded journal samples contain
no display-domain denial. These observations do not establish the root cause.
The detailed display worker log was transient under `/run` and lost at rescue.

Temporary diagnostic media is attached only to the r4 test VM. Its root-only
collector preserves at most 64 KiB of the fixed display-1000 log in
`/var/log/greyward-login-diagnostic/display.log`; no authentication output,
protected resources, mappings or policy are changed. Source syntax and capture,
empty-log retention, symlink/public-source refusal checks pass in a build-area
fixture on .149; this is not installed collector or compositor acceptance.
Console automated text entry failed, so guest installation remains pending.
The timer, service and helper must be removed after diagnosis. They are test-only
artifacts under the release output, excluded from the product and ISO payload.

### Revision-4 login root cause and revision-5 candidate

The user installed the diagnostic collector successfully. Its retained log
contains `PermissionError: [Errno 13] Permission denied` at `os.execve` of the
protected Labwc binary. Installed `namei` confirms three blocking mode-0700
directories: the program root, desktop and bin. The coordinator intentionally
sets umask 077, but subprocess assemblers' directory creation inherited it.
The earlier development assembly ran under a different directory-creation mask.
This is a demonstrated DAC traversal failure; no permissive or SELinux allow
change is part of the correction.

Enrollment 5 finalizes only validated root-owned immutable program directories
to 0755 before admission preparation is checkpointed. Files, context labels,
private policy/grant storage and authentication runtime are unchanged. Thirteen
lifecycle tests pass, including restrictive-umask and unsafe-input refusal.
The actual RPM's extracted coordinator matches source and reproduces denial,
then allows an unprivileged UID to read a nonsecret program fixture while its
private-state fixture remains denied. This is DAC/package validation, not
installed compositor or SELinux enforcement acceptance. The first fixture on
the development-owned build disk correctly failed root-ancestry validation;
the successful fixture uses separate root-owned disposable build-test scratch.

Enrollment RPM: `greyward-application-enrollment-0.1.0-5.fc44.x86_64`, SHA-256
`3571fecae60e7b5d32609edd3f5718d585d805654df2904fe0ebb8508360fb85`.
It has no package installation scriptlets. Center 91, Context 83, runtime 34,
Session 10, Branding 15 and DMS 1.6.2-8 are retained.

The wrong greeter default is a separate issue: pinned upstream GreeterContent
selects the first asynchronously discovered entry when no remembered session
exists; `--no-save-session` prevented use of a seeded choice. Production now
seeds upstream's memory contract with `greyward-labwc.desktop` and enables
remembered session selection while retaining `--no-save-username`. Existing
explicit choices survive refresh; the configured Hyprland fallback is not
deleted. Three actual cache-producer tests and 63 image tests pass. Installed
greeter selection remains a manual acceptance gate.

R5 composition uses the existing verified Fedora base, installer customization,
offline acquisition/Flatpak caches and ordered package inputs. No package,
policy, mapping or service is installed or activated on .149. The prior media
and evidence are retained. The user has the scoped rescue permission repair
for verifying the causal fix on the r4 test installation before fresh r5
installation acceptance. At this recording, r5 build and live login acceptance
remain pending; no working-ISO claim is made.

### Revision-5 composition and repaired-login evidence

The user confirms that the scoped rescue directory repair allows GREYWARD
Labwc login on the r4 installation. A fresh capture of the exact r4 VMConnect
console shows the DMS desktop panel and Security Center plugin. This confirms
the causal login repair; it does not validate every enforcement claim or a
fresh r5 installation. The temporary r4 diagnostic collector remains test-only
and its removal is pending.

R5 composition exited successfully. Embedded payload checks, production-stage
validation and the installer recursive-copy/hash boundary pass. All ten
packaged policy inputs are byte-identical to the previously linked policy
closure. The 5,216,010,240-byte image transferred to Windows and matches both
the build manifest and checksum receipt:

`734963d573c92ca96d7cbcffe6a4a81f02f4a4c4753365a6d3a792db9d555428`

Windows image: `output/iso/greyward-installer-20261010-enrollment-r5.iso`.
The new empty VM `GREYWARD-ISO-ENROLLMENT-R5-20261010` uses this image for
manual installation. No automatic installation or candidate activation on
.149 occurred. The source is public-mirror base
`182650322e47c86b2140ea8d91e4d0a52233568c` plus scoped uncommitted candidate
changes, not a new committed release SHA.

GO for manual clean-install testing; production acceptance remains NO-GO
until fresh r5 enrollment, login, default session selection, installed kernel
boundaries and encrypted recovery are actually exercised. Generic Flatpak
and arbitrary-script authorization is not delivered by this ISO. Existing
unsupported workflows must remain unavailable rather than imply coverage.

### R5 user acceptance and r6 display corrections

The user reports that the r5 ISO works and explicitly validates the login fix.
That is manual installation/login acceptance; it is not evidence that every
enforcement, recovery or hardware gate passed.

R6 rebuilds Center 92 and Context 84 to retain source-manifest integrity; it retains runtime 34, Session 10, Branding 15 and
DMS 1.6.2-8. Enrollment revision 6 includes the output-management commit
`8c130a662b047a33406c695d54adf524cc302d99`. Two compositor contracts pass;
the private compositor and policy package rebuild pass their checks.

The black greeter background is a renderer defect, not a missing wallpaper:
the separately packaged `dms-greeter` uses its own embedded frontend, including
a wallpaper MultiEffect shader. Qt's software scenegraph cannot render that
effect. A test of the actual embedded frontend on a private headless display,
with private runtime/config and no usable greetd or session-bus endpoint,
reproduces black under `QT_QUICK_BACKEND=software` and shows the canonical
wallpaper under Qt RHI/OpenGL with Mesa software rendering. The normal `.149`
desktop and greetd service were not changed or restarted.

The production command therefore changes only the greeter's Qt renderer;
Labwc retains Pixman, and `LIBGL_ALWAYS_SOFTWARE=1`/`QT_OPENGL=software` keep
Qt rendering on the CPU. Authentication and the embedded frontend are
unchanged. An initially built desktop-QML patch was rejected because that
frontend is not used by `dms-greeter`; it and its package artifacts are not
included in r6. Earlier tiny synthetic image captures were inconclusive and
are not used as evidence. The actual embedded frontend comparison is retained
under the release output as `grim-embedded-software.png` and
`grim-embedded-rhi.png`.

Four greeter contracts, 64 image tests and 13 enrollment lifecycle tests pass.
R6 composition/Windows hash and installed greeter/DMS display acceptance are
pending at this recording. Reuse the existing R5 VM; do not create a VM or
erase its installed disk automatically.

### R6 verified handoff

R6 composition, installer contracts, extracted payload hashes and recursive-copy checks pass. Windows SHA-256 matches: `452c8ab517c5379f50a3650eaedc6b3477939cff583e36f0178dac03b5fa122e` (5,216,010,240 bytes). The ISO is `output/iso/greyward-installer-20261010-enrollment-r6.iso`, mounted in the existing running R5 VM (545df626-71d2-426d-bb0a-bc83ab69a3f9). No new VM, VM restart, installation, disk erasure or candidate activation on .149 occurred. Rust package tests: 208 passed; Context: 331 passed; frontend contracts: 127 passed. Wider WebDriver files require their absent test dependency and were not accepted as live-window validation. Fresh R6 greeter/DMS apply and full installed security/recovery acceptance remain pending. GO for manual testing; no release publication.
