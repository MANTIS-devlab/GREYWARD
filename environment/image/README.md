# Future GREYWARD image boundary

Before creating or testing an ISO, read the mandatory [ISO creation and
installation runbook](../../docs/architecture/ISO_CREATION.md). It contains
the canonical recipe and the historical failure-prevention ledger.

This directory contains the production staging entry point and the internal
alpha installer entry point. `build.sh` prepares the production payload layout
consumed by `environment/production/provision.sh`; `build-iso.sh` embeds that
payload in an installable ISO and finalizes it on the installed root before
any normal graphical session. It is not a release builder.

From a Fedora-like build host, prepare a new input directory with:

```bash
environment/image/build.sh --output output/greyward-production-inputs \
  --branding-rpm output/branding-current/greyward-branding-*.rpm \
  --security-rpm path/to/greyward-security-center-*.rpm \
  --security-rpm path/to/greyward-security-context-*.rpm \
  --security-build-manifest path/to/security-center-build-manifest.tsv \
  --require-complete
```

The RPM arguments are optional for source inspection. With
`--require-complete`, the command requires exactly one RPM of each required
package. It refuses to overwrite an existing output and records whether the
source checkout was dirty. The internal alpha image builder
consumes this staged directory and the production Kickstart, then runs the
separate production acceptance contract; it must not call the development
overlay.

The ISO composer additionally requires `--baseline FILE` captured with
`tools/greyward-dev/capture-image-baseline.ps1` and `--base-sha256` from verified
Fedora media. `baseline.py` applies portable preferences to staging and verifies
RPM version floors and selected Flatpak commits at first boot. Configuration
source drift is rejected. The ISO is published only after extracted-payload
checksum validation, with SHA-256 and provenance sidecars. Follow
[`ISO_CREATION.md`](../../docs/architecture/ISO_CREATION.md) for the complete recipe
and the explicit limits of the `.149` state import.

The stager also emits `artifacts/` with package, COPR, Flatpak, and
license/SBOM inventory records. Source staging marks resolved values as
`UNRESOLVED_AT_IMAGE_BUILD`; exact package NEVRAs, COPR build identifiers,
Flatpak refs/commits, and installed-image licensing are recorded by the Fedora
provisioning step from the image being built. An unresolved source stage is for
inspection only, not a release artifact.

When image work begins, the builder must consume:

1. `../production/manifest.json` as the system contract;
2. `../production/` plus its staged RPM inputs as the installed-system
   provisioner;
3. `installer.ks.tmpl` as the encrypted-root installation base for the
   standard Anaconda/Kickstart path; and
4. `../../branding/` plus the repository-owned production payloads staged by
   the provisioner.

`installer.ks.tmpl` is the single installation workflow. It leaves root and
normal-account creation to the visible Anaconda account page, copies the
production stage, primes the target initramfs with the GREYWARD Plymouth
branding before the first reboot, installs only the retryable first-boot gate,
and requests the standard post-install reboot. Network-dependent DNF, DMS, and
Flatpak work is finalized by the canonical provisioner after the first boot and
before greetd is released. No production DNF or systemd-dependent work runs in
the Anaconda target chroot.
There is no live root, GDM autologin, temporary `greyward-live` account, or
account-handoff service in the installer media.

The first-boot service masks both system and GNOME user Initial Setup units on
the installed target, runs the canonical provisioner, verifies the installed
contract, writes the completion marker, and only then removes the greetd gate.
If provisioning fails, the marker and stage remain and greetd stays gated so a
later systemd retry cannot expose a half-configured desktop. GDM and the GNOME
Wayland session are excluded from the installed target; the supported login
boundary is greetd → DMS Greeter → Labwc.

The existing `../greyward.pkr.hcl` remains a disposable Hyper-V factory for
`GREYWARD-DEV`: it deliberately adds `../development/` after production and
must not become the production image definition. A future image builder may
share its staging conventions, but must not include the development Kickstart,
developer credentials, SSH access, passwordless sudo, Hyper-V agents, or
developer toolchain.

The source `environment/session/labwc` directory contains the VM-only Labwc
environment/autostart variant used by that factory. `build.sh` stages only its
shared compositor definition, theme, and icons into the production payload;
the production `labwc-environment` and `labwc-autostart` files remain the
authoritative session inputs. The production payload also includes the small
`greyward-start-labwc` launcher, which applies the Pixman workaround only for
known unsupported virtual/no-render-node graphics; it does not ship the
development VM's Virtual-1 setup or
globally disable hardware rendering.

Release signing and hardware certification remain separate from internal
ISO validation. Every candidate still requires a clean offline install test.

## Internal alpha installer ISO

On a Fedora build host with `mkksiso`, `rpm2cpio`, `cpio`, and the required RPM
inputs, build the two Security Center RPMs first with the development
component builder, then run:

```bash
environment/image/build-iso.sh \
  --base-iso cache/iso/Fedora-Everything-netinst-x86_64-44-1.7.iso \
  --output output/greyward-alpha-installer.iso \
  --baseline output/iso-baselines/greyward-149-YYYYMMDD.json \
  --base-sha256 "$verified_vendor_sha256" \
  --branding-rpm output/branding-current/greyward-branding-*.rpm \
  --security-rpm output/security-center-current/greyward-security-center-*.rpm \
  --security-rpm output/security-center-current/greyward-security-context-*.rpm \
  --security-build-manifest output/security-center-current/security-center-build-manifest.tsv \
  --production-rpm cache/packages/opensnitch-1.8.0-1.x86_64.rpm
```

Place the checkout, `GREYWARD_ISO_WORK_ROOT`, and output on Linux filesystems
with at least 40 GiB free for downloads, dependency validation and composition.
The offline helper needs noninteractive sudo for isolated DNF roots and network
namespaces. See the canonical runbook for build prerequisites.

The resulting ISO is a minimally customized Fedora Everything/netinst image.
Its default boot entry is labelled `Install GREYWARD OS` and starts the
unmodified graphical Fedora Anaconda setup directly. The base Fedora profile
keeps the account pages visible; it must not be replaced by the Fedora
Workstation profile because GREYWARD does not ship GNOME Initial Setup. The
builder adds only the GREYWARD GTK profile, stylesheet, and logo through a
small Anaconda `updates.img`; it does not replace the account pages, storage
logic, or stage2 code. The full GREYWARD branding RPM remains in the staged
target payload and is installed before the first target reboot so Plymouth/LUKS
is branded, while the
production stage is available from the mounted installer media for the target
Kickstart (normally `/run/install/repo/greyward/production`; the Kickstart
resolves the payload marker with controlled fallbacks). The explicit media-test and basic-graphics entries remain
diagnostic alternatives; none starts a live desktop.

No development account, SSH key, passwordless sudo, Hyper-V service, or
development overlay is included. Only the builder needs internet: the ISO
contains the Fedora/COPR RPM closure, Flatpak applications and runtimes, DMS
archive and pinned shell sources. Anaconda uses CD-ROM packages; first boot
finishes with networking absent. Future online updates remain available.

This is deliberately an internal alpha path. It is not release-ready and does
not yet provide a signed release pipeline, hardware
validation, or release-grade installation testing. A fresh image containing
this installer-only workflow still requires a full boot/install/reboot and
first-boot validation before it can be called release-ready.

`validate-production-stage.sh` is the final production-tree closure gate. It
checks the literal staged paths declared by the provisioner in addition to the
payload checksum manifest. `tools/greyward-dev/validate-vmware-candidate.ps1`
is the Windows/VMware gate: it validates the exact ISO-to-VMX mapping, refuses
persistent ISO boot, inspects Linux-visible Rock Ridge names directly from the
ISO, and verifies the provisioner closure and every payload hash before a
VMware start. It is intentionally a preflight: it does not start, stop, or
reconfigure the VM.
