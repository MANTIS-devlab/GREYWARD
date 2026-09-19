# GREYWARD ISO rebuild quickstart

This is the short operational card for producing the next internal alpha ISO.
Read it together with [ISO_CREATION.md](ISO_CREATION.md). The goal is one
controlled candidate per source change, with the previous ISO kept intact for
rollback. Do not start by booting `.120`; prove the factory inputs first.

## Required bundle

Prepare a dedicated Linux workspace with at least 40 GiB free, preferably
100 GiB. Do not build in a Windows-mounted tree or in the VM's root filesystem.
The bundle must contain exactly these reviewed inputs:

```text
/srv/greyward-build/
  repo/                         # source checkout, recorded revision/diff
  inputs/Fedora-Everything-netinst-x86_64-44-1.7.iso
  inputs/Fedora-Everything-netinst-x86_64-44-1.7.iso.sha256
  inputs/greyward-149-YYYYMMDD.json
  rpms/greyward-branding-*.rpm
  rpms/greyward-security-center-*.rpm
  rpms/greyward-security-context-*.rpm
  rpms/security-center-build-manifest.tsv
  inputs/rpms/opensnitch-1.8.0-1.x86_64.rpm
  output/                         # immutable candidates and sidecars
```

Never use a glob that can select two versions. Resolve each path, then record
its SHA-256. The baseline, Security Center manifest, RPMs and Fedora ISO are
inputs, not disposable build output. Keep them beside the candidate until the
candidate has passed the media-removed reboot.

## One-pass build

Run source checks on Windows before copying the checkout to Linux:

```powershell
pwsh -NoProfile -File .\tests\static.ps1
pwsh -NoProfile -File .\tools\validate-repository.ps1
python -m unittest discover -s tests -p 'test_image_*.py'
git diff --check
git status --short
git rev-parse HEAD
```

Capture the `.149` baseline only after the intended production sources and
portable preferences are final:

```powershell
pwsh -NoProfile -File .\tools\greyward-dev\capture-image-baseline.ps1 `
  -Output output\iso-baselines\greyward-149-YYYYMMDD.json
```

On Fedora, use a new output name and fail immediately if any prerequisite is
missing:

```bash
set -euo pipefail
repo=/srv/greyward-build/repo
build=/srv/greyward-build
base="$build/inputs/Fedora-Everything-netinst-x86_64-44-1.7.iso"
baseline="$build/inputs/greyward-149-YYYYMMDD.json"
output="$build/output/greyward-installer-YYYYMMDD-HHMM.iso"

test -d "$repo"
test -s "$base"
test -s "$baseline"
test "$(find "$build/rpms" -maxdepth 1 -name 'greyward-branding-*.rpm' -type f | wc -l)" -eq 1
test "$(find "$build/rpms" -maxdepth 1 -name 'greyward-security-center-*.rpm' -type f | wc -l)" -eq 1
test "$(find "$build/rpms" -maxdepth 1 -name 'greyward-security-context-*.rpm' -type f | wc -l)" -eq 1
test ! -e "$output"
df -Pk "$build" "$repo" | awk 'NR > 1 && $4 < 41943040 { exit 1 }'

sha256sum -c "$base.sha256"
bash "$repo/environment/image/build-iso.sh" \
  --base-iso "$base" \
  --output "$output" \
  --baseline "$baseline" \
  --base-sha256 "$(awk '{print $1}' "$base.sha256")" \
  --branding-rpm "$(find "$build/rpms" -maxdepth 1 -name 'greyward-branding-*.rpm' -type f -print -quit)" \
  --security-rpm "$(find "$build/rpms" -maxdepth 1 -name 'greyward-security-center-*.rpm' -type f -print -quit)" \
  --security-rpm "$(find "$build/rpms" -maxdepth 1 -name 'greyward-security-context-*.rpm' -type f -print -quit)" \
  --security-build-manifest "$build/rpms/security-center-build-manifest.tsv" \
  --production-rpm "$build/inputs/rpms/opensnitch-1.8.0-1.x86_64.rpm"

sha256sum -c "$output.sha256"
xorriso -indev "$output" -pvd_info 2>&1 | grep "Volume id.*GREYWARD-INSTALLER-44"
```

The builder is the only producer of a fresh canonical ISO. It stages from
empty RPM/Flatpak roots, verifies the payload after composition, and publishes
the ISO only after the embedded payload hashes and baseline match. If any
command fails, keep the output unpublished and diagnose the first failure.

The final ISO also has to pass `environment/image/validate-production-stage.sh`
after extraction. This validator checks the literal staged-file contract used
by `provision.sh`, so a manually remastered or stale tree cannot publish an ISO
whose checksum manifest is internally consistent but incomplete. On Windows,
run the hardware-neutral ISO contract check before starting the Hyper-V guest.
The script name is historical; it does not inspect or require VMware:

```powershell
python .\tools\greyward-dev\validate-vmware-iso.py `
  --iso C:\path\to\candidate.iso
```

The check reads Linux Rock Ridge names directly, checks the provisioner
closure, and verifies the embedded payload hashes. A passing result is only a
media/closure gate; it is not a Hyper-V or bare-metal runtime result.

## Fast update loop

For a normal development change, use this loop instead of repeatedly trying
the VM:

1. Change one owner boundary: production shell/session, branding, Flatpak,
   Security Center, or installer/boot logic.
2. Run the Windows source checks above.
3. Rebuild only the changed component inputs, but always create a fresh staging
   directory and a new ISO filename.
4. Run the offline factory validation. It must use separate
   `XDG_*`, `FLATPAK_SYSTEM_DIR`, `FLATPAK_SYSTEM_CACHE_DIR` and
   `FLATPAK_USER_DIR` directories and an empty network namespace.
5. Inspect the ISO and sidecars before touching the Hyper-V test VM.
6. Prepare `GREYWARD-ISO-TEST-20260901` (`.120`) with a fresh VHDX under the
   project on `F:`. Attach the candidate DVD only for the installer launch; do
   not leave the DVD in persistent firmware boot order.
7. Run the risk-appropriate Hyper-V gate below. Before the first post-install
   reboot, disconnect/eject the ISO and verify the firmware is disk-first. A
   clean install that returns to the installer is not accepted evidence.
8. If it fails, leave the last known-good ISO untouched, record the first
   failure, fix the owning source, and start a new candidate.

The validation order is intentional: Hyper-V is the controlled integration
gate, then bare metal is the portability gate. Do not add hypervisor-specific
production behavior to make the Hyper-V test pass; the ISO must keep its
NVMe/SCSI and physical-hardware paths hardware-neutral.

### Risk gates

| Change | VM gate |
|---|---|
| Docs/tests | No VM boot; source and repository checks |
| Wallpaper, DMS, Labwc, shell, branding | Fresh user login, wallpaper, resolution, minimize controls, zsh configuration |
| Flatpak ref/commit | Offline installation of the complete selected set and commit comparison |
| Security Center/RPM | Provider services active, user bus active, Security Center posture available |
| Kickstart, core RPMs, boot, initramfs, first boot | Fresh Hyper-V Anaconda install, first boot, acceptance, ISO removed, reboot; then repeat the minimum boot/provisioning gate on bare metal |

When in doubt, use the higher gate. A repaired installed disk never closes the
fresh-install gate.

## Flatpak-specific invariant

Flatpak 1.18.2 is the known target behavior. `create-usb` may leave refs under
`refs/mirrors/org.flathub.Stable` with no usable summary branches. The factory
must therefore:

1. copy selected collection refs to ordinary `refs/heads` refs;
2. run `flatpak build-update-repo --collection-id=org.flathub.Stable`;
3. write a non-empty `offline/flatpak-inventory.tsv`;
4. install through the ISO-local `file://` remote and `--sideload-repo`;
5. run in an empty network namespace;
6. verify every installed commit with `flatpak info --show-commit`; and
7. remove only the temporary remote with `remote-delete --force` after success.

Do not add `flatpak install --commit=...`: Flatpak 1.18.2 does not support it.
Do not add `--no-pull`: it prevents the sideload remote from resolving. The
network namespace, local remote, and post-install commit check are the three
offline guarantees.

## Candidate record and rollback

Save this record beside every candidate before attaching it:

```text
candidate ISO and SHA-256:
parent known-good ISO and SHA-256:
source revision and intentional dirty changes:
base ISO and vendor SHA-256:
baseline and SHA-256:
branding/security/external RPMs and SHA-256:
Flatpak refs and commits:
builder/tool versions:
offline factory result:
ISO payload/volume/repository result:
test VM and disk identity:
VM gate result and remaining limitations:
```

Rollback is selecting the previous immutable ISO and restoring its recorded
DVD mapping. Do not copy files into the installed disk, overwrite an ISO, or
reuse a failed candidate filename.
