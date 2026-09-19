# GREYWARD Recovery V1

Recovery V1 provides local Btrfs safety points and encrypted Restic backups.
It does not provide a bootable rollback or complete operating-system restore.

## Local recovery points

The root-owned `greyward-recovery-point` helper creates read-only snapshots of
the installed Btrfs root and explicitly managed system subvolumes. `/home`,
`/boot`, and the EFI system partition are outside the point. On the current
Fedora layout, `/etc` and `/usr` are directories inside the root subvolume and
therefore are referenced by the local filesystem snapshot; V1 exposes no
restore operation for them. They are never included in the Restic backup.
Metadata is stored
under `/var/lib/greyward/recovery/` and retains the reason, creation time,
Update Center operation ID, optional DNF transaction ID, and snapshot status.

Three valid points are retained. Cleanup only operates on metadata-owned point
directories and validates that each deletion target is a Btrfs subvolume.
Manual points are available from Security Center. GREYWARD-managed offline
DNF5 updates create a pre-update point immediately before scheduling the
transaction; direct DNF5 commands are not intercepted. The point and reviewed
system-provider plan run inside one fixed update helper, so Polkit
authenticates the invoking `wheel` user once through the graphical agent.
Manual recovery-point create/cleanup operations retain their separate
per-action authorization.

Creating a local point does not change the platform recovery-readiness check.
That separate posture check covers boot, Secure Boot, encryption, rescue-kernel,
and TPM evidence. It also does not require a Restic backup; the personal backup
has its own destination, completion, and integrity states.
If a platform safeguard is unavailable on a device, Security Center shows the
specific missing capability and offers an explicit accepted-deviation decision.
Accepting Secure Boot, for example, does not claim that a TPM or another
platform safeguard is present.

These points are safety data, not proven bootable system rollbacks.

## Personal backup

The user-scoped `greyward-backup` helper uses Restic with a repository below a
user-selected mounted destination outside the home directory. Backup is
unavailable until that destination has been chosen and validated; cancellation
or a missing configuration leaves the existing destination unchanged. Removable
storage or another supported user-controlled mount is recommended for
protection from local disk loss. GREYWARD rejects directories that only reside
on the root filesystem and records the selected mount identity so a replacement
filesystem at the same path cannot silently receive the backup. The Restic
passphrase is entered by the user
and held only for the current operation; it is never persisted by GREYWARD.

The backup includes existing personal folders and the explicit settings
allowlist for DankMaterialShell, Labwc, and GREYWARD. It excludes operating
system files, `/etc`, `/usr`, kernels, bootloader state, and RPM databases.

Backup completion and integrity verification are separate states. A successful
backup does not run `restic check`; the Security Center records the last
explicit verification independently. Native Restic retention keeps 7 daily and
4 weekly snapshots. Retention pruning is maintenance after the encrypted
snapshot is written: if pruning is temporarily unavailable, the backup still
remains successful and the cleanup is retried on the next backup.

The Security Center displays these operations in a compact workflow queue. It
keeps local points, backup completion, and repository verification independent.
The helper persists the current or most recent operation (`BACKUP`, `VERIFY`,
or `RESTORE`) with `RUNNING`, `COMPLETED`, or `FAILED` state and a stable,
product-safe problem category. Provider diagnostics remain local diagnostics;
they are never used as primary UI feedback.

Restores are selective and staged under the user's GREYWARD restore directory;
existing files are not overwritten automatically. The helper returns at most
500 selectable paths and enforces a maximum selection of 100 paths per restore.
Security Center reports both the shown/available count and the exact review
staging path after a successful restore.

## Deferred

Failed-boot detection, GRUB rollback, root-subvolume promotion, recovery media,
reinstallation, TPM recovery, full bare-metal restore, and complete OS
backup/restore remain deferred. Any boot or system-restore work belongs in an
independent disposable-VM prototype until it passes the current Fedora
`/boot`, EFI, GRUB/BLS, kernel, and Secure Boot tests.
