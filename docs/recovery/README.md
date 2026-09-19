# GREYWARD recovery documentation

- [RECOVERY_V1.md](RECOVERY_V1.md) is the current local recovery-point and
  encrypted Restic backup boundary.
- [BOOT_ROLLBACK_PROTOTYPE.md](BOOT_ROLLBACK_PROTOTYPE.md) is a separate
  technical prototype and is not product rollback behavior.

Recovery points are safety points, not proven bootable system rollbacks. The
implementation is in `security-center/security-context/` and its tests are in
`security-center/security-context/tests/`.
