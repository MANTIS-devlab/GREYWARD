# Boot rollback prototype

This is deliberately separate from Recovery V1. The current scaffold is the
read-only inventory harness at `tools/greyward-dev/recovery-prototype.ps1`.
Run it against the disposable `GREYWARD-BOOTTEST` VM to capture the current
Fedora Btrfs, `/boot`, EFI, GRUB/BLS, kernel, and Secure Boot arrangement:

```powershell
.\tools\greyward-dev\recovery-prototype.ps1
```

The harness performs no guest mutation. It records filesystem mounts, Btrfs
subvolumes, default subvolume, BLS entries, kernels, `bootctl`, and GRUB
environment state. The next prototype-only step is to add a disposable test
snapshot and one-time boot selection, then verify restoration in a VM before
any product code receives rollback behavior.

Prototype acceptance requires that the VM can boot the selected retained point,
preserve the separate `/boot` and EFI arrangement, and return to the normal
entry afterward. A failed prototype leaves Recovery V1 unchanged.
