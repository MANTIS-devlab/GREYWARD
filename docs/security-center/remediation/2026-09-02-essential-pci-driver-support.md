# Essential PCI driver support audit

## Assessment

Status: EASY and implemented as a bounded extension of the existing Updates
workflow.

The current GREYWARD Update Center already normalizes DNF5, Flatpak, fwupd,
and ClamAV provider data into one snapshot and sends system changes through
the DNF5 daemon or its fixed CLI fallback. Fedora 44's installed DNF5 5.4.3
metadata advertises kernel-module `modalias(...)` capabilities, and
`repoquery --whatprovides modalias(...)` resolves matching RPMs from the
enabled repositories. No daemon, hardware database, hw-probe dependency, or
new privileged service was required.

## Implementation

- Inspect only unbound PCI devices in display, network, and mass-storage
  classes through sysfs.
- Resolve each modalias through the existing DNF5 provider boundary.
- Expose an available non-debug package as a normal DNF5 `system` record with
  driver-support metadata and a minimal Updates-row presentation.
- Add the package to the existing DNF5 daemon goal with `install()` before the
  existing `upgrade("*")` goal.
- Extend the existing fixed CLI helper with validated package arguments for
  its same Apply operation. Its legacy offline upgrade behavior is unchanged
  when no driver package is detected.
- Leave fwupd and firmware behavior unchanged.

## Runtime evidence

In GREYWARD-DEV on Fedora 44:

- DNF5 5.4.3.0 and both `dnf5daemon-server` packages are installed; the DNF5
  D-Bus service is reachable.
- Enabled repositories were Fedora, Fedora Updates, Fedora OpenH264, and the
  existing GREYWARD development COPR sources; no repository was enabled or
  modified by this work.
- The Hyper-V guest has an empty `/sys/bus/pci/devices` directory, so the
  normal scan produced no missing-driver warnings. This is a guest topology
  limitation, not evidence about physical hardware.
- Fedora RPM metadata was verified with AMDGPU modalias queries; DNF5 returned
  `kernel-modules` providers and also exposed the expected debug variants,
  which the implementation excludes.
- A dry-run confirmed DNF5 treats an absent `kernel-modules-extra` package as
  an install goal, while `upgrade kernel-modules-extra` correctly refuses it
  as not installed. This is why the fallback uses the same apply operation's
  separate native install goal.
- The real Tauri interaction harness was also attempted after synchronizing
  the development frontend. It stopped at the pre-existing Privacy profile
  convergence scenario (`SC-PRV-001`) before reaching its Updates checks; no
  Updates UI interaction pass is claimed from that run.

Focused source tests cover essential-class filtering, provider selection,
installed-package unresolved handling, and daemon goal composition. A fake
sysfs fixture is used for the safely simulated unbound case; no guest package
was installed or system state changed.

## Limitations

This does not diagnose why a driver is unbound, load modules immediately,
install proprietary NVIDIA drivers, enable RPM Fusion, repair firmware, or
replace a currently bound driver. The current development VM cannot provide a
real unbound PCI-device runtime case. A package that is already installed is
reported unresolved because the cause may be blacklisting, firmware, kernel
configuration, or hardware failure.

Further work is not justified for the current scope. A future hardware-
specific diagnostic feature would need a separate product decision and
runtime evidence from physical hardware; it should not be folded into this
Updates extension.
