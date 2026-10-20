# Post-0.3.8 bare-metal follow-up

This development patch note covers GREYWARD changes prepared after 0.3.8 and
tested on the physical `<validation-host>` system. The user confirms that the feature
workflows described here were exercised on that bare-metal installation. This
is not an ISO release announcement: the matched source and package set below
has not yet been built into a new ISO or accepted through a clean installation.

## Bare-metal test system

- **Machine:** HP OMEN laptop, used as bare metal (not a VM). The exact product
  model, firmware revision, kernel build, and originating ISO checksum were not
  recorded.
- **Graphics:** hybrid AMD and NVIDIA graphics; PCI IDs `1002:1638` and
  `10de:2520`. The test used the built-in eDP panel and two external screens,
  one connected over HDMI and one over DisplayPort. The external screens were
  switched to GREYWARD through a KVM. The model and firmware of the KVM and
  screens were not recorded.
- **Wireless:** Intel Wi-Fi 6 AX200 and the laptop's Intel Bluetooth
  controller.
- **USB:** USB 2.1 hub `05e3:0610` used for the protected **Trust always**
  workflow. The earlier USB 2.0 hub `214b:7260` was also observed and remained
  blocked until separately approved.
- **Keyboard:** French AZERTY selected during installation.
- **Firmware:** Secure Boot enabled. GREYWARD separately reported firmware HSI
  findings; Secure Boot state and overall firmware posture are distinct checks.

The user confirmed successful use of the GREYWARD desktop and taskbar across
the external displays, USB approval, selected keyboard layout, administration,
Security Center and its update/network/security workflows, and the greeter and
protected authorization experience. Available device-level evidence includes
both external screens displaying the desktop, the Intel radios loading their
firmware and discovering nearby networks/devices, and the approved hub's
kernel authorization and persistent USBGuard rule being read back. The patch
does not claim that devices absent from this machine, such as non-Intel radio
families, were physically tested on it.

## Changes prepared for the next ISO

- **Graphics and multi-display shell:** choose the hardware-capable wlroots
  GLES2 renderer when a usable DRM render device exists, retaining bounded
  Pixman fallback for virtual or render-node-limited systems. Scope DMS Network
  Identity and Security Center callbacks per output so each screen keeps its
  own widget state and feedback.
- **Wireless firmware:** include Fedora firmware packages for Intel, Realtek,
  MediaTek, Qualcomm/Atheros, Broadcom/Cypress, NXP, TI WiLink and legacy
  Marvell Libertas devices. The installed Intel AX200 and Bluetooth controller
  were exercised; the other vendor families are included for future hardware
  coverage, not claimed as present on `<validation-host>`.
- **Keyboard selection:** carry Anaconda's XKB selection into the greeter,
  regular Labwc session, and protected compositor instead of assuming a fixed
  layout. The tested installation used French AZERTY.
- **USBGuard:** preserve the protected **Trust always** flow, exact device
  authorization and persistent-rule verification, matching-alert clearance,
  and SELinux boundaries.
- **Security Center workflows:** keep the matched Network Rule and Update
  Center package contracts; make the Overview security-update review open
  Updates and start a resolve-only scan rather than implying that updates are
  available or installing them automatically. Present measured fwupd HSI
  results distinctly from Secure Boot status and keep firmware changes under
  the user's control.
- **Status consistency:** use one bounded posture projection for the taskbar
  and Security Center so short collection gaps do not produce contradictory
  flapping alerts or stale plugin state.
- **Greeter and authorization:** allow correction of an unknown username,
  present the greeter across displays, select a hardware renderer on physical
  systems, and make clear which protected Polkit display accepts password
  input. Keep the other protected displays informational and retain the
  existing authentication boundary.
- **Network Identity and shell completion:** expand country-flag asset support
  and retain actionable button feedback and the corrected Security Center
  launcher behavior.
- **Installation and enrollment reliability:** keep the corrected protected
  session launcher and enrollment/package-receipt checks so an incomplete or
  mismatched installation cannot silently report a successful protected
  session.

The matched source candidate selects DMS `1.6.2-26`, Security Center
`0.1.0-113`, Security Context `0.1.0-106`, Application Security `0.1.0-64`,
and Enrollment `0.1.0-55`. These versions identify source build inputs; they do
not prove an RPM build, a complete offline dependency transaction, or an ISO
installation. The user-confirmed bare-metal results above apply to the
installed `<validation-host>` system, not to a newly composed image.

## Before promoting an ISO

Build and verify the matched Fedora RPM set, confirm the source-to-RPM and
offline payload manifests, compose the ISO through the existing pipeline, and
run the installation and first-boot acceptance checks. Test the resulting
image separately from `<validation-host>`. The broader hardware matrix in
[`HARDWARE_TESTING.md`](../../HARDWARE_TESTING.md) records device families and
edge cases that this one laptop cannot cover.
