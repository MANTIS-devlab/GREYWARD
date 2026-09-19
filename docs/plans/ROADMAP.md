# GREYWARD roadmap

The canonical `GREYWARD-DEV` development VM is the runtime authority when it is
available. It is not currently registered; a reachable internal-alpha VM is
available for diagnosis only and is development-contaminated. Factory recovery
is maintenance work and is not on the product critical path.

## Production surface decision

DMS Settings is the sole general desktop/system settings surface. GREYWARD Security Center
is the production GREYWARD-specific security and privacy surface. The former standalone
GREYWARD Settings application is removed; roadmap work must not recreate it or add a second
generic settings stack.

The production login path is greetd with the signed DMS Greeter frontend and Fedora PAM.
Any future greeter work must preserve that backend boundary and must not restore tty
autologin or implement authentication in the desktop shell.

## H0 — Development environment recovery (baseline complete; canonical runtime unavailable)

The last accepted VM was a reliable autonomous Labwc + DMS development appliance. The
production image path is `graphical.target → greetd → DMS Greeter/PAM → selected
Wayland session → DMS`; Hyprland remains a selectable fallback. The retained
Quickshell shell and any tty-autologin VM state are development/rollback material only.

Historical runtime acceptance covered Hyprland, Quickshell, portals, PipeWire,
WirePlumber, Wayland capture, repository-shell deployment, session-aware reload,
workspace state-change captures, guest acceptance, graphics gate, and the
`CLEAN-GREYWARD-DEV` checkpoint. Re-run those checks after the VM is recreated;
historical evidence does not prove the current runtime.

Do not make factory recovery the product critical path. Recreate the disposable
VM only as maintenance when runtime validation or the historical Session 10
validation backlog requires
it; do not redesign the factory as part of ordinary product work.

## H1 — Visible GREYWARD shell and canonical identity (complete)

Use the existing `Panel.qml`, workspace/task/status/clock/power components, security placeholder, canonical SVG, and token architecture. Add the geometric wallpaper and establish the full-width bottom taskbar: GREYWARD identity, workspaces, pinned/running applications, intentional negative space, inert Security Center placeholder, status/tray, date/time, and power.

Acceptance: GREYWARD identity is visible, taskbar architecture works, workspace and task interactions work, and no fabricated security state is shown.

Known failed acceptance item (deferred): native mouse edge/corner resizing remains non-functional on the current Hyprland 0.56.2 guest despite the native settings being enabled. Review at the end of H1/H4 compatibility work; do not block the remaining shell work on it.

Do not redesign the taskbar or start compatibility/A-B work.

## H2 — Premium visual refinement and branding (active)

Refine obsidian/graphite/silver materials, controlled blur, borders, reflections, typography, spacing, and restrained animation. Formalize canonical logo generation and controllable Plymouth/boot/unlock branding.

Completed H2 runtime slices include canonical branding regeneration, panel depth and boundary refinement, shared hover/active motion, Fluent app-tile gloss, and the GREYWARD Plymouth theme installed with normal initramfs inventory verified. The disposable encrypted boot-test remains pending; it is separate from the daily development VM.

Acceptance: canonical logo changes regenerate declared consumers and H1 behavior remains intact. Do not delay H1 for visual perfection or alter production login security.

## H3 — GREYWARD system surfaces and ISO integration

Complete the launcher, Quick Settings, notifications, OSD, power menu, and richer
taskbar interactions with real behavior. Package Security Center into the
production image and remove any remaining dependency on a separate development
deployment step.

## H4 — Compatibility and architecture decision

Validate GTK, Qt, Firefox, Flatpak, portals, scaling, restart persistence, and representative applications under Labwc, then compare against the retained Hyprland fallback. Do not reopen COSMIC implementation during H0–H3 or modify STENOS during GREYWARD work.
