# VMware Workstation Wayland display diagnostic

This is a development-VM investigation record, not a GREYWARD display
configuration or a release claim. It must not be used to add custom DRM modes,
hard-code a resolution, or alter production Labwc/DMS behaviour.

## Current evidence — 2026-09-16

The Fedora 44 guest booted with `vmwgfx` 2.21.0 on kernel
`7.2.5-200.fc44.x86_64`; that establishes the VMware SVGA DRM driver is loaded.
In the active Labwc session, `wlr-randr` and
`/sys/class/drm/card0-Virtual-1/modes` both listed the same modes and neither
listed `2560x1440`. Their common list included `1280x800` (preferred),
`4096x2160`, `2560x1600`, `1920x1440`, `1920x1200`, and `1920x1080`.

Consequently Labwc and DMS cannot expose `2560x1440`: neither can offer a mode
that the DRM connector has not advertised. This is upstream of GREYWARD.

The VMX declares `svga.maxWidth = 2560` and `svga.maxHeight = 1440`. These are
VMware display limits, not an EDID entry and not a request that `vmwgfx` add a
`2560x1440` DRM mode. Host logs further show the active Workstation process
creating a `ScreenTarget` at `1280x800`, while VMware Tools heartbeats time out
intermittently and a later guest RPC to the toolbox timed out. Those facts make
the prior `vmtoolsd` observation incomplete: the guest agent was not reliably
healthy, but host heartbeats mean it must not be described simply as absent.

At the time this record was updated, the SSH endpoint returned `Connection
refused`; exact installed NEVRAs and current unit state are therefore explicitly
**unverified**, not inferred from the host log.

## Fedora 44 VMware Tools contract

The required base RPM is `open-vm-tools`. Fedora's package owns
`vmtoolsd.service`, the `libresolutionKMS.so` plugin, and related system-side
components. For desktop integration, install `open-vm-tools-desktop`; it owns
the `vmware-user.desktop` autostart entry, `vmware-user`, `vmwgfxctrl`, and the
user-experience plugins including `libresolutionSet.so`. `open-vm-tools-sdmp`
is a service-discovery add-on and is not required for graphics.

Expected processes are deliberately split:

| Scope | Expected component | Purpose |
|---|---|---|
| system | `vmtoolsd.service` / `/usr/bin/vmtoolsd` | host/guest RPC, `resolutionKMS`, time and power integration |
| graphical user session | XDG autostart starts `vmware-user` (which starts a user `vmtoolsd -n vmusr`) | desktop events, clipboard/DnD and resolution user-side integration |
| kernel | `vmwgfx` | VMware SVGA KMS connector and its advertised mode list |

`systemctl is-active vmtoolsd.service` alone does not test the user process;
`pgrep -a vmtoolsd` does not replace the system service state. Both scopes must
be captured. The normal Fedora service name is `vmtoolsd.service`, not an
`open-vm-tools.service` alias.

## Exact next runtime capture

When SSH is reachable, run the read-only gate below from the repository host:

```powershell
pwsh -NoProfile -File .\tools\greyward-dev\graphics-gate.ps1
```

It writes `output/graphics-gate/display-diagnostic.txt` and captures, in order:

1. the installed `open-vm-tools*` RPM NEVRAs;
2. enablement, activity and recent status of `vmtoolsd.service`;
3. the graphical-session `vmtoolsd` processes and VMware user units;
4. the installed resolution plugins and effective `resolutionKMS` stanza;
5. `vmwgfx` boot messages, DRM connector modes, and Labwc's `wlr-randr` view.

Do not run `wlr-randr --custom-mode`, `vmwgfxctrl --set-topology`, or change
`tools.conf` during this capture. They would turn diagnosis into an unrepeatable
workaround and cannot prove that Workstation's automatic Wayland path works.

### What is known about the failure mechanism

VMware's documented Linux resolution path is the Tools `resolutionKMS` plugin,
which communicates the guest UI topology to `vmwgfx`; its desktop user process
implements fit-guest-to-window. That means a functional chain can ask `vmwgfx`
to expose a new virtual topology before the Wayland compositor enumerates it.
It does **not** grant wlroots permission to invent a mode.

The current evidence stops before proving whether Fedora 44 has both the base
and desktop RPMs, whether `resolutionKMS` is enabled/loaded, and whether the
intermittent `vmtoolsd` failure prevents Workstation from sending a 2560x1440
topology. A maintained upstream report still documents current Wayland guests
where fit-to-window and `vmwgfxctrl` do not change the guest resolution even
with both RPMs installed. Therefore the conditional conclusion is precise:

- if enabling/repairing the standard Tools components makes `2560x1440` appear
  in `Virtual-1/modes`, the failure was the VMware Tools/KMS topology path;
- if Tools are healthy, Workstation has been asked to fit to a 2560x1440 window,
  and `Virtual-1/modes` still lacks it, the failure is the VMware
  Workstation/open-vm-tools Wayland resize path. It is not Labwc, wlroots or
  DMS, because the requested topology was never published to DRM.

This is a VMware/Wayland integration limitation, specifically the missing or
ineffective topology update from Workstation through the Tools
`resolutionKMS`/`vmwgfx` path. It is not a claim that Wayland in general, or
every Fedora desktop, cannot resize in VMware.

## Chain and decision tree

```text
Workstation fit-to-window / fullscreen request
  -> open-vm-tools: system vmtoolsd + graphical vmware-user/vmusr
  -> resolutionKMS communicates topology to vmwgfx
  -> DRM Virtual-1 connector modes
  -> wlroots publishes wl_output modes; wlr-randr reads them
  -> Labwc uses those output modes
  -> DMS must list every valid compositor-provided mode
```

```text
Is 2560x1440 in /sys/class/drm/card*-*/modes?
|
|- no -> Is vmwgfx loaded and are base + desktop Tools healthy, with a real
|       Workstation fit request?
|       |- no -> VMware Tools / Workstation integration failure.
|       `- yes -> VMware Wayland topology limitation (or, on physical hardware,
|                 a DRM driver/EDID issue).
|
`- yes -> Is it in wlr-randr for the same connector?
        |- no -> wlroots/Labwc output-enumeration issue.
        `- yes -> Can Labwc select it?
                |- no -> Labwc compositor issue.
                `- yes -> Is it absent from DMS Settings?
                        |- yes -> GREYWARD/DMS presentation issue.
                        `- no -> end-to-end chain works.
```

## Bare-metal expectation

On physical hardware, the monitor's EDID is read by the DRM connector and
provides valid modes. A monitor whose preferred/native mode is `2560x1440`
must consequently expose that mode through DRM, wlroots/Labwc and `wlr-randr`.
DMS should expose every valid compositor-provided mode.

Kanshi can persist and apply a layout using modes that are already exposed; it
does not create DRM modes, repair EDID, or compensate for a missing VMware
topology. That distinction is why VMware diagnosis remains separate from
production output policy.

## References

- Fedora package inventory: <https://packages.fedoraproject.org/pkgs/open-vm-tools/open-vm-tools/fedora-44.html>
- Fedora desktop subpackage inventory: <https://packages.fedoraproject.org/pkgs/open-vm-tools/open-vm-tools-desktop/>
- VMware Tools service and `resolutionKMS` documentation: <https://techdocs2-prod.adobecqms.net/content/dam/broadcom/techdocs/us/en/pdf/vmware/vsphere/vmware-tools/vmware-tools-11-1-0.pdf>
- Fedora Wayland regression evidence for an unloaded `libresolutionKMS.so`: <https://bugzilla.redhat.com/show_bug.cgi?id=1890815>
- Current upstream Wayland resize report: <https://github.com/vmware/open-vm-tools/issues/797>
