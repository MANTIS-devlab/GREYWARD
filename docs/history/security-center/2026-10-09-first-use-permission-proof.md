# First-use permission prerequisite experiment — 9 October 2026

Status: BLOCKED at the approved minimal-architecture stop condition. This is
dated development evidence, not delivery of Flatpak permissions or a grant test.

## Installed baseline and experiment

Normal enrolled `.149`: Center 89 / Context 81 / experimental runtime 32;
SELinux Enforcing, workflow broker active, policy revision 8. The shared root
filesystem had 5.1 GiB available (92% used). No cleanup, build, package update,
policy installation, relabel, grant, service restart or session termination was
performed. SSH and the existing desktop remained available.

The generic prerequisite probe is
`tools/greyward-dev/application-security-first-use-proof.py`. It runs as the
enrolled user against an already registered protected directory, attempts
directory enumeration, and makes no protected-file content reads. The test used
the existing registered `.ssh` directory; it did not provision Sensitive files
or alter that registration. Only a launch-local read-only Flatpak filesystem
exposure was used, never a persistent override.

Representative installation: `com.collaboraoffice.Office`, system/stable,
deployment `ea63f13fca944be938b64e5c3e9212c02c10f1eb163c4f30191130cba419f106`.
Commands were ordinary `ls` processes inside this installation's sandbox, not
the office application itself. The separate experiment exercised the stock
FileChooser protocol from that sandbox, not Collabora's actual chooser selection
or document editing. Run the probe as the enrolled user:

```bash
python3 tools/greyward-dev/application-security-first-use-proof.py --app com.collaboraoffice.Office --registered-folder /home/development-user/.ssh --portal
```

| Experiment | Actual result |
|---|---|
| Default Flatpak namespace: inspect protected directory path | ENOENT; zero new corresponding resource-denial events. Sandbox invisibility cannot trigger a SELinux review. |
| Launch-local `--filesystem=<registered-folder>:ro`: enumerate directory | EACCES; broker recorded enforcing READ denial at revision 8, executable `ls`, attribution UNKNOWN. No application permission was granted. |
| Stock FileChooser `OpenFile`, `current_folder` set to protected directory | Request returned successfully; the probe maintained its connection and closed only its own request after four seconds. Root event identified `xdg-desktop-portal-gtk`, PID 1222317, attribution UNKNOWN. |
| Unrelated Brave sandbox and ordinary native process | Native enumeration denied. Brave deployment `9d20be5668b864b145de1a25576c7a7206d56ea6e04d3eee838f4c107433aaab` also hid the path by default; launch-local exposure produced EACCES and a broker READ denial. This is a sandbox command test, not browser interaction. |
| Ordinary synthetic document exported transiently with no app permission | Ordinary host process read the original through `/run/user/1001/doc/...`; alias label `fusefs_t`, original label `user_tmp_t`. Export explicitly removed and disposable source deleted. No protected data or app grant involved. |

The last control proves host alias readability for an ordinary exported file,
not an actual protected-resource bypass. Protected-resource access remains
denied. It explains why shared document-service resource reads are not an
acceptable shortcut: the original resource label cannot be presumed to enforce
access through that host FUSE view.

## Gate outcome and reason to stop

- **Gate A — NOT DEMONSTRATED:** current reviewed launcher supports restricted
  read-only SSH inspection, not a generic writable Flatpak workload. No protected
  Flatpak grant was created; no positive/revocation claim is made.
- **Gate B — BLOCKED for the standard shared portal workflow:** a resource AVC
  from the chooser identifies the shared backend, not the requesting Flatpak.
  App-only permission would leave that chooser denied. Current audit/grant APIs
  contain no request-bound portal delegation that resolves this.
- Native/Flatpak negative controls pass. Both end-to-end properties remain
  unpassed; script support, full UI and general provisioning did not begin.

Immutable deployment and app ID alone do not bind a grant to a live workload.
Historical PID/basename fields in `access_events.rs` deliberately have UNKNOWN
attribution. They were not upgraded into authorization evidence. The existing
notification pipeline remains informational; no unsupported Allow was added.

Broadening the ordinary shared portal would introduce a deputy boundary needing
separate enforcement and alias tests. Private portal workers, a custom portal
backend, forcing a particular application's native dialog, or broadly granting
the ordinary role exceed the minimal experiment or violate its stop conditions.
None was done. This does not prove safe managed Flatpak grants universally
impossible. It is a NO-GO for treating the current audit-notification bridge as
a complete generic solution with unchanged standard portal workflow. Further
architecture work requires an explicit decision, not silent expansion.

All Allow once, Allow always, Deny and Revoke decisions remain reserved for the
user. There is no ready end-to-end authorization test entry point yet.

Repository checks after the scoped probe/documentation additions:
`pwsh -NoProfile -File tests/static.ps1` and
`pwsh -NoProfile -File tools/validate-repository.ps1` both PASS. No backend or
frontend source changed, and no Rust/GUI acceptance is claimed for this feature.
