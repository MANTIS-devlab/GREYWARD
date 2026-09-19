# 2026-09-07 F07 terminal migration

> **Historical record.** This intermediate Kitty migration was superseded by
> the Fedora-native Black Box implementation in
> [the current F07 record](2026-09-07-f07-blackbox-terminal.md).

## Scope

This record covers only the F07 terminal integration. Tabby was the former
GREYWARD terminal application. The current product identity is `Terminal`,
implemented with Kitty as the rendering and terminal engine.

## Source implementation

- `environment/production/packages.txt` installs Kitty from the configured
  Fedora/COPR package source; the Tabby external RPM is no longer a production
  input.
- `environment/production/desktop-entry-overrides/greyward-terminal.desktop`
  is the single user-facing desktop entry. It starts `/usr/bin/zsh`, uses the
  `greyward-terminal` application identity, and points to the GREYWARD
  geometric icon.
- The package-provided `kitty.desktop` and `kitty-open.desktop` entries are
  installed as hidden, non-displayable overrides so application search does
  not expose duplicate Kitty launchers. They are backend packaging details,
  not alternate GREYWARD terminal identities.
- `environment/production/kitty/kitty.conf` is the canonical Kitty config. It
  uses `Cascadia Mono NF`, opaque obsidian/platinum colors, enabled shell
  integration for working-directory behavior, and `allow_remote_control no`.
- Labwc, Hyprland, image staging, production provisioning, development deploy,
  acceptance, and DMS default-pin migration all reference the same Terminal
  entry. `.zshrc`, `.p10k.zsh`, Oh My Zsh pins, history, aliases, plugins, and
  the user's shell remain unchanged.
- The migration changes only the exact former GREYWARD default pin list from
  `tabby` to `greyward-terminal`; a customized DMS `barPinnedApps` list is not
  rewritten. Existing user-owned `~/.config/tabby` data is not deleted.

## Runtime evidence on `.149`

- Kitty `0.48.2` installed successfully with its required Kitty helper,
  shell-integration, and terminfo packages.
- The former `tabby-terminal` RPM is absent.
- The installed desktop entry is named `Terminal`, uses
  `greyward-terminal.desktop`, and has `greyward-terminal` as its icon and
  startup identity.
- The live Kitty child shell is `/usr/bin/zsh` with `TERM=xterm-kitty`,
  `COLORTERM=truecolor`, and `KITTY_WINDOW_ID=1`; the Powerlevel10k prompt was
  visible in the real VMConnect desktop screenshot.
- DMS state is now:
  `brave-browser`, `greyward-terminal`, `org.gnome.Nautilus`.
- The live DMS launcher returned `Terminal` as the top application result for
  `terminal`, `console`, `shell`, and `command`; the GREYWARD icon and the
  terminal comment were visible in the live guest framebuffer. The taskbar
  pin state and legacy `pinnedApps` state both contain the same three default
  identities above.
- No reboot was performed. One controlled `greyward-dms` user-service restart
  was used to load the migrated pin state.

## Validation

- `tests/static.ps1` passed.
- `tools/validate-repository.ps1` passed.
- `git diff --check` passed.
- Remote `bash -n` passed for the installed DMS migration helper; local WSL
  `bash -n` was unavailable because the host WSL distribution was mounted
  read-only, not because of a script syntax error.
- Kitty launched successfully in the existing Labwc session and rendered a
  ready `Terminal` window.
- An isolated Kitty fixture validated tabs, vertical splits, horizontal
  splits, shell startup, and GREYWARD terminal styling; the fixture was
  removed after the check.
- DMS `spotlight`/launcher search was validated against the live guest
  Wayland framebuffer rather than relying on the stale VMConnect overlay
  capture.

## Status

**FIXED + RUNTIME VERIFIED** — the canonical Terminal migration, live Kitty /
Oh My Zsh / Powerlevel10k session, DMS search identities, default pins, hidden
backend launchers, and isolated terminal interaction fixture all passed on
`.149` without a reboot.
