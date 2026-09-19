# 2026-09-07 F07 Black Box terminal

## Scope

This is the current F07 remediation record. The prior Kitty-backed Terminal
migration is retained as historical evidence in
`2026-09-07-f07-terminal-migration.md`; it is superseded by this Fedora-native
Black Box implementation.

## Source implementation

- `environment/production/packages.txt` installs Fedora's `blackbox-terminal`.
- `environment/production/desktop-entry-overrides/com.raggesilver.BlackBox.desktop`
  overrides the upstream desktop entry by its real app ID, presents the name
  `Terminal`, uses the GREYWARD icon, and starts `/usr/bin/zsh` through Black
  Box.
- `environment/production/blackbox/schemes/` and
  `environment/production/dconf/50-greyward-blackbox` provide the captured
  production state: Dark Pastel dark theme, Gruvbox Light light theme,
  Cascadia Mono NF 14, 93% opacity, 12px padding, remembered 1237x945 window,
  login shell, tabs, and discoverable settings defaults.
- Labwc, Hyprland, image staging, production provisioning, development deploy,
  acceptance, and DMS default-pin migration all use the Black Box app ID.
  The Zsh and Oh My Zsh sources remain the same; the canonical Powerlevel10k
  prompt explicitly shows the current user and current directory.
- Existing user Kitty/Tabby directories are not deleted; no active production
  launcher or package depends on them.

## Runtime evidence

- Fedora Updates provided `blackbox-terminal-0.15.2-1.fc44.x86_64` on `.149`.
- An isolated Black Box launch in the existing Wayland/Labwc session created a
  `/usr/bin/zsh --login` child with `TERM=xterm-256color` and
  `COLORTERM=truecolor`. The shell-only prompt correction now shows the current
  user and keeps the current-directory segment visible; terminal application
  settings are not part of this correction.
- The real Black Box menu exposed New Tab, New Window, Preferences, Keyboard
  Shortcuts, and Fullscreen. The Preferences dialog exposed General, Terminal,
  Keyboard, and Advanced settings. A second tab was created successfully.
- No reboot was performed. The deployed session shows the three expected DMS
  pins (Brave, Terminal/Black Box, and Nautilus) and a ready Black Box window.

## Validation

- `tests/static.ps1`, `tools/validate-repository.ps1`, and `git diff --check`
  passed after the Black Box source migration.
- The live development deployment completed with `DEPLOY OK` and no reboot.
- `.149` reports `blackbox-terminal-0.15.2-1.fc44.x86_64`; Kitty and Tabby are
  not installed. The installed override reports `Name=Terminal`, the Zsh
  launcher, GREYWARD icon, and `StartupWMClass=com.raggesilver.BlackBox`.
- The live Black Box settings were captured as the fresh-install production
  defaults: Dark Pastel/Gruvbox Light themes, Cascadia Mono NF 14, 93%
  opacity, easy copy/paste, remembered 1237x945 window, 1000 scrollback lines,
  visible header/menu, floating controls, and 12px padding.
- Live DMS state contains exactly `brave-browser`,
  `com.raggesilver.BlackBox`, and `org.gnome.Nautilus` in both pin lists.
- The deployed Black Box process has a `/usr/bin/zsh --login` child. The
  canonical `.zshrc` and `.p10k.zsh` match the live shell hashes
  `4db86514da187b6d55f15368c3fcc8baf1591fd884170a4b8ed30ab6c080ea5a` and
  `d832b4a9ef8d8babd9e2f35dc208222263d9312cf517982c1e37bd10dce106b3`;
  Powerlevel10k shows the current directory on the left and current user on the
  right with no icon padding or proactive directory shortening.
- New Black Box sessions render the local-only GREYWARD terminal brief from
  `/usr/local/libexec/greyward-terminal-brief`; nested, non-interactive, and
  SSH shells remain quiet. It reads no Security Context cache and makes no
  provider calls; rapid additional sessions receive one compact line instead
  of repeating the full brief.
- The brief now shows only useful local system information: Fedora release,
  kernel, uptime, memory use, shell, and hostname. It does not display
  Security Center posture, network, DNS, profile, firewall, or update-provider
  details during shell startup. Its terminal card uses a restrained,
  font-safe GREYWARD wordmark and aligned system facts, so it does not depend
  on a runtime image renderer.
- The canonical desktop and Labwc/Hyprland launchers set
  `GREYWARD_TERMINAL_BRIEF=1`; the first Black Box window therefore does not
  depend on `TERM_PROGRAM` timing. On `.149`, the interactive pseudo-terminal
  check rendered the brief and reached `READY_OK` without a reboot.
- No real user C2 or unrelated network policy is involved.

## Status

**F07 — FIXED + RUNTIME VERIFIED** — Black Box is now the sole production
terminal backend and the live `.149` session is ready to accept commands.
