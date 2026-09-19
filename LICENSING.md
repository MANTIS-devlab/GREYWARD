# Licensing and branding

This repository contains GPL-licensed project material, reserved GREYWARD
branding, and third-party material. Those categories are separate.

## GPL-3.0-only material

Unless a file carries a different notice, GREYWARD-authored source code and
documentation are licensed under `GPL-3.0-only`. The complete license text is
in [LICENSE](LICENSE). This grant permits source forks, modification, and
redistribution under the GPL; it does not make a modified distribution an
official GREYWARD product.

Configuration, themes, and non-identity artwork are GPL material unless they
are listed below or carry their own notice.

## Reserved branding

To the extent MANTIS SYSTEMS owns the relevant rights, the general GPL grant in
this repository does **not** apply to the following designated identity assets:

- the `GREYWARD` and `MANTIS SYSTEMS` names as product/source identifiers;
- GREYWARD logos, symbol, wordmarks, and lockups under `branding/source/`;
- GREYWARD wallpapers under `branding/wallpaper/`;
- files derived from those assets under `branding/generated/`;
- exact copies or generated forms of those assets installed from packaging or
  embedded in Security Center, the shell, the installer, Plymouth, or Cockpit;
- `environment/flatpak/greyward-software-banner.svg`.

See [branding/LICENSE](branding/LICENSE) and
[branding/PROVENANCE.md](branding/PROVENANCE.md) for the file-level boundary.
Describing material as reserved does not create rights that MANTIS SYSTEMS does
not otherwise hold.

The GPL-covered scripts, service files, stylesheets, and configuration in the
branding RPM remain GPL-3.0-only. The package therefore contains both GPL code
and separately reserved identity artwork.

## Fork and naming policy

GPL source forks may modify and redistribute the GPL-covered material under its
license. A fork may accurately describe its relationship to GREYWARD where the
law permits, but it must not imply endorsement or official status. A modified
distribution does not automatically receive permission to use the reserved
GREYWARD identity as its own product branding. Rebranding does not change the
fork's GPL obligations.

## Third-party material

This policy does not relicense third-party software, fonts, icons, marks, or
artwork. They retain their original terms and may also carry trademark
restrictions. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and notices
next to the relevant files.

## Existing grants and available history

The current Git history contains the branding assets but no committed project
license or committed GPL grant for them. At the time of this audit, `LICENSE`,
the earlier GPL branding statements, and this file are uncommitted worktree
material, and the repository has no configured Git remote. The available local
evidence therefore does not show that these identity assets were publicly
distributed under GPL.

That is not proof that no copy was ever shared elsewhere. If an earlier public
GPL distribution is found, its recipients keep the rights already granted for
that version; this policy must not be read as attempting to revoke them.
