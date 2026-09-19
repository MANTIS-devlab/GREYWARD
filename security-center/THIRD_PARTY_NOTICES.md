# Third-party notices

This inventory is a repository-hygiene record, not legal advice. Version,
source, hash, and license evidence must be updated together when an asset is
refreshed.

## Bundled code

- `security-center/vendor/tao-0.35.3/` is Tao 0.35.3 from the Tauri project,
  licensed under Apache-2.0. Its complete upstream license and SPDX record are
  retained as `LICENSE` and `LICENSE.spdx` in that directory. The local Cargo
  patch exists for the documented Labwc integration and must not be mistaken
  for GREYWARD-owned code.

## Fonts

- `security-center/data/fonts/InterVariable.ttf` and its byte-identical
  frontend copy are Inter Variable, SHA-256
  `4989b125924991b90d05b2d16e0e388c48f7d5bb8b30539bbf9c755278d0ccaf`.
  The binary is byte-identical to
  `assets/fonts/inter/InterVariable.ttf` in the official DMS v1.5.3 QML
  release archive. Its upstream SIL Open Font License 1.1 text is retained as
  `security-center/data/fonts/Inter-OFL-1.1.txt`.
- `security-center/data/fonts/MaterialSymbolsRounded.ttf` is Google Material
  Symbols Rounded, SHA-256
  `d719f22fdee27e344b07e46e6fa8b50b1fce3cfcb03d4a84f03fafbf0812fc22`.
  The binary is byte-identical to
  `assets/fonts/material-design-icons/variablefont/MaterialSymbolsRounded[FILL,GRAD,opsz,wght].ttf`
  in the same archive. Its upstream Apache-2.0 text is retained as
  `security-center/data/fonts/Material-Symbols-Apache-2.0.txt`.

Exact shared receipt: DMS tag `v1.5.3`, full source commit
`069ddab041c738236a8910e4c39b65d9628d3018`, official immutable asset
`https://github.com/AvengeMedia/DankMaterialShell/releases/download/v1.5.3/dms-qml.tar.gz`,
archive SHA-256
`db9d4955a8155d4c6f157027a7f3d61173546afe71eff439f74cf7b918b27f2b`.
The archive and its sibling checksum asset are recorded by the official GitHub
release. The DMS source pin and release evidence are documented in
`docs/decisions/DANK_UPSTREAM.md`.

## Network identity marks

- `security-center/tauri/frontend/assets/network-icons/` contains the Simple
  Icons 16.28.0 set and a generated local catalog. The upstream project is
  CC0-1.0, while individual marks may remain subject to trademark or additional
  brand restrictions. The version and upstream disclaimer are recorded in the
  directory README. Review the individual marks actually used by the product
  before a release rather than treating the bulk catalog as blanket trademark
  permission.

## GREYWARD visual assets

GREYWARD symbols and supplied wallpaper images are project assets, not
third-party inventory. Their repository origins and immutable hashes are
recorded in `branding/PROVENANCE.md`; `LICENSING.md` includes them in the
project's GPL-3.0-only grant.
