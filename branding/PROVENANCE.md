# GREYWARD visual asset provenance

The commits below record when assets entered this repository. A commit proves
repository origin, not authorship or a complete chain of title.

- identity sources: `e89f76f63278929804e6b6cfa031b0f230b95414`;
- current wallpaper variants: `d437ca964efaa501666d86f595d1141a181d32d5`;

The listed identity files are designated reserved branding under
[`branding/LICENSE`](LICENSE), to the extent MANTIS SYSTEMS owns the relevant
rights. Generated files inherit the status of their canonical source.

| Asset | SHA-256 | Role |
|---|---|---|
| `source/greyward-lockup.svg` | `fcaf3313b6d33ae3e96a562d4df51c390974d5b762be06c357f07941fd1ee3f5` | canonical lockup |
| `source/greyward-symbol.svg` | `dd925d9f9ef3edc174f9b9fcbc0972a60d13a3d21c9d6864ac39727a028b6f22` | canonical symbol |
| `source/greyward-wordmark.svg` | `3cc9f65e9e677dab5a4deb0cc86368fe46ab61195be5069713247cb77b2441a2` | canonical wordmark |
| `source/greyward-wordmark.png` | `3e5bc969e59d3314cc3641f5077aeb1bee9389b281cf9612413dbd7bee54752e` | raster wordmark |
| `source/greyward-security-status.svg` | `db8498f6928b58a8b1962bb68af9c60f671747f2da73bec4e0d8c85c8ed97411` | shared Security Center shield-G emblem |
| `source/greyward-terminal.svg` | `9107af619b980da9d00071159ddcc7fd8ca602b598b1b9236eeab513ecbe4817` | terminal identity icon |
| `source/greyward-files.svg` | `a19431fda8cf7bded368da790c0ed8c282dae0b7c6ae6a6b0bfdb8dc57c4f122` | original GREYWARD Obsidian/Platinum file-manager folder, 13 October 2026 |
| `wallpaper/greyward-wallpaper.svg` | `f7bcb113e6116897c601ba1328811ccf62e94f44b08cd4d63c428fc4cee83a16` | canonical environmental source |
| `wallpaper/greyward-wallpaper-black-art-4k.jpg` | `30f33a7f347c53e29dab65e8b6ef49345063d2ae674bcf102bed693c7db431c7` | desktop wallpaper |
| `wallpaper/greyward-wallpaper-2109-4k.jpg` | `5b05020838a7a7f661f17be715470af4860253d2f23ea530d311ba123c15bd67` | desktop wallpaper |

The maintainer has confirmed that the two supplied JPG wallpapers are to be
retained and published as designated GREYWARD branding. Their repository
origin is recorded above; any private source or chain-of-title evidence should
be retained outside Git. The separate historical greeter JPG was removed from
the publication candidate rather than making an unsupported rights claim.
Do not add third-party material to this table.

The file/object family catalog `source/greyward-icon-family.json` has SHA-256
`51bebf9834052729d3fb8671d192ad0d4b011ba09188a7d74c61787fdb44848f`.
Its folder/page/material geometry is GREYWARD artwork; its separately attributed
action and extension glyphs are derived from Lucide/Feather and Catppuccin in
the pinned Strata source archive recorded in `packaging/greyward-files/source.json`.
`tools/generate-file-icons.py` copies those exact ISC/MIT notices into the RPM
and records each generated asset's digest. Those third-party glyphs are not
claimed as reserved GREYWARD branding.

The current Security Center emblem was approved by the maintainer on 8 October
2026 after built-in image generation using the canonical GREYWARD symbol as
reference. The repository SVG is a polygonal refinement of that candidate;
the launcher SVG and PNG are derived assets. The previous small emblem hash
`8f9768936e6c6227bc567dfe06404f4230a2f098f0789e21effd15d3bedde46d`
describes the historical design.

Original GREYWARD application bag: `source/greyward-software.svg`, SHA-256
`cc026f6f65e1c98ec1ae095f366bfece864a766fe9b74d29474d4b84e1139598` (25 October 2026).

Original GREYWARD photograph frame: `source/greyward-image-viewer.svg`, SHA-256
`452f433b812e909e635a0b75df78939491306f445da5941a9967082a73f23930` (25 October 2026).

Original GREYWARD machined gear: `source/greyward-settings.svg`, SHA-256
`e88d8d47663ffd5ab5929aecc39f8d53fabec67aa416f89709afc19703af908b` (25 October 2026).

## Office application/document separation — 25 October 2026

The four `greyward-*-document.svg` files retain the accepted revision-5
application artwork byte-for-byte. The new application vectors use coordinated
graphite tiles and independent functional marks. The Office source manifest
locks both families; no third-party logos or external SVG resources are added.

| Family | Application SHA-256 | Retained document SHA-256 |
|---|---|---|
| Writer | `a9fd4a79f5a3dd2209cf143eeb63d6af050b0c053525cb966179a893ee777903` | `f9dbbb6d310485b72213b69c0411d0de5857e9c2132c432444e95d0515a1ad9d` |
| Sheets | `38d024ddacea88f9b4a095a5516f3365a4844652829e08c43c49d1563970f053` | `1cadb11395d3461f855180e7004cb58a896e384ceb26413b2fac54af48d52794` |
| PDF | `b563f79413565aacb182e444db31532b687547bc7d310ea27c3b2ba9e2669b19` | `f15b53a789886de48e4fe9857fb8e50d8478ca2873bf0fef3a65d286f45944bf` |
| Slides | `3a065e665ec0fc53e97dd5beef4e059537d90532716353df162352e2ed9ef801` | `1d224eaf5e43524967d364701b3dcd348e9342cc1a85afed679af20a5745b33c` |
