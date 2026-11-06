# Local country flags

Unmodified 4x3 SVG artwork from [flag-icons](https://github.com/lipis/flag-icons),
tag **v7.3.2**, commit `fe15c16e7463d0c66d6c5730e9d0e832438d98e1`.
All 249 ISO 3166-1 countries/territories and Kosovo (XK) are included.
Original MIT terms and copyright are in `LICENSE.flag-icons`; immutable archive
and per-file hashes are in `provenance.json`.

`catalog.js` is the generated local allowlist. The application never requests a
flag from a CDN and does not infer a destination's country from its artwork.
Missing/unknown country evidence retains GREYWARD's neutral world marker.
Validate artwork, license and catalog closure with
`python3 tools/verify-country-flags.py`. Assets are embedded by the existing
Tauri frontend build and the MIT license is also installed by the Center RPM.
