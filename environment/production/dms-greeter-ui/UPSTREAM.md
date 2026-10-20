# GREYWARD DMS Greeter UI

This directory is the external Quickshell UI selected by the production greetd
command. It is based on AvengeMedia `dank-greeter` tag `v1.6.2` at commit
`0175be5c2084e2c5027324403a329e04040cd0bc`. Its `DankCommon` directory is from
`dank-qml-common` commit `26396ce432d6c71c3f5367438f96f4a8d667e160`.

GREYWARD carries two UI changes here:

- The password screen always has an explicit way back to username entry, even
  when only one account exists and the user picker is unavailable.
- Greeter surfaces remain per-monitor through the upstream `GreeterSurface`
  screen variants. The production launcher uses hardware rendering on physical
  systems and applies the software fallback only to virtual/no-render-node
  systems.

The upstream project and shared QML library are MIT licensed. Their license
texts are retained in `LICENSE-dank-greeter-MIT` and
`LICENSE-dank-qml-common-MIT`.
