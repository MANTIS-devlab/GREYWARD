# GREYWARD DMS v1.5.3 visual spike

This disposable spike tests the supported DMS custom-theme contract against
the GREYWARD visual language. It intentionally contains no DMS source copy,
QML patch, backend change, plugin, updater, or network module.

The theme is consumed by the shared upstream `qs.Common.Theme` singleton, so
the representative bar, launcher, Control Center, Settings, and notification
surfaces receive the same palette and surface hierarchy. The VM entry/exit
workflow is `tools/greyward-dev/dms-visual-spike.ps1`.

The script backs up `~/.config/DankMaterialShell/settings.json`, applies the
theme only for the capture, restarts the canonical DMS service, and restores
the prior settings on `exit`. The canonical DMS payload and legacy rollback
shell are not modified.
