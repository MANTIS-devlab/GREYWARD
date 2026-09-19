#!/usr/bin/env bash
set -euo pipefail

# UWSM 0.24.3 creates this drop-in before writing it, but does not create the
# parent directory. Keep the fix narrow and version-independent: patch only
# the installed Labwc plugin's two computed drop-in paths and refuse silently
# changing an unexpected plugin layout.
plugin=/usr/share/uwsm/plugins/labwc.sh
test -r "$plugin"

if ! grep -Fq 'GREYWARD_UWSM_LABWC_DROPIN_DIRECTORY' "$plugin"; then
  grep -Eq '^[[:space:]]*TEMP_DROPIN_DIR=.*systemd/user/.*\.d$' "$plugin"
  sed -i '/^[[:space:]]*TEMP_DROPIN_DIR=.*systemd\/user\/.*\.d$/a\
\t# GREYWARD_UWSM_LABWC_DROPIN_DIRECTORY\
\tinstall -d -m 0755 "${TEMP_DROPIN_DIR}"' "$plugin"
fi

grep -Fq 'GREYWARD_UWSM_LABWC_DROPIN_DIRECTORY' "$plugin"
grep -Fq 'install -d -m 0755 "${TEMP_DROPIN_DIR}"' "$plugin"
