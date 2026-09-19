#!/usr/bin/env bash
set -euo pipefail

# Compatibility entry point for older factory callers.
exec /bin/bash "${GREYWARD_PRODUCTION_DMS_INSTALLER:-/tmp/greyward-production/install-dms.sh}" "$@"
