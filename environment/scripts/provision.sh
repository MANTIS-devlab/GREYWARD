#!/usr/bin/env bash
set -euo pipefail

# Compatibility entry point. The production system definition lives in one
# place; factories stage it at this path before invoking this wrapper.
exec /bin/bash "${GREYWARD_PRODUCTION_PROVISION:-/tmp/greyward-production/provision.sh}" "$@"
