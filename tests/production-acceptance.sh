#!/usr/bin/env bash
set -euo pipefail

# The installed copy is the single runtime authority. Keep this repository
# entry point so the repository map and existing validation commands remain
# stable while image provisioning installs the same script under libexec.
exec /usr/local/libexec/greyward-production-acceptance "$@"
