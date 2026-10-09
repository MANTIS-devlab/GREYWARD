#!/bin/bash
# Compatibility entrypoint for the retired standalone Safe Open probe.
# The shared workflow owns synthetic inputs, fresh authorization and rollback.
set -euo pipefail
test "$#" = 0
exec /bin/bash /var/tmp/greyward-application-security-probe/application-security-registration-guard.sh --workflow
