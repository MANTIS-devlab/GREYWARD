#!/usr/bin/env bash
set -euo pipefail

readonly DMS_UNIT=greyward-dms.service

status() {
    printf 'dms=%s\n' "$(systemctl --user is-active "$DMS_UNIT" || true)"
    systemctl --global is-enabled "$DMS_UNIT" || true
}

cutover() {
    test -x /usr/local/bin/greyward-dms
    /usr/libexec/greyward-dms-verify >/dev/null
    systemctl --global enable "$DMS_UNIT"
    systemctl --user daemon-reload
    systemctl --user start "$DMS_UNIT"
    sleep 5
    systemctl --user is-active --quiet "$DMS_UNIT"
    status
}

case "${1:-status}" in
    cutover) cutover ;;
    status) status ;;
    *) echo "usage: $0 {cutover|status}" >&2; exit 64 ;;
esac
