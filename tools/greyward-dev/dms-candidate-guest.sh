#!/usr/bin/env bash
set -euo pipefail
# Disposable development VM only. Stop the old bus owners before any switch.
state="${XDG_STATE_HOME:-$HOME/.local/state}/greyward/dms-candidate"
action=${1:-status}
mkdir -p -m0700 "$state"
case "$action" in
  prepare)
    test ! -e "$state/original.tar.gz"
    paths=()
    for path in \
      usr/local/bin/greyward-dms usr/local/libexec/greyward-dms-session-migrate \
      usr/local/libexec/greyward-dms-state-migrate usr/local/libexec/greyward-dms-runtime-check \
      usr/local/bin/greyward-session-lock usr/local/bin/greyward-display-power \
      etc/systemd/user/greyward-dms.service etc/systemd/user/dms.service \
      etc/systemd/user/greyward-session-idle.service etc/greyward/dms-release \
      "${HOME#/}/.local/bin/greyward-dms" \
      "${HOME#/}/.config/systemd/user/greyward-dms.service.d" \
      "${HOME#/}/.config/DankMaterialShell" \
      "${HOME#/}/.local/state/DankMaterialShell" \
      "${HOME#/}/.cache/DankMaterialShell" "${HOME#/}/.cache/danklinux"; do
      [[ -e "/$path" || -L "/$path" ]] && paths+=("$path")
    done
    systemctl --user is-active --quiet greyward-session-idle.service && touch "$state/idle-was-active" || true
    systemctl --global is-enabled --quiet greyward-session-idle.service && touch "$state/idle-was-enabled" || true
    sudo -n tar -C / -czf "$state/original.tar.gz" "${paths[@]}"
    sudo -n chmod 0600 "$state/original.tar.gz"
    sudo -n sha256sum "$state/original.tar.gz" > "$state/original.sha256"
    ;;
  activate)
    source=${2:?Provide staged repository directory}
    test -e "$state/original.tar.gz"
    sudo -n sha256sum -c "$state/original.sha256"
    release=$(jq -er '.releaseId' "$source/environment/production/dms-release.json")
    [[ "$release" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]]
    test -r "/usr/lib/greyward/dms/$release/release.json"
    sudo -n install -d -m0755 /etc/greyward
    selector=$(sudo -n mktemp /etc/greyward/.dms-candidate.XXXXXX)
    printf '%s\n' "$release" | sudo -n tee "$selector" >/dev/null
    sudo -n chmod 0644 "$selector"
    sudo -n mv -f "$selector" /etc/greyward/dms-release
    /usr/libexec/greyward-dms-verify >/dev/null
    systemctl --user stop greyward-dms.service
    # Preserve development overrides as evidence; the selected wrapper now owns PATH.
    if [[ -d "$HOME/.config/systemd/user/greyward-dms.service.d" ]]; then
      stamp=$(date -u +%Y%m%dT%H%M%S%N)
      mv "$HOME/.config/systemd/user/greyward-dms.service.d" "$state/pre-candidate-dropins-$stamp"
    fi
    rpm -q greyward-session >/dev/null
    rpm -qf /usr/local/bin/greyward-dms /usr/local/bin/greyward-session-lock \
      /usr/lib/systemd/user/greyward-dms.service /etc/pam.d/greyward-dms-lock >/dev/null
    # Retire the former idle owner; DMS now coordinates native lock and sleep.
    systemctl --user stop greyward-session-idle.service 2>/dev/null || true
    sudo -n systemctl --global disable greyward-session-idle.service 2>/dev/null || true
    sudo -n systemctl --global enable greyward-dms.service
    /usr/libexec/greyward-dms-verify >/dev/null
    systemctl --user daemon-reload
    systemctl --user start greyward-dms.service
    ;;
  rollback)
    test -e "$state/original.tar.gz"
    sudo -n sha256sum -c "$state/original.sha256"
    systemctl --user stop greyward-dms.service greyward-session-idle.service
    # Move migrated data aside; restore originals without merging newer schema files.
    stamp=$(date -u +%Y%m%dT%H%M%S%N)
    for path in "$HOME/.config/DankMaterialShell" "$HOME/.local/state/DankMaterialShell" "$HOME/.cache/DankMaterialShell" "$HOME/.cache/danklinux"; do
      if [[ -e "$path" ]]; then
        destination="$state/post-candidate-$stamp/${path#"$HOME/"}"
        mkdir -p -m0700 "$(dirname "$destination")"
        mv "$path" "$destination"
      fi
    done
    # Remove only managed files absent from the original inventory, then restore.
    sudo -n tar -tzf "$state/original.tar.gz" > "$state/original-files.txt"
    for path in etc/greyward/dms-release etc/systemd/user/dms.service \
      etc/systemd/user/greyward-session-idle.service \
      usr/local/libexec/greyward-dms-state-migrate usr/local/libexec/greyward-dms-runtime-check; do
      if ! grep -Fxq "$path" "$state/original-files.txt"; then sudo -n rm -f "/$path"; fi
    done
    if [[ ! -e "$state/idle-was-enabled" ]]; then
      sudo -n rm -f /etc/systemd/user/graphical-session.target.wants/greyward-session-idle.service
    fi
    sudo -n tar -C / -xzf "$state/original.tar.gz"
    systemctl --user daemon-reload
    systemctl --user start greyward-dms.service
    [[ ! -e "$state/idle-was-active" ]] || systemctl --user start greyward-session-idle.service
    ;;
  status)
    systemctl --user show greyward-dms.service -p ActiveState -p ExecStart -p MainPID
    if [[ -r /etc/greyward/dms-release ]]; then cat /etc/greyward/dms-release; fi
    ;;
  *) echo 'Usage: dms-candidate-guest.sh {prepare|activate REPOSITORY|rollback|status}' >&2; exit 2;;
esac
