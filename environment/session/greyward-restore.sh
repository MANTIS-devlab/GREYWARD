#!/usr/bin/env bash
set -euo pipefail

address="${1:?window address required}"
state_file="${XDG_STATE_HOME:-$HOME/.local/state}/greyward/minimized.tsv"
workspace=""
if [ -f "$state_file" ]; then
    workspace=$(awk -F '\t' -v address="$address" '$1 == address { print $2; exit }' "$state_file")
    tmp="$state_file.tmp"
    awk -F '\t' -v address="$address" '$1 != address' "$state_file" > "$tmp"
    mv -f "$tmp" "$state_file"
fi
if [ -z "$workspace" ]; then
    workspace=$(hyprctl activeworkspace -j | jq -r '.id')
fi
hyprctl dispatch movetoworkspacesilent "$workspace,address:$address"
exec hyprctl dispatch focuswindow "address:$address"
