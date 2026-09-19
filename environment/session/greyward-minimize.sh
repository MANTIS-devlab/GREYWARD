#!/usr/bin/env bash
set -euo pipefail

# Hyprland 0.56.2 does not implement xdg_toplevel.set_minimized. GREYWARD's
# supported emulation is a dedicated special workspace plus per-window state.
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/greyward"
state_file="$state_dir/minimized.tsv"
mkdir -p "$state_dir"
window=$(hyprctl activewindow -j)
address=$(jq -r '.address // empty' <<<"$window")
workspace=$(jq -r '.workspace.id // empty' <<<"$window")
test -n "$address" -a -n "$workspace"
test "$workspace" != "-98"
tmp="$state_file.tmp"
touch "$state_file"
awk -F '\t' -v address="$address" '$1 != address' "$state_file" > "$tmp"
printf '%s\t%s\n' "$address" "$workspace" >> "$tmp"
mv -f "$tmp" "$state_file"
exec hyprctl dispatch movetoworkspacesilent "special:minimized,address:$address"
