#!/usr/bin/env bash
set -u

# Keep tty1 informative while the first-boot gate owns the machine.  The
# getty is deliberately gated during this period, so writing directly to the
# terminal avoids exposing either a misleading login prompt or a blank screen.
pending=/var/lib/greyward/installer/production-pending
status=/var/lib/greyward/installer/status.txt
stage=/usr/lib/greyward/installer/production
phase_file="$stage/provision-current-phase.txt"
failure_file="$stage/provision-failure.txt"
log=/var/log/greyward-production-firstboot.log
tty=/dev/tty1
message='GREYWARD setup is in progress. Please wait and do not turn off the computer.'

# Print the hand-off message once. Repainting the terminal every few seconds
# erases the first-boot service's useful command output and makes a healthy
# transaction look frozen.
plymouth display-message --text="$message" 2>/dev/null || true
if [[ -w "$tty" ]]; then
  {
    printf '\n\n  GREYWARD setup is in progress.\n\n  Please wait and do not turn off the computer.\n\n'
    if [[ -r "$status" ]]; then
      printf '  Last recorded status:\n'
      sed -n '1,2p' "$status"
      printf '\n'
    fi
    if [[ -r "$phase_file" ]]; then
      printf '  Last recorded phase: '
      sed -n '1p' "$phase_file"
      printf '\n'
    fi
    if [[ -r "$failure_file" ]]; then
      printf '  Previous failure details:\n'
      sed -n '1,12p' "$failure_file"
      printf '\n'
    fi
    if [[ -r "$log" ]]; then
      printf '  Recent provisioning output:\n'
      tail -n 20 "$log"
    fi
    printf '\n  Provisioning logs follow:\n\n'
  } >"$tty"
fi
while [[ -e "$pending" ]]; do
  sleep 5
done
