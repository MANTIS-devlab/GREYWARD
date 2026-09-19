#!/usr/bin/env bash
set -euo pipefail

# Anaconda owns disk encryption and creation of the user's account. This
# service is installed as a small on-disk gate by the installer %post because
# system-service and Flatpak work cannot safely run inside
# Anaconda's target chroot. It runs only after the first reboot.
# The production payload is immutable installer content and lives on the
# installed root filesystem. Do not put it below /var: Fedora's automatic
# Btrfs layout may mount /var separately after Anaconda's nochroot %post.
stage=/usr/lib/greyward/installer/production
provision="$stage/provision.sh"
pending=/var/lib/greyward/installer/production-pending
reboot_requested=/var/lib/greyward/installer/anaconda-reboot-requested
reboot_confirmed=/var/lib/greyward/installer/anaconda-firstboot-entered
ready=/var/lib/greyward/installer/production-ready
phase_file="$stage/provision-current-phase.txt"
failure_file="$stage/provision-failure.txt"
greetd_failure=/var/lib/greyward/installer/greetd-failure.txt
status=/var/lib/greyward/installer/status.txt
log=/var/log/greyward-production-firstboot.log
console=/dev/tty1

install -D -m 0644 /dev/null "$log"
install -D -m 0644 /dev/null "$status"
if [[ -w "$console" ]]; then
  exec > >(tee -a "$log" "$console")
  exec 2> >(tee -a "$log" "$console" >&2)
else
  exec > >(tee -a "$log")
  exec 2> >(tee -a "$log" >&2)
fi
report() {
  printf 'GREYWARD setup: %s\n' "$1" | tee "$status"
  plymouth display-message --text="GREYWARD setup: $1" 2>/dev/null || true
}
failed() {
  code=$?
  trap - ERR
  report 'Setup could not finish. Your installation is preserved. Diagnostic log: journalctl -u greyward-production-firstboot. Retry setup after resolving the reported error.'
  if [[ -r "$phase_file" ]]; then
    report "Last provisioning phase: $(sed -n '1p' "$phase_file")"
  fi
  if [[ -r "$failure_file" ]]; then
    report 'Provisioning failure details follow:'
    sed -n '1,12p' "$failure_file"
  fi
  plymouth quit 2>/dev/null || true
  chvt 1 2>/dev/null || true
  exit "$code"
}
preflight_failed() {
  local reason="$1"
  local path="${2:-}"
  trap - ERR
  report "Setup could not start: $reason"
  printf 'GREYWARD first-boot: preflight failure: %s\n' "$reason"
  if [[ -n "$path" ]]; then
    printf 'GREYWARD first-boot: required path: %s\n' "$path"
    ls -ld -- "$path" 2>&1 || true
  fi
  printf 'GREYWARD first-boot: stage: %s\n' "$stage"
  exit 1
}
preflight_check() {
  local label="$1"
  local path="$2"
  local kind="$3"
  printf 'GREYWARD first-boot: checking %s\n' "$label"
  case "$kind" in
    directory)
      [[ -d "$path" ]] || preflight_failed "$label is missing" "$path"
      ;;
    file)
      [[ -f "$path" ]] || preflight_failed "$label is missing" "$path"
      ;;
    readable)
      [[ -r "$path" ]] || preflight_failed "$label is missing or unreadable" "$path"
      ;;
    *)
      preflight_failed "internal preflight kind is invalid: $kind" "$path"
      ;;
  esac
  [[ -r "$path" ]] || preflight_failed "$label is not readable" "$path"
  printf 'GREYWARD first-boot: %s is present and readable\n' "$label"
}
trap failed ERR
report 'GREYWARD is finishing setup. Please wait and do not power off.'
printf 'GREYWARD first-boot: finalizer entered; validating staged inputs.\n'
# Keep these checks after the log redirection so a missing or unreadable stage
# is visible on tty1 and in the journal instead of looking like a blank boot.
[[ "$(id -u)" -eq 0 ]] || preflight_failed 'finalizer is not running as root'
# The staged provisioner is intentionally invoked through bash below; its
# executable bit is not part of the production-stage contract.
preflight_check 'production stage directory' "$stage" directory
preflight_check 'staged production provisioner' "$provision" file
preflight_check 'production pending marker' "$pending" file
preflight_check 'Anaconda reboot hand-off marker' "$reboot_requested" file
install -D -m 0644 /dev/null "$reboot_confirmed"
preflight_check 'staged payload manifest' "$stage/payload.sha256" readable
preflight_check 'staged offline manifest' "$stage/offline/manifest.json" readable
payload_check="$stage/payload-check.txt"
printf 'GREYWARD first-boot: validating staged payload checksums\n'
if ! (cd "$stage" && sha256sum --quiet -c payload.sha256 >"$payload_check" 2>&1); then
  report 'Payload integrity check failed. Failed entries follow.'
  sed -n '1,40p' "$payload_check"
  report "Full payload diagnostic: $payload_check"
  exit 1
fi
rm -f "$payload_check"

# Do not allow either Fedora Initial Setup implementation to compete with the
# account page that the user just completed in Anaconda. This is intentionally
# done on the installed target, never in the installer stage2 before Anaconda
# has finished configuring its systemd units.
for unit in initial-setup.service initial-setup-reconfiguration.service; do
  systemctl mask "$unit"
done
for unit in gnome-initial-setup.service gnome-initial-setup-first-login.service \
  gnome-initial-setup-copy-worker.service; do
  systemctl --global mask "$unit"
done

# The production provisioner is the sole owner of packages, services, the
# GREYWARD session, and Security Center integration. It is retry-safe: a
# failure leaves this service and its stage in place while greetd remains
# gated, so systemd can retry instead of exposing a half-configured desktop.
report 'Preparing GREYWARD and included applications. Keep this device connected to power. No internet is needed.'
GREYWARD_OFFLINE_INSTALL=1 GREYWARD_PRODUCTION_STAGE="$stage" bash "$provision"
if [[ -r "$stage/artifacts/runtime-baseline.json" ]]; then
  report 'Verifying the selected GREYWARD baseline'
  python3 "$stage/baseline.py" verify --baseline "$stage/artifacts/runtime-baseline.json"
  install -D -m 0644 "$stage/artifacts/runtime-baseline.json" /usr/share/greyward/artifacts/runtime-baseline.json
fi
install -D -m 0644 "$stage/offline/manifest.json" /usr/share/greyward/artifacts/offline-payload.json
install -D -m 0644 "$stage/offline/flatpak-inventory.tsv" /usr/share/greyward/artifacts/offline-flatpak-inventory.tsv

# Read back the installed contract before opening the login boundary. The
# acceptance script checks actual RPMs, services, files, session entries,
# encryption, and Security Center artifacts rather than trusting exit status.
report 'Checking the installed system'
install -D -m 0644 /dev/null "$ready"
rm -f /etc/greyward-production-complete
timeout --foreground 10m /usr/local/libexec/greyward-production-acceptance --pre-marker
install -D -m 0644 /dev/null /etc/greyward-production-complete
report 'Final checks passed. Starting GREYWARD login screen.'

# Release only the greetd gate while the pending marker and tty1 status
# service remain in place. If the compositor fails, the stage and retry
# boundary must survive so the diagnostic is actionable and a retry is safe.
rm -f /etc/systemd/system/greetd.service.d/greyward-production-firstboot.conf
systemctl daemon-reload
# greetd may already have attempted to start while the production gate was
# active and therefore be left in a failed state. Removing the drop-in does not
# re-run that failed job, so explicitly release and start the login boundary.
systemctl reset-failed greetd.service 2>/dev/null || true
if ! timeout --foreground 120s systemctl start greetd.service; then
  report 'GREYWARD login service did not start within 120 seconds.'
  exit 1
fi
if ! timeout --foreground 30s systemctl is-active --quiet greetd.service; then
  report 'GREYWARD login service did not become active.'
  exit 1
fi
# A running greetd daemon is not sufficient evidence of a usable graphical
# login: greetd can remain active while its dms-greeter/labwc child exits. Wait
# briefly for both children and preserve the actual journal if VMware's DRM
# path still rejects the compositor.
rm -f "$greetd_failure"
greeter_ready=false
for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if pgrep -u greeter -x dms-greeter >/dev/null 2>&1 &&
     pgrep -u greeter -x labwc >/dev/null 2>&1; then
    greeter_ready=true
    break
  fi
  sleep 1
done
if [[ "$greeter_ready" != true ]]; then
  {
    printf 'GREYWARD login boundary failed to produce dms-greeter and labwc.\n'
    printf '\n[greetd status]\n'
    systemctl status --no-pager --full greetd.service || true
    printf '\n[greetd journal]\n'
    journalctl --no-pager -b -u greetd.service -n 80 || true
  } > "$greetd_failure"
  report 'GREYWARD login screen did not start. Diagnostic: /var/lib/greyward/installer/greetd-failure.txt'
  cat "$greetd_failure"
  plymouth quit 2>/dev/null || true
  chvt 1 2>/dev/null || true
  exit 1
fi

# The installed system is now proven to have a live GREYWARD login boundary.
# Only this commit point may remove the retry marker, diagnostic stage, and
# tty1/getty gate. Any earlier failure must leave all of them intact.
report 'GREYWARD login screen is ready.'
rm -f "$pending"
rm -rf "$stage"
rm -f \
  /etc/systemd/system/getty@tty1.service.d/greyward-production-firstboot.conf \
  /etc/systemd/system/initial-setup.service.d/greyward-production-firstboot.conf
systemctl daemon-reload
systemctl disable --now greyward-firstboot-status.service 2>/dev/null || true
systemctl disable greyward-production-firstboot.service 2>/dev/null || true
sync
