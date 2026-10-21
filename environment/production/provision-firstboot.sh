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

# Retain the original failure across retries; journal and text evidence agree.
install -d -m 0755 /var/log
touch "$log"
chmod 0644 "$log"
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
greeter_is_running() {
  # dms-greeter 1.6.2 execs Labwc; its launcher name no longer exists after
  # startup. Check both the compositor and its Quickshell UI as the greeter.
  # This is startup evidence only, never protected-session coverage.
  pgrep -u greeter -x labwc >/dev/null 2>&1 &&
    pgrep -u greeter -x 'qs|quickshell' >/dev/null 2>&1
}
protected_session_is_ready() {
  local session_id account_uid account_name seat remainder result sessions
  sessions=$(loginctl list-sessions --no-legend --no-pager) || return 1
  while read -r session_id account_uid account_name seat remainder; do
    [[ "$account_uid" =~ ^[0-9]+$ && "$account_uid" -ge 1000 &&
       "$account_name" != greeter && "$seat" == seat0 ]] || continue
    # A general Labwc or DMS process is not proof of the admitted desktop.
    # Reuse the existing root-only, generation-bound live seat verifier.
    if result=$(timeout --kill-after=1 3 /usr/bin/python3 -I \
        /usr/lib/greyward/application-security/desktop/verify.py "$account_uid"); then
      [[ "$result" == '{"verified": true}' ]] && return 0
    fi
  done <<< "$sessions"
  return 1
}
report_enrollment_workloads() {
  local account_uid proc uid process found=false
  local -a account_uids=()
  mapfile -t account_uids < <(awk -F: '$3 >= 1000 && $6 ~ /^\/home\// { print $3 }' /etc/passwd)
  [[ ${#account_uids[@]} -gt 0 ]] || return 0
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/status" ]] || continue
    uid=$(awk '/^Uid:/ { print $3; exit }' "$proc/status" 2>/dev/null) || continue
    for account_uid in "${account_uids[@]}"; do
      [[ "$uid" == "$account_uid" ]] || continue
      if [[ "$found" != true ]]; then
        printf 'GREYWARD first-boot: account processes present when enrollment refused:\n'
        found=true
      fi
      process=$(tr -d '\n' < "$proc/comm" 2>/dev/null || printf 'unavailable')
      printf 'GREYWARD first-boot: enrollment blocker uid=%s pid=%s process=%s\n' \
        "$uid" "${proc##*/}" "${process:-unknown}"
      break
    done
  done
  if [[ "$found" != true ]]; then
    printf 'GREYWARD first-boot: no account processes remained when enrollment failure was collected\n'
  fi
}
stop_idle_installer_user_managers() {
  local account_uid sessions manager manager_state
  local -a account_uids=()
  mapfile -t account_uids < <(awk -F: '$3 >= 1000 && $6 ~ /^\/home\// { print $3 }' /etc/passwd)
  sessions=$(loginctl list-sessions --no-legend --no-pager) || {
    printf 'GREYWARD first-boot: cannot verify logind sessions before enrollment\n'
    return 1
  }
  for account_uid in "${account_uids[@]}"; do
    # Do not terminate a real login session. A surviving user manager with no
    # logind session is a setup-time PAM residue; stopping just that manager
    # lets enrollment make its account mapping change before first login.
    if awk -v uid="$account_uid" '$2 == uid { found=1 } END { exit(found ? 0 : 1) }' \
       <<< "$sessions"; then
      printf 'GREYWARD first-boot: refusing enrollment cleanup; uid=%s still has a logind session\n' \
        "$account_uid"
      return 1
    fi
    manager="user@$account_uid.service"
    manager_state=$(systemctl show --property=ActiveState --value "$manager") || {
      printf 'GREYWARD first-boot: cannot inspect %s before enrollment\n' "$manager"
      return 1
    }
    if [[ "$manager_state" == active || "$manager_state" == activating || "$manager_state" == deactivating ]]; then
      printf 'GREYWARD first-boot: stopping idle user manager for uid=%s before enrollment\n' \
        "$account_uid"
      systemctl stop "$manager"
    fi
    manager_state=$(systemctl show --property=ActiveState --value "$manager") || {
      printf 'GREYWARD first-boot: cannot verify stopped state for %s\n' "$manager"
      return 1
    }
    if [[ "$manager_state" != inactive ]]; then
      printf 'GREYWARD first-boot: %s remained in state %s\n' "$manager" "$manager_state"
      return 1
    fi
  done
}
failed() {
  local previous_status=$?
  local code="${1:-$previous_status}"
  trap - ERR
  # A failed enrollment must never fall through into an interactive desktop.
  # Keep only the text setup/recovery path available for the next boot.
  systemctl set-default multi-user.target 2>/dev/null || true
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

# The installed image starts finalization in text mode. The installer also
# seeds this default, and the provisioner preserves it while enrollment runs.
systemctl set-default multi-user.target

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
GREYWARD_OFFLINE_INSTALL=1 GREYWARD_FIRSTBOOT_FINALIZE=1 \
  GREYWARD_PRODUCTION_STAGE="$stage" bash "$provision"
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
if stop_idle_installer_user_managers; then
  :
else
  setup_status=$?
  report_enrollment_workloads
  failed "$setup_status"
fi
if /usr/libexec/greyward-enrollment prepare; then
  :
else
  enrollment_status=$?
  report_enrollment_workloads
  failed "$enrollment_status"
fi
/usr/libexec/greyward-enrollment check
# The account mapping is now committed and verified. Only now run the user
# scoped shell setup, which invokes Git as the Anaconda account. Keep this
# after prepare because enrollment intentionally refuses live account work.
mapfile -t production_users < <(awk -F: '$3 >= 1000 && $6 ~ /^\/home\// { print $1 }' /etc/passwd)
if [[ ${#production_users[@]} -eq 0 ]]; then
  printf 'GREYWARD first-boot: no installed human account is available for shell setup\n'
  exit 1
fi
for production_user in "${production_users[@]}"; do
  printf 'GREYWARD first-boot: configuring the interactive shell for %s after enrollment\n' \
    "$production_user"
  /usr/local/libexec/greyward-configure-zsh "$production_user"
done
/usr/libexec/greyward-enrollment check
install -D -m 0644 /dev/null "$ready"
rm -f /etc/greyward-production-complete
timeout --foreground 10m /usr/local/libexec/greyward-production-acceptance --pre-marker
systemctl set-default graphical.target
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
# login: greetd can remain active while its Labwc/Quickshell child exits.
# After successful authentication the greeter is replaced by the admitted
# desktop. Accept that handoff only after the existing live seat verification.
# This avoids treating a successful greeter hand-off as a delayed failure.
rm -f "$greetd_failure"
greeter_ready=false
for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if greeter_is_running; then
    greeter_ready=true
    break
  fi
  if protected_session_is_ready; then
    greeter_ready=true
    break
  fi
  sleep 1
done
if [[ "$greeter_ready" != true ]]; then
  {
    printf 'GREYWARD login boundary failed to produce a greeter or handed-off graphical session.\n'
    printf '\n[login sessions]\n'
    loginctl list-sessions --no-pager || true
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
