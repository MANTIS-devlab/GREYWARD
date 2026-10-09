#!/bin/bash
# Development-only extracted RPM check, never installed/enabled protection.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
stage=/var/tmp/greyward-application-security-probe
package=$(realpath "${1:?Pass the privately extracted experimental RPM directory}")
case "$package" in /var/tmp/greyward-application-security-build/rpm-read-broker.*/extracted.*) ;; *) exit 2;; esac
test -f "$package/usr/lib/systemd/system/greyward-application-security.service"
test -f "$package/usr/libexec/greyward-application-security"
test "$(stat -c %u "$package")" = "$(id -u)"
sudo -n test ! -e /etc/dbus-1/system.d/greyward-application-security-package-probe.conf
sudo -n test ! -e /run/systemd/system/greyward-application-security-rpm-mac-probe.service
test "$(systemctl --user is-active greyward-dms.service)" = active
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
build=$(mktemp -d /var/tmp/greyward-application-security-build/broker-policy.XXXXXX)
cp "$stage/greyward_application_broker_probe.te" "$build/"
systemd-run --user --wait --pipe --collect --unit=greyward-appsec-policy-build \
    -p "WorkingDirectory=$build" -p RuntimeMaxSec=180 -p CPUQuota=100% \
    -p MemoryMax=512M make -f /usr/share/selinux/devel/Makefile greyward_application_broker_probe.pp
fixture=/var/lib/greyward-development/application-security/rpm-mac-storage-probe
guard_setup=false
broker_installed=false
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    local cleanup_failed=0
    sudo -n systemctl stop greyward-application-security-rpm-mac-probe.service \
        greyward-application-security-mac-test.service >/dev/null 2>&1 || true
    sudo -n rm -f /run/systemd/system/greyward-application-security-rpm-mac-probe.service \
        /etc/dbus-1/system.d/greyward-application-security-package-probe.conf
    sudo -n systemctl daemon-reload || cleanup_failed=1
    sudo -n busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig >/dev/null || cleanup_failed=1
    sudo -n restorecon /usr/local/libexec/greyward-application-security-package-probe \
        /usr/local/libexec/greyward-application-security-mac-test \
        /usr/local/libexec/greyward-application-security-fd-driver || cleanup_failed=1
    if sudo -n test -d "$fixture"; then sudo -n restorecon -R "$fixture" || cleanup_failed=1; fi
    if $broker_installed; then sudo -n semodule -r greyward_application_broker_probe || cleanup_failed=1; fi
    if $guard_setup; then sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || cleanup_failed=1; fi
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || cleanup_failed=1
    test "$(getenforce)" = Enforcing || cleanup_failed=1
    if test "$cleanup_failed" = 1; then echo 'Probe cleanup requires recovery' >&2; result=1; fi
    exit "$result"
}
trap cleanup EXIT
# All privileged copies are reviewed executables/configuration, never Cargo.
sudo -n install -m0755 "$package/usr/libexec/greyward-application-security" \
    /usr/local/libexec/greyward-application-security-package-probe
sudo -n install -m0755 /usr/local/libexec/greyward-application-security-mac-test \
    /usr/local/libexec/greyward-application-security-fd-driver
sudo -n restorecon /usr/local/libexec/greyward-application-security-fd-driver
guard_setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
sudo -n semodule -i "$build/greyward_application_broker_probe.pp"
broker_installed=true
sudo -n chcon -t greyward_application_broker_exec_t \
    /usr/local/libexec/greyward-application-security-package-probe \
    /usr/local/libexec/greyward-application-security-mac-test
sudo -n chcon -t greyward_application_fd_driver_exec_t /usr/local/libexec/greyward-application-security-fd-driver
sudo -n test ! -L "$fixture"
sudo -n install -d -m0700 "$fixture"
sudo -n test "$(sudo -n stat -c %u "$fixture")" = 0
sudo -n chcon -R -t greyward_application_broker_state_t "$fixture"
sudo -n install -m0644 "$package/usr/share/dbus-1/system.d/systems.mantis.greyward.ApplicationSecurity1.conf" \
    /etc/dbus-1/system.d/greyward-application-security-package-probe.conf
sudo -n busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
sed -e 's|^ExecStart=.*|ExecStart=/usr/local/libexec/greyward-application-security-package-probe|' \
    -e 's|^StateDirectory=.*|StateDirectory=|' \
    -e 's|^RuntimeDirectory=.*|RuntimeDirectory=greyward-application-security-rpm-mac-probe|' \
    "$package/usr/lib/systemd/system/greyward-application-security.service" > "$build/unit"
printf '\nRuntimeMaxSec=60\nTemporaryFileSystem=/var/lib/greyward\nBindPaths=%s:/var/lib/greyward/application-security\n' "$fixture" >> "$build/unit"
sudo -n install -m0644 "$build/unit" /run/systemd/system/greyward-application-security-rpm-mac-probe.service
sudo -n systemctl daemon-reload
sudo -n systemctl start greyward-application-security-rpm-mac-probe.service
busctl call systems.mantis.greyward.ApplicationSecurity1 /systems/mantis/greyward/ApplicationSecurity1 \
    systems.mantis.greyward.ApplicationSecurity1 GetCoverage
busctl call systems.mantis.greyward.ApplicationSecurity1 /systems/mantis/greyward/ApplicationSecurity1 \
    systems.mantis.greyward.ApplicationSecurity1 ListApplications ubts 10 false 0 ''
PYTHONPATH=/var/tmp/greyward-application-security-build/security-center/security-context /usr/bin/python3 - <<'PY'
import json
from greyward_security_context.application_security import ApplicationSecurityReads, ApplicationReadError
reads = ApplicationSecurityReads()
coverage = reads.coverage()
assert coverage["source_state"]["state"] == "AVAILABLE", coverage["source_state"]
assert coverage["projection"]["protection"]["health"] == "UNKNOWN"
assert coverage["projection"]["protection"]["effective_profile"] is None
page = reads.applications(10)
assert page["source_state"]["state"] == "AVAILABLE", page["source_state"]
assert page["projection"]["inventory_health"] == "UNKNOWN"
assert page["projection"]["applications"] == []
missing = reads.application("installation_" + "a" * 64)
assert missing["source_state"]["state"] == "AVAILABLE", missing["source_state"]
assert missing["projection"]["application"] is None
try:
    reads.application("../secret")
except ApplicationReadError:
    pass
else:
    raise AssertionError("Path-shaped identifier reached the broker")
print(json.dumps({"schema":"greyward.application-security.context-probe/v1",
                  "typed_root_reads":True, "enforcement_health":"UNKNOWN", "protection_claimed":False}))
PY
pid=$(sudo -n systemctl show -p MainPID --value greyward-application-security-rpm-mac-probe.service)
context=$(sudo -n cat "/proc/$pid/attr/current" | tr -d '\000')
test "${context%%:*}" = system_u
test "$(printf '%s' "$context" | cut -d: -f3)" = greyward_application_broker_t
sudo -n stat -c '%u %a %C' "$fixture/policy.sqlite3"
test "$(sudo -n stat -c '%u %a' "$fixture/policy.sqlite3")" = '0 600'
sudo -n test ! -e /var/lib/greyward/application-security/policy.sqlite3
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-mac-test \
    -p RuntimeMaxSec=30 -p NoNewPrivileges=yes \
    -p 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' \
    /usr/local/libexec/greyward-application-security-mac-test --ignored --exact \
    root_broker_domain_can_read_process_metadata_but_not_synthetic_credentials --nocapture
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-mac-test \
    -p RuntimeMaxSec=30 -p NoNewPrivileges=yes \
    -p 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' \
    /usr/local/libexec/greyward-application-security-mac-test --ignored --exact \
    root_broker_installed_metadata_collection_retains_credential_denial --nocapture
# Systemd/system D-Bus refuse credential FDs. A separate fixed recovery-side
# driver opens only the synthetic fixture, then selects the broker child domain.
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-mac-test \
    -p RuntimeMaxSec=30 -p NoNewPrivileges=yes \
    -p CapabilityBoundingSet=CAP_DAC_READ_SEARCH \
    /usr/local/libexec/greyward-application-security-fd-driver --ignored --exact \
    recovery_descriptor_is_denied_after_a_broker_domain_transition --nocapture
printf 'EXTRACTED_MAC_READ_AND_SECRET_DENIAL_PASS\n'
