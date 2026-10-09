#!/bin/bash
# Private headless source-binary check. No enrollment or installed desktop change.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
case "${1:-}" in ''|--confined|--workflow) ;; *) exit 2;; esac
confined=false
reuse=false
guard_setup=false
ui_module=false
if test "${1:-}" = --confined; then confined=true; fi
if test "${1:-}" = --workflow; then confined=true; reuse=true; fi
test "$(id -u greyward-guard-probe)" = 1002
test "$(id -G greyward-guard-probe)" = 1002
if ! $reuse && pgrep -u 1002 >/dev/null; then echo 'The separate probe account is busy' >&2; exit 1; fi
if $reuse; then
    test "$(sudo -n stat -c '%u %a' /etc/greyward/application-security-development.json)" = '0 644'
    test "$(/usr/bin/busctl --timeout=6 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s systems.mantis.greyward.ApplicationSecurityDevelopment1)" = 'b true'
    test "$(sudo -n semanage login -l | awk '$1 == "greyward-guard-probe" {print $2}')" = greyward_guard_u
fi
test "$(/usr/bin/busctl --address=unix:path=/run/dbus/system_bus_socket --timeout=6 call \
    org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s \
    systems.mantis.greyward.ApplicationSecurity1)" = 'b false'
stage=/var/tmp/greyward-application-security-probe
source_binary=/var/tmp/greyward-application-security-build/security-center/target/debug/greyward-security-center
state=/var/lib/greyward-development/application-security/ui-session
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    sudo -n systemctl stop greyward-application-security-ui-check.service >/dev/null 2>&1
    sudo -n rm -f -- /usr/local/libexec/greyward-application-security-ui-context-python
    if $reuse; then
        sudo -n restorecon /usr/local/libexec/greyward-application-security-center-probe || result=1
        sudo -n restorecon -R "$state" || result=1
        if $ui_module; then sudo -n semodule -r greyward_ui_probe || result=1; fi
    fi
    if $guard_setup; then
        sudo -n loginctl terminate-user greyward-guard-probe >/dev/null 2>&1
        sudo -n restorecon /usr/local/libexec/greyward-application-security-center-probe || result=1
        sudo -n restorecon -R "$state" || result=1
        if $ui_module; then sudo -n semodule -r greyward_ui_probe || result=1; fi
        sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || result=1
    fi
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    test "$(getenforce)" = Enforcing || result=1
    exit "$result"
}
trap cleanup EXIT
if $confined; then
    build=$(mktemp -d /var/tmp/greyward-application-security-build/ui-policy.XXXXXX)
    cp "$stage/greyward_ui_probe.te" "$build/"
    systemd-run --user --wait --pipe --collect --unit=greyward-appsec-ui-policy-build \
        -p "WorkingDirectory=$build" -p RuntimeMaxSec=120 -p MemoryMax=512M -p CPUQuota=100% \
        /usr/bin/make -f /usr/share/selinux/devel/Makefile greyward_ui_probe.pp
    if ! $reuse; then
        guard_setup=true
        sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
    fi
    sudo -n semodule -i "$build/greyward_ui_probe.pp"
    ui_module=true
fi
sudo -n test ! -L "$state"
if sudo -n test -e "$state"; then test "$(sudo -n stat -c '%u %a' "$state")" = '1002 700'; fi
sudo -n install -d -o 1002 -g 1002 -m0700 "$state"
for directory in runtime home config config/labwc state cache; do
    sudo -n test ! -L "$state/$directory"
    if sudo -n test -e "$state/$directory"; then test "$(sudo -n stat -c '%u' "$state/$directory")" = 1002; fi
    sudo -n install -d -o 1002 -g 1002 -m0700 "$state/$directory"
done
for file in session-bus.conf config/labwc/rc.xml config/labwc/autostart; do
    sudo -n test ! -L "$state/$file"
    if sudo -n test -e "$state/$file"; then test "$(sudo -n stat -c '%u %h' "$state/$file")" = '0 1'; fi
done
for name in ui-session.sh ui-probe.mjs ui-context.py; do
    sudo -n install -m0755 "$stage/application-security-$name" "/usr/local/libexec/greyward-application-security-$name"
done
sudo -n install -m0755 "$source_binary" /usr/local/libexec/greyward-application-security-center-probe
sudo -n test ! -e /usr/local/libexec/greyward-application-security-ui-context-python
sudo -n test ! -L /usr/local/libexec/greyward-application-security-ui-context-python
sudo -n install -m0555 /usr/bin/python3 /usr/local/libexec/greyward-application-security-ui-context-python
sudo -n install -m0755 "$HOME/.cargo/bin/tauri-driver" /usr/local/libexec/greyward-application-security-ui-driver
sudo -n restorecon /usr/local/libexec/greyward-application-security-{ui-session.sh,ui-probe.mjs,ui-context.py,center-probe,ui-driver}
context_source=/var/tmp/greyward-application-security-build/security-center/security-context/greyward_security_context
context_copy=/usr/local/lib/greyward-application-security-ui-context-source
for directory in "$context_copy" "$context_copy/greyward_security_context"; do
    sudo -n test ! -L "$directory"
    if sudo -n test -e "$directory"; then
        test "$(sudo -n stat -c '%u %a' "$directory")" = '0 755'
    fi
    sudo -n install -d -m0755 "$directory"
done
for source in "$context_source"/*.py; do
    name=$(basename "$source")
    case "$name" in *[!a-z0-9_.]*) exit 2;; esac
    destination=$context_copy/greyward_security_context/$name
    sudo -n test ! -L "$destination"
    if sudo -n test -e "$destination"; then test "$(sudo -n stat -c '%u %h' "$destination")" = '0 1'; fi
    sudo -n install -m0644 "$source" "$destination"
done
sudo -n restorecon -R "$context_copy"
# No activation directories: this private bus cannot spawn installed session
# providers or use the active account's Context/notification owner.
cat > "$stage/ui-session-bus.conf" <<'EOF'
<busconfig><type>session</type><listen>unix:path=/run/greyward-application-security-ui/runtime/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="1002"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>
EOF
sudo -n install -m0444 "$stage/ui-session-bus.conf" "$state/session-bus.conf"
printf '<labwc_config><core><decoration>server</decoration></core></labwc_config>\n' > "$stage/ui-labwc-rc.xml"
sudo -n install -m0444 "$stage/ui-labwc-rc.xml" "$state/config/labwc/rc.xml"
printf '#!/bin/sh\n' > "$stage/ui-labwc-autostart"
sudo -n install -m0555 "$stage/ui-labwc-autostart" "$state/config/labwc/autostart"
context=unconfined_u:unconfined_r:unconfined_t:s0
if $confined; then
    context=greyward_guard_u:greyward_guard_r:greyward_ui_probe_driver_t:s0
    sudo -n chcon -t greyward_ui_probe_application_exec_t /usr/local/libexec/greyward-application-security-center-probe
    sudo -n chcon -t greyward_ui_probe_application_exec_t /usr/local/libexec/greyward-application-security-ui-context-python
    sudo -n chcon -R -t user_home_t "$state"
    # Match a session runtime directory; the private session bus transitions
    # into its confined dbusd domain and cannot create sockets in home content.
    sudo -n chcon -R -t user_tmp_t "$state/runtime"
fi
ui_domain=unconfined_t
if $confined; then ui_domain=greyward_guard_t; fi
sha256sum "$source_binary"
sudo -n systemd-run --wait --pipe --collect --unit=greyward-application-security-ui-check \
    -p User=greyward-guard-probe -p Group=greyward-guard-probe \
    -p RuntimeMaxSec=90 -p TimeoutStopSec=3 -p MemoryMax=1G -p CPUQuota=100% -p TasksMax=128 \
    -p PrivateNetwork=yes -p PrivateTmp=yes -p ProtectHome=yes -p ProtectSystem=strict \
    -p "BindPaths=$state:/run/greyward-application-security-ui" \
    -p ReadWritePaths=/run/greyward-application-security-ui \
    -p "SELinuxContext=$context" \
    -E "GREYWARD_UI_EXPECTED_DOMAIN=$(printf '%s' "$context" | cut -d: -f3)" \
    -E "GREYWARD_UI_APPLICATION_DOMAIN=$ui_domain" \
    -E "GREYWARD_UI_WORKFLOW=$reuse" \
    -E HOME=/run/greyward-application-security-ui/home -E PATH=/usr/bin:/bin \
    /bin/bash /usr/local/libexec/greyward-application-security-ui-session.sh
