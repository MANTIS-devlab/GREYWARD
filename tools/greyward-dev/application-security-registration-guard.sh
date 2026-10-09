#!/bin/bash
# Fixed fresh-owner continuation under the separate enrolled probe account.
set -euo pipefail
stage=/var/tmp/greyward-application-security-probe
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
test "$(id -u greyward-guard-probe)" = 1002
if pgrep -u 1002 >/dev/null; then echo 'Probe account is busy' >&2; exit 1; fi
for module in greyward_grant_access_critical greyward_grant_context_critical greyward_registration_critical; do
    if sudo -n semodule -l | awk -v name="$module" '$1 == name {found=1} END {exit !found}'; then
        echo 'A previous private policy is still installed; refusing a new fixture' >&2; exit 1
    fi
done
desktop_pid=$(systemctl --user show -p MainPID --value greyward-dms.service)
setup=false
critical=false
grants=false
transport=false
transport_policy=/etc/dbus-1/system.d/greyward-application-security-workflow-probe.conf
transport_installed=false
transport_started=false
native_worker_installed=false
display_helper_installed=false
context_fixture_installed=false
context_fixture=/usr/local/lib/greyward-application-security-product-context
case "${1:-}" in
    '') test "$#" = 0 ;;
    --end-to-end) test "$#" = 1; critical=true; grants=true ;;
    --workflow) test "$#" = 1; critical=true; grants=true; transport=true ;;
    *) exit 2 ;;
esac
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    if $transport_started; then
        sudo -n systemctl stop greyward-appsec-development-workflow.service >/dev/null 2>&1
    fi
    if $native_worker_installed; then sudo -n rm -f -- /usr/libexec/greyward-native-worker || result=1; fi
    if $display_helper_installed; then sudo -n rm -f -- /usr/libexec/greyward-wayland-context || result=1; fi
    if $context_fixture_installed; then
        sudo -n rm -f -- /etc/greyward/application-security-development.json /usr/local/libexec/greyward-application-security-product-context.py
        for name in __init__.py application_security.py application_workflows.py telemetry.py findings.py safe_open.py; do
            sudo -n rm -f -- "$context_fixture/greyward_security_context/$name"
        done
        sudo -n rmdir "$context_fixture/greyward_security_context" "$context_fixture" || result=1
    fi
    sudo -n systemctl stop greyward-appsec-product-display.service >/dev/null 2>&1
    if $transport_installed; then
        sudo -n rm -f -- "$transport_policy"
        sudo -n busctl --timeout=6 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig >/dev/null || result=1
    fi
    for suffix in control direct unknown tool bypass holder; do
        sudo -n systemctl stop "greyward-appsec-critical-$suffix.service" >/dev/null 2>&1
    done
    # logind's normal user-manager stop delay survives the private PAM display
    # session briefly. Wait for that owned account before removing its policy.
    for attempt in {1..120}; do
        if ! pgrep -u 1002 >/dev/null; then break; fi
        sleep 0.1
    done
    if $critical; then
        sudo -n restorecon -R /home/greyward-guard-probe/registration-critical || result=1
        for module in greyward_grant_access_critical greyward_grant_context_critical greyward_registration_critical greyward_managed_grant_probe; do
            if sudo -n semodule -l | awk -v name="$module" '$1 == name {found=1} END {exit !found}'; then
                sudo -n semodule -r "$module" || result=1
            fi
        done
    fi
    if $setup; then sudo -n bash "$stage/application-security-feasibility.sh" rollback "$stage" || result=1; fi
    test "$(getenforce)" = Enforcing || result=1
    test "$(systemctl --user show -p MainPID --value greyward-dms.service)" = "$desktop_pid" || result=1
    if pgrep -u 1002 >/dev/null; then result=1; fi
    exit "$result"
}
trap cleanup EXIT
if $grants; then
    source=/var/tmp/greyward-application-security-build/security-center
    build=$(mktemp -d /var/tmp/greyward-application-security-build/critical-policy.XXXXXXXX)
    cp "$stage/greyward_managed_grant_probe.te" "$build/"
    systemd-run --user --quiet --wait --pipe --collect --unit=greyward-appsec-critical-build \
        -p RuntimeMaxSec=180 -p MemoryMax=1G -p CPUQuota=100% -p "WorkingDirectory=$source" \
        -E PATH=/usr/bin:/bin -E RUSTC=/usr/bin/rustc -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
        /usr/bin/cargo build -p greyward-application-security --example reviewed-tool-check --offline --locked
    binary=$source/target/debug/examples/reviewed-tool-check
    sha256sum "$binary"
    sudo -n install -m0755 "$binary" /usr/local/libexec/greyward-application-security-reviewed-tool
    sudo -n restorecon /usr/local/libexec/greyward-application-security-reviewed-tool
    for helper in application-security-tty.py application-security-critical-session.py application-security-critical-headless.sh; do
        sudo -n install -m0755 "$stage/$helper" "/usr/local/libexec/greyward-$helper"
        sudo -n restorecon "/usr/local/libexec/greyward-$helper"
    done
    systemd-run --user --quiet --wait --pipe --collect --unit=greyward-appsec-critical-policy-build \
        -p RuntimeMaxSec=90 -p MemoryMax=512M -p CPUQuota=100% -p "WorkingDirectory=$build" \
        /usr/bin/make -f /usr/share/selinux/devel/Makefile greyward_managed_grant_probe.pp
fi
setup=true
sudo -n bash "$stage/application-security-feasibility.sh" setup "$stage"
if $grants; then sudo -n semodule -i "$build/greyward_managed_grant_probe.pp"; fi
if $transport; then
    /usr/bin/python3 -I "$stage/application-security-product-fixtures.py" prepare /var/tmp/greyward-application-security-build/product-fixtures
    sudo -n /usr/bin/python3 -I "$stage/application-security-product-fixtures.py" install /var/tmp/greyward-application-security-build/product-fixtures
    helper_build=$source/target/private-display-helper
    mkdir -p "$helper_build"
    (
        cd "$helper_build"
        wayland-scanner client-header "$source/packaging/application-security/wayland/security-context-v1.xml" security-context-v1-client-protocol.h
        wayland-scanner private-code "$source/packaging/application-security/wayland/security-context-v1.xml" security-context-v1-protocol.c
        gcc -O2 -Wall -Wextra -Werror -I. "$source/packaging/application-security/wayland/context.c" security-context-v1-protocol.c $(pkg-config --cflags --libs wayland-client) -o greyward-wayland-context
    )
    sudo -n test ! -e /usr/libexec/greyward-wayland-context
    sudo -n install -m0755 "$helper_build/greyward-wayland-context" /usr/libexec/greyward-wayland-context
    display_helper_installed=true
    sudo -n restorecon /usr/libexec/greyward-wayland-context
    sudo -n test ! -e "$context_fixture"
    sudo -n test ! -L "$context_fixture"
    sudo -n test ! -e /etc/greyward/application-security-development.json
    sudo -n test ! -L /etc/greyward/application-security-development.json
    sudo -n install -d -m0755 "$context_fixture/greyward_security_context"
    context_fixture_installed=true
    for name in __init__.py application_security.py application_workflows.py telemetry.py findings.py safe_open.py; do
        sudo -n install -m0644 "$source/security-context/greyward_security_context/$name" "$context_fixture/greyward_security_context/$name"
    done
    sudo -n install -m0755 "$stage/application-security-product-context.py" /usr/local/libexec/greyward-application-security-product-context.py
    printf '{"schema":"greyward.application-security/v1","development_uid":1002}\n' | sudo -n tee /etc/greyward/application-security-development.json >/dev/null
    sudo -n chmod 0644 /etc/greyward/application-security-development.json
    sudo -n restorecon -R "$context_fixture" /usr/local/libexec/greyward-application-security-product-context.py
fi
if $critical; then
    sudo -n /usr/bin/python3 -I - <<'PY'
import os, pathlib, stat, time
base=pathlib.Path('/home/greyward-guard-probe/registration-critical')
state=pathlib.Path('/var/lib/greyward-development/application-security/registration-critical')
for path,uid,mode in [(base,1002,0o700),(base/'nested',1002,0o700),(state,0,0o700),(state/'content',0,0o700)]:
    if path.exists():
        m=path.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid!=uid:
            raise SystemExit('Refusing changed synthetic fixture')
    else:
        path.mkdir(mode=mode)
        os.chown(path,uid,uid)
entry=pathlib.Path('/usr/libexec/greyward-guard-entry')
if entry.exists():
    m=entry.lstat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_gid!=0 or m.st_nlink!=1 or m.st_size!=0 or stat.S_IMODE(m.st_mode)!=0o555:
        raise SystemExit('Refusing a changed launch entrypoint')
else:
    fd=os.open(entry,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o555)
    os.close(fd)
    entry.chmod(0o555)
database=state/'policy.sqlite3'
if database.exists():
    m=database.lstat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_nlink!=1 or stat.S_IMODE(m.st_mode)!=0o600:
        raise SystemExit('Refusing changed private policy database')
    database.rename(state/f'policy-{time.time_ns()}.sqlite3')
configuration=pathlib.Path('/etc/selinux/semanage.conf').read_text()
if configuration.count('expand-check=0')!=1:
    raise SystemExit('Changed Fedora compilation contract')
config=state/'semanage.conf'
if config.is_symlink(): raise SystemExit('Unsafe private configuration')
config.write_text(configuration.replace('expand-check=0','expand-check=1'))
config.chmod(0o600)
for name in ['greyward_registration_critical','greyward_grant_context_critical','greyward_grant_access_critical']:
    cil=state/(name+'.cil')
    if cil.exists():
        m=cil.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_gid!=0 or m.st_nlink!=1:
            raise SystemExit('Refusing changed private compiler input')
        # The account is empty and the corresponding kernel modules were
        # verified absent above. Archive this completed test's compiler input;
        # do not retain its retired subject cache into a fresh fixture.
        cil.rename(state/f'{name}-{time.time_ns()}.cil')
for path in [base/'synthetic',base/'nested'/'synthetic']:
    if path.exists():
        m=path.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=1002 or m.st_nlink!=1:
            raise SystemExit('Refusing changed synthetic object')
    else:
        with path.open('x') as stream: stream.write('synthetic registration data')
        path.chmod(0o600)
        os.chown(path,1002,1002)
PY
    sudo -n restorecon -R /home/greyward-guard-probe/registration-critical
    if $transport; then
        sudo -n test ! -e "$transport_policy"
        sudo -n test ! -L "$transport_policy"
        test "$(busctl --timeout=6 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s systems.mantis.greyward.ApplicationSecurityDevelopment1)" = 'b false'
        systemd-run --user --quiet --wait --pipe --collect --unit=greyward-appsec-workflow-build \
            -p RuntimeMaxSec=180 -p MemoryMax=1G -p CPUQuota=100% -p "WorkingDirectory=$source" \
            -E PATH=/usr/bin:/bin -E RUSTC=/usr/bin/rustc -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
            /usr/bin/cargo build -p greyward-application-security --bins --offline --locked
        if sudo -n test -e /usr/libexec/greyward-native-worker || sudo -n test -L /usr/libexec/greyward-native-worker; then
            sudo -n cmp "$source/target/debug/greyward-native-worker" /usr/libexec/greyward-native-worker
        else
            sudo -n install -m0755 "$source/target/debug/greyward-native-worker" /usr/libexec/greyward-native-worker
            native_worker_installed=true
            sudo -n restorecon /usr/libexec/greyward-native-worker
        fi
        sudo -n install -m0755 "$source/target/debug/greyward-application-security-development" /usr/local/libexec/greyward-appsec-development-workflow
        sudo -n restorecon /usr/local/libexec/greyward-appsec-development-workflow
        sudo -n install -m0644 "$source/packaging/application-security/systems.mantis.greyward.ApplicationSecurityDevelopment1.conf" "$transport_policy"
        transport_installed=true
        sudo -n busctl --timeout=6 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
        transport_started=true
        sudo -n systemd-run --quiet --unit=greyward-appsec-development-workflow --collect \
            -p RuntimeMaxSec=180 -p TimeoutStopSec=3 -p MemoryMax=512M -p TasksMax=64 -p CPUQuota=100% \
            -p SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0 \
            /usr/local/libexec/greyward-appsec-development-workflow
        bash "$stage/application-security-policy-intent.sh" --workflow
    else
        bash "$stage/application-security-policy-intent.sh" --end-to-end
    fi
else
    bash "$stage/application-security-policy-intent.sh" --confined
fi
