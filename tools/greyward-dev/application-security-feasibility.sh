#!/bin/bash
# Development-only lifecycle for the fixed, separately owned SELinux probe.
set -euo pipefail
account=greyward-guard-probe
home=/home/greyward-guard-probe
state=/var/lib/greyward-development/application-security
contexts=/etc/selinux/targeted/contexts/users/greyward_guard_u
module=greyward_guard_probe
subject=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0
owner=greyward_guard_u:greyward_guard_owner_r:greyward_guard_owner_t:s0
recovery_account=${GREYWARD_RECOVERY_ACCOUNT:?Set the existing recovery account explicitly}
recovery_home=$(getent passwd "$recovery_account" | cut -d: -f6)
test -n "$recovery_home" && test "$recovery_home" != "$home"

test "$(id -u)" = 0 || { echo 'Run this development lifecycle as root' >&2; exit 1; }
test "$(getenforce)" = Enforcing || { echo 'SELinux must remain enforcing' >&2; exit 1; }
source_dir=$(realpath "${2:-.}")

safe_state() {
    for directory in /var/lib/greyward-development "$state"; do
        test -d "$directory" && test ! -L "$directory"
        test "$(stat -c '%u' "$directory")" = 0
        test $(( 8#$(stat -c '%a' "$directory") & 022 )) = 0
    done
    test "$(stat -c '%a' "$state")" = 700
}

owned_account() {
    safe_state
    test -f "$state/account.uid" && test ! -L "$state/account.uid"
    test "$(stat -c '%u' "$state/account.uid")" = 0
    test "$(id -u "$account")" = "$(cat "$state/account.uid")"
    test "$(getent passwd "$account" | cut -d: -f6)" = "$home"
    test "$(id -u "$account")" != "$(id -u "$recovery_account")"
    test "$(id -G "$account")" = "$(id -g "$account")"
}

quiesce_user_manager() {
    # logind termination is asynchronous. Wait only for this owned account;
    # never infer process ownership from a stale PID or touch the recovery UID.
    local uid
    uid=$(id -u "$account")
    loginctl terminate-user "$account" 2>/dev/null || true
    systemctl stop --no-block "user@$uid.service" "user-runtime-dir@$uid.service" 2>/dev/null || true
    for attempt in {1..40}; do
        if ! pgrep -u "$uid" >/dev/null; then return 0; fi
        sleep 0.1
    done
    echo 'Probe account still has processes; maintenance refused' >&2
    return 1
}

case "${1:-}" in
setup)
    test -f "$source_dir/greyward_guard_probe.te"
    test -f "$source_dir/application-security-probe.py"
    test -f /usr/share/selinux/devel/Makefile
    for directory in /var/lib/greyward-development "$state"; do
        test ! -L "$directory"
        if test -e "$directory"; then
            test "$(stat -c '%u' "$directory")" = 0
        fi
        if test ! -d "$directory"; then
            install -d -m0700 "$directory"
        fi
    done
    safe_state
    if getent passwd "$account" >/dev/null; then
        owned_account || { echo 'Refusing an unowned/existing account' >&2; exit 1; }
    else
        semanage export > "$state/selinux-before-probe.txt"
        rpm -qa | sort > "$state/packages-before-probe.txt"
        useradd --create-home --user-group --shell /bin/bash "$account"
        id -u "$account" > "$state/account.uid"
        chmod 0600 "$state/account.uid"
    fi
    # Quiesce only the owned probe account before root fixture maintenance.
    # Refuse leftover processes instead of mutating a user-writable tree while
    # an adversarial probe can race its paths.
    systemctl stop greyward-guard-owner-probe.service greyward-guard-subject-probe.service greyward-guard-alias-probe.service 2>/dev/null || true
    quiesce_user_manager
    test -d "$home" && test ! -L "$home"
    test "$(realpath "$home")" = "$home"
    for directory in "$home/.ssh" "$home/protected" "$home/bound-secret"; do
        test ! -L "$directory"
        if test -e "$directory"; then test -d "$directory"; fi
    done
    for file in "$home/.ssh/authorized_keys" "$home/protected/credential" "$home/protected/agent-key" "$home/ordinary-agent-key" "$home/ordinary-agent-key.pub" "$home/ordinary.txt" "$home/unknown-cat"; do
        test ! -L "$file"
        if test -e "$file"; then
            test -f "$file" && test "$(stat -c '%u' "$file")" = "$(id -u "$account")"
        fi
    done
    test ! -L "$recovery_home/.ssh/authorized_keys"
    (cd "$source_dir"; make -f /usr/share/selinux/devel/Makefile "$module.pp")
    semodule -i "$source_dir/$module.pp"
    if semanage user -l | grep -q '^greyward_guard_u '; then
        semanage user -m -R 'greyward_guard_r greyward_guard_owner_r' -r s0 -L s0 greyward_guard_u
    else
        semanage user -a -R 'greyward_guard_r greyward_guard_owner_r' -r s0 -L s0 greyward_guard_u
    fi
    sed 's/user_r:user_t/greyward_guard_r:greyward_guard_t/g; /user_su_t/d; /user_sudo_t/d; s/ user_r:cronjob_t:s0//' \
        /etc/selinux/targeted/contexts/users/user_u > "$contexts"
    chmod 0644 "$contexts"
    if semanage login -l | grep -q '^greyward-guard-probe '; then
        semanage login -m -s greyward_guard_u -r s0 "$account"
    else
        semanage login -a -s greyward_guard_u -r s0 "$account"
    fi
    install -d -m0700 -o "$account" -g "$account" "$home/.ssh"
    # Public keys only; no recovery-account private material is copied.
    install -m0600 -o "$account" -g "$account" "$recovery_home/.ssh/authorized_keys" "$home/.ssh/authorized_keys"
    install -Dm0755 "$source_dir/application-security-probe.py" /usr/local/libexec/greyward-application-security-probe.py
    if test -f "$source_dir/application-security-routes.sh"; then
        install -Dm0755 "$source_dir/application-security-routes.sh" /usr/local/libexec/greyward-application-security-routes.sh
        restorecon /usr/local/libexec/greyward-application-security-routes.sh
    fi
    install -d -m0755 -o "$account" -g "$account" "$home/protected" "$home/bound-secret"
    printf 'synthetic credential\n' > "$home/protected/credential"
    printf 'ordinary\n' > "$home/ordinary.txt"
    cp /usr/bin/cat "$home/unknown-cat"
    chown "$account:$account" "$home/protected/credential" "$home/ordinary.txt" "$home/unknown-cat"
    chmod 0644 "$home/protected/credential" "$home/ordinary.txt"
    chmod 0755 "$home/unknown-cat"
    # Synthetic key only, generated for an actual agent/deputy positive control.
    # No existing credentials are read, and private contents are never emitted.
    if test ! -f "$home/ordinary-agent-key"; then
        ssh-keygen -q -t ed25519 -N '' -C greyward-synthetic-probe -f "$home/ordinary-agent-key"
        chown "$account:$account" "$home/ordinary-agent-key" "$home/ordinary-agent-key.pub"
    fi
    chmod 0600 "$home/ordinary-agent-key"
    install -m0600 -o "$account" -g "$account" "$home/ordinary-agent-key" "$home/protected/agent-key"
    test -L "$home/credential-link" || ln -s protected/credential "$home/credential-link"
    test -f "$home/credential-hardlink" || ln "$home/protected/credential" "$home/credential-hardlink"
    restorecon -RF "$home"
    restorecon /usr/local/libexec/greyward-application-security-probe.py
    # Only synthetic fixtures live in this fixed test directory. Re-setup also
    # labels children retained from a previous rollback rehearsal.
    chcon -R -t greyward_guard_secret_t "$home/protected"
    printf 'SETUP\n' > "$state/lifecycle"
    ;;
run|namespace)
    owned_account
    trap 'systemctl stop greyward-guard-owner-probe.service >/dev/null 2>&1 || true' EXIT
    systemd-run --quiet --collect --unit=greyward-guard-owner-probe \
        --property="User=$account" --property="Group=$account" \
        --property="SELinuxContext=$owner" --property=RuntimeMaxSec=90 --property=MemoryMax=64M \
        /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-probe.py --home "$home" --owner
    for attempt in {1..30}; do
        pid=$(systemctl show greyward-guard-owner-probe.service --property=MainPID --value)
        if test "$pid" != 0 && test -f "$home/owner.json" && \
           test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$home/owner.json")" = "$pid"; then
            break
        fi
        sleep 0.1
    done
    test "$pid" != 0
    command=(/usr/bin/python3 -I /usr/local/libexec/greyward-application-security-probe.py --home "$home")
    receipt=confined-subject.json
    if test "$1" = namespace; then
        # Namespace root maps only to UID 1002, with no new PID namespace: the
        # live owner remains visible so ptrace/proc/socket/deputy probes run.
        command=(/usr/bin/unshare --user --map-root-user --mount --net "${command[@]}")
        receipt=confined-namespace-subject.json
    fi
    systemd-run --quiet --collect --wait --pipe --unit=greyward-guard-subject-probe \
        --property="User=$account" --property="Group=$account" \
        --property="SELinuxContext=$subject" --property=RuntimeMaxSec=45 --property=MemoryMax=64M \
        "${command[@]}" | tee "$state/$receipt"
    ;;
desktop)
    owned_account
    quiesce_user_manager
    # Select only the already built development provider for this account.
    # The system provider, active desktop and production package remain intact.
    provider=/usr/local/libexec/greyward-application-security-document-portal
    test -f "$provider" && test ! -L "$provider"
    test "$(stat -c '%u' "$provider")" = 0
    test $(( 8#$(stat -c '%a' "$provider") & 022 )) = 0
    for directory in "$home/.config" "$home/.config/systemd" "$home/.config/systemd/user" "$home/.config/systemd/user/xdg-document-portal.service.d"; do
        test ! -L "$directory"
        if test -e "$directory"; then test -d "$directory"; fi
        install -d -m0755 -o "$account" -g "$account" "$directory"
    done
    dropin=$home/.config/systemd/user/xdg-document-portal.service.d/greyward-feasibility.conf
    test ! -L "$dropin"
    printf '[Service]\nExecStart=\nExecStart=%s\n' "$provider" > "$dropin"
    chown "$account:$account" "$dropin"
    chmod 0644 "$dropin"
    restorecon -RF "$home/.config/systemd"
    for helper in application-security-headless.sh application-security-portal-probe.py; do
        test -f "$source_dir/$helper"
        install -Dm0755 "$source_dir/$helper" "/usr/local/libexec/greyward-$helper"
        restorecon "/usr/local/libexec/greyward-$helper"
    done
    for receipt in portal-probe-result.json session-shell-result.json; do
        test ! -L "$home/$receipt"
        rm -f -- "$home/$receipt"
    done
    ;;
aliases)
    owned_account
    # The bind exists only in this transient unit's private mount namespace.
    # It never mounts over a path in the active desktop or host namespace.
    systemd-run --quiet --collect --wait --pipe --unit=greyward-guard-alias-probe \
        --property="User=$account" --property="Group=$account" \
        --property="SELinuxContext=$subject" --property=RuntimeMaxSec=45 --property=MemoryMax=64M \
        --property="BindReadOnlyPaths=$home/protected:$home/bound-secret" \
        /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-probe.py \
        --home "$home" --route-only --bind-alias | tee "$state/confined-aliases.json"
    ;;
rollback)
    owned_account
    # An interrupted private-agent probe may retain only this account's shadow
    # recovery receipt. Stop its fixed unit before restoring the original hash.
    if test -e "$state/authentication-shadow-backup.json"; then
        systemctl stop greyward-application-security-auth-probe.service 2>/dev/null || true
        helper=/usr/local/libexec/greyward-application-security-authorization.py
        test -f "$helper" && test ! -L "$helper"
        test "$(stat -c '%u' "$helper")" = 0
        test $(( 8#$(stat -c '%a' "$helper") & 022 )) = 0
        /usr/bin/python3 -I "$helper" --restore
    fi
    # Only this tool's account and fixed units are affected. The home is retained.
    systemctl stop greyward-guard-owner-probe.service greyward-guard-subject-probe.service greyward-guard-alias-probe.service 2>/dev/null || true
    quiesce_user_manager
    test -d "$home" && test ! -L "$home"
    test -d "$home/.ssh" && test ! -L "$home/.ssh"
    test ! -L "$home/.ssh/authorized_keys"
    # Undo only the provider selection created for this account. Refuse parent
    # symlinks; no other user's service or system portal binary is changed.
    for directory in "$home/.config" "$home/.config/systemd" "$home/.config/systemd/user" "$home/.config/systemd/user/xdg-document-portal.service.d"; do
        test ! -L "$directory"
        if test -e "$directory"; then test -d "$directory"; fi
    done
    rm -f -- "$home/.config/systemd/user/xdg-document-portal.service.d/greyward-feasibility.conf"
    install -m0600 -o "$account" -g "$account" /dev/null "$home/.ssh/authorized_keys"
    if semanage login -l | grep -q '^greyward-guard-probe '; then semanage login -d "$account"; fi
    restorecon -RF "$home"
    if semanage user -l | grep -q '^greyward_guard_u '; then semanage user -d greyward_guard_u; fi
    rm -f -- "$contexts"
    if semodule -l | awk '$1 == "greyward_guard_probe" { found=1 } END { exit !found }'; then semodule -r "$module"; fi
    printf 'ROLLED_BACK\n' > "$state/lifecycle"
    ;;
*)
    echo 'Usage: application-security-feasibility.sh setup|run|namespace|desktop|aliases|rollback [source-directory]' >&2
    exit 2
    ;;
esac
