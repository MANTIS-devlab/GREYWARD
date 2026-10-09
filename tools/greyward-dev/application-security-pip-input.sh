#!/bin/bash
# Fixed Fedora input for an offline synthetic task. No RPM installation.
set -euo pipefail
package=python3-pip-26.0.1-3.fc44.noarch
digest=5715def217cfaa500123a0461c607c580400780012fa8d6b004a4a073879f291
input=/var/tmp/greyward-application-security-build/pip-input/$package.rpm
payload=/usr/local/lib/greyward-development/pip-probe
state=/var/lib/greyward-development/application-security/pip-probe-input
if test "$(id -u)" != 0; then
    test "${1:-}" = acquire
    umask 077
    test "$(stat -c '%u %a' /var/tmp/greyward-application-security-build)" = "$(id -u) 700"
    test ! -L /var/tmp/greyward-application-security-build/pip-input
    mkdir -p /var/tmp/greyward-application-security-build/pip-input
    dnf5 download --destdir=/var/tmp/greyward-application-security-build/pip-input "$package"
    test "$(sha256sum "$input" | cut -d' ' -f1)" = "$digest"
    rpmkeys --checksig "$input"
    sudo -n bash /var/tmp/greyward-application-security-probe/application-security-pip-input.sh extract
    exit
fi
test "${1:-}" = extract
test "$(getenforce)" = Enforcing
# Copy then verify the root-owned receipt, excluding a builder replacement race.
for directory in /var/lib/greyward-development /var/lib/greyward-development/application-security "$state"; do
    test ! -L "$directory"
    if test -e "$directory"; then
        test "$(stat -c '%u' "$directory")" = 0
        test $(( 8#$(stat -c '%a' "$directory") & 022 )) = 0
    else
        install -d -m0700 "$directory"
    fi
done
test "$(stat -c '%a' "$state")" = 700
test ! -L "$state/input.rpm"
install -m0600 "$input" "$state/input.rpm"
test "$(sha256sum "$state/input.rpm" | cut -d' ' -f1)" = "$digest"
test "$(rpm -qp --qf '%{NEVRA}' "$state/input.rpm")" = "$package"
rpmkeys --checksig "$state/input.rpm"
extract=$(mktemp -d "$state/extracted.XXXXXX")
(cd "$extract"; rpm2cpio "$state/input.rpm" | cpio --quiet -idm --no-absolute-filenames)
for directory in /usr/local/lib/greyward-development "$payload"; do
    test ! -L "$directory"
    if test -e "$directory"; then test "$(stat -c '%u %a' "$directory")" = '0 755'; fi
    install -d -m0755 "$directory"
done
# This pinned input has regular Python files/directories, no links or special
# objects. Only its pip package is exposed; packaged /usr/bin launchers are not.
selected=$extract/usr/lib/python3.14/site-packages/pip
test -d "$selected" && test ! -L "$selected"
test -z "$(find "$selected" ! -type f ! -type d -print -quit)"
test ! -e "$payload/pip" # Refuse an unreviewed previous payload.
cp -R "$selected" "$payload/pip"
chown -R root:root "$payload/pip"
chmod -R u=rwX,go=rX "$payload/pip"
restorecon -RF "$payload"
printf '%s %s\n' "$package" "$digest" > "$state/receipt.txt"
test "$(rpm -q python3-pip 2>/dev/null || true)" = 'package python3-pip is not installed'
