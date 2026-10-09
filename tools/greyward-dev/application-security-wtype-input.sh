#!/bin/bash
# Exact signed Fedora keyboard actuator for private UID-1002 display tests.
# No RPM installation, scriptlets, PATH change or host keyboard device access.
set -euo pipefail
package=wtype-0.4-11.fc44.x86_64
digest=97646d188ca009d47297227d8832657d052c19c2670d976e1619a13ecfcac348
fingerprint=36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6
input=/var/tmp/greyward-application-security-build/wtype-input/$package.rpm
payload=/usr/local/lib/greyward-development/wtype-probe
state=/var/lib/greyward-development/application-security/wtype-probe-input
if test "$(id -u)" != 0; then
    test "${1:-}" = acquire
    umask 077
    base=/var/tmp/greyward-application-security-build
    test "$(stat -c '%u %a' "$base")" = "$(id -u) 700"
    test ! -L "$base/wtype-input"
    mkdir -p "$base/wtype-input"
    if test ! -e "$input"; then
        curl --fail --location --proto '=https' --max-time 60 --silent --show-error \
            "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/Packages/w/$package.rpm" \
            --output "$input"
    fi
    test "$(sha256sum "$input" | cut -d' ' -f1)" = "$digest"
    rpmkeys --checksig --verbose "$input" | grep -F "$fingerprint: OK"
    sudo -n bash /var/tmp/greyward-application-security-probe/application-security-wtype-input.sh extract
    exit
fi
test "${1:-}" = extract
test "$(getenforce)" = Enforcing
for directory in /var/lib/greyward-development /var/lib/greyward-development/application-security "$state"; do
    test ! -L "$directory"
    if test -e "$directory"; then
        test "$(stat -c '%u' "$directory")" = 0
        test $(( 8#$(stat -c '%a' "$directory") & 022 )) = 0
    else
        install -d -m0700 "$directory"
    fi
done
test ! -L "$state/input.rpm"
install -m0600 "$input" "$state/input.rpm"
test "$(sha256sum "$state/input.rpm" | cut -d' ' -f1)" = "$digest"
test "$(rpm -qp --qf '%{NEVRA}' "$state/input.rpm")" = "$package"
rpmkeys --checksig --verbose "$state/input.rpm" > "$state/signature.txt"
grep -F "$fingerprint: OK" "$state/signature.txt"
extract=$(mktemp -d "$state/extracted.XXXXXXXX")
(cd "$extract"; rpm2cpio "$state/input.rpm" | cpio --quiet -idm --no-absolute-filenames)
test -f "$extract/usr/bin/wtype" && test ! -L "$extract/usr/bin/wtype"
test "$(stat -c '%h %a' "$extract/usr/bin/wtype")" = '1 755'
for directory in /usr/local/lib/greyward-development "$payload"; do
    test ! -L "$directory"
    if test -e "$directory"; then test "$(stat -c '%u %a' "$directory")" = '0 755'; fi
    install -d -m0755 "$directory"
done
test ! -e "$payload/wtype"
install -m0755 "$extract/usr/bin/wtype" "$payload/wtype"
install -m0644 "$extract/usr/share/licenses/wtype/LICENSE" "$payload/LICENSE"
restorecon -RF "$payload"
printf '%s %s %s\n' "$package" "$digest" "$fingerprint" > "$state/receipt.txt"
sha256sum "$payload/wtype" >> "$state/receipt.txt"
test "$(rpm -q wtype 2>/dev/null || true)" = 'package wtype is not installed'
printf 'SIGNED_PRIVATE_WTYPE_INPUT_PASS\n'
