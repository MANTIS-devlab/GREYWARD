#!/bin/bash
# Validate before dracut packages the theme for a new or rebuilt kernel.
# Fedora's plymouth module still owns renderer/font/cryptsetup integration.
check() {
    [[ $(plymouth-set-default-theme 2>/dev/null) == greyward ]] || return 1
    return 0
}

depends() {
    echo plymouth
}

install() {
    "${dracutsysrootdir-}/usr/libexec/greyward/verify-boot-theme" \
        --script "${dracutsysrootdir-}/usr/share/plymouth/themes/greyward/greyward.script" || {
        dfatal 'GREYWARD Plymouth theme is invalid; refusing to generate a black splash.'
        exit 1
    }
}
