#!/bin/bash
# Unprivileged, offline experimental checkpoint; no installation/activation.
set -euo pipefail
test "$(id -u)" != 0
umask 077
export PATH=/usr/bin:/bin
export CARGO=/usr/bin/cargo RUSTC=/usr/bin/rustc RUSTDOC=/usr/bin/rustdoc
export CARGO_BUILD_JOBS=1
source_root=${GREYWARD_APPSEC_SOURCE:-/var/tmp/greyward-application-security-build/security-center}
build_parent=${GREYWARD_APPSEC_BUILD_PARENT:-/var/tmp/greyward-application-security-build}
test -d "$source_root"
test -d "$build_parent"
test "$(realpath -e "$source_root")" = "$source_root"
test "$(realpath -e "$build_parent")" = "$build_parent"
test ! -L "$build_parent"
test "$(stat -c '%u %a' "$build_parent")" = "$(id -u) 700"
test -f "$source_root/Cargo.lock"
test -f "$source_root/LICENSE"
test ! -L "$source_root"
case "${1:-}" in ''|--warm) ;; *) exit 2;; esac
if test "${1:-}" = --warm; then
    build_root=$(cat "$build_parent/read-broker-package-build.path")
    case "$build_root" in "$build_parent"/rpm-read-broker.*) ;; *) exit 2;; esac
    test "$(realpath "$build_root")" = "$build_root"
    test "$(stat -c '%u %a' "$build_root")" = "$(id -u) 700"
    spec=$build_root/SPECS/greyward-application-security-experimental.spec
    archive=$build_root/SOURCES/greyward-application-security-experimental-0.1.0.tar.gz
    expected=$(awk -v archive="$archive" '$2 == archive {print $1}' "$build_root/inputs.txt")
    test "${#expected}" = 64
    test "$(sha256sum "$archive" | cut -d' ' -f1)" = "$expected"
    spec_hash=$(awk -v spec="$spec" '$2 == spec {print $1}' "$build_root/inputs.txt")
    test "${#spec_hash}" = 64
    test "$(sha256sum "$spec" | cut -d' ' -f1)" = "$spec_hash"
    test "$(/usr/bin/rustc --version)" = "$(head -n1 "$build_root/inputs.txt")"
    rpm_name=$(/usr/bin/rpmspec -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' "$spec")
    [[ "$rpm_name" =~ ^greyward-application-security-experimental-0\.1\.0-[1-9][0-9]*\.fc44\.x86_64\.rpm$ ]]
    rpm_path=$build_root/RPMS/x86_64/$rpm_name
    test ! -e "$build_root/validated-original.rpm"
    cp -p "$rpm_path" "$build_root/validated-original.rpm"
    restore_artifact() { cp -p "$build_root/validated-original.rpm" "$rpm_path"; }
    trap restore_artifact EXIT
    started=$SECONDS
    systemd-run --user --wait --pipe --collect --unit=greyward-appsec-rpm-build \
        -p RuntimeMaxSec=900 -p CPUQuota=100% -p MemoryMax=2G -p TasksMax=256 \
        -E PATH=/usr/bin:/bin -E CARGO=/usr/bin/cargo -E RUSTC=/usr/bin/rustc \
        -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
        /usr/bin/rpmbuild -bb --define "_topdir $build_root" \
        --define "greyward_cargo_target $build_root/target" "$spec" \
        > "$build_root/warm-build.log" 2>&1
    cp -p "$rpm_path" "$build_root/warm-rebuild.rpm"
    for candidate in validated-original warm-rebuild; do
        destination=$(mktemp -d "$build_root/cache-extracted.XXXXXX")
        rpm2cpio "$build_root/$candidate.rpm" | (cd "$destination"; cpio -id --quiet --no-absolute-filenames)
        sha256sum "$destination/usr/libexec/greyward-application-security" >> "$build_root/cache-binaries.txt"
    done
    test "$(cut -d' ' -f1 "$build_root/cache-binaries.txt" | sort -u | wc -l)" = 1
    printf 'WARM_CACHE_IDENTICAL_BINARY_PASS seconds=%s\n' "$((SECONDS - started))"
    sha256sum "$build_root/validated-original.rpm" "$build_root/warm-rebuild.rpm"
    exit 0
fi
build_root=$(mktemp -d "$build_parent/rpm-read-broker.XXXXXX")
mkdir -p "$build_root"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}
cp "$source_root/packaging/application-security/greyward-application-security-experimental.spec" "$build_root/SPECS/"
archive=$build_root/SOURCES/greyward-application-security-experimental-0.1.0.tar.gz
tar --sort=name --mtime=@1791331200 --owner=0 --group=0 --numeric-owner \
    --exclude='./target' --exclude='./.git' --exclude='./.secrets' --exclude='./output' \
    --exclude='__pycache__' --exclude='node_modules' \
    --transform='s,^\.,greyward-application-security-experimental-0.1.0,' \
    -C "$source_root" -czf "$archive" .
{
    /usr/bin/rustc --version
    /usr/bin/cargo --version
    /usr/bin/clippy-driver --version
    /usr/bin/rustfmt --version
    rpm -q rust cargo sqlite-libs sqlite-devel dbus-libs dbus-devel libseccomp libseccomp-devel selinux-policy systemd
    sha256sum "$archive" "$source_root/Cargo.lock" "$build_root/SPECS/greyward-application-security-experimental.spec"
} > "$build_root/inputs.txt"
# The transient unit independently bounds a blocked build, in addition to Cargo
# deadlines. No dependency acquisition or sudo is part of this command.
systemd-run --user --wait --pipe --collect --unit=greyward-appsec-rpm-build \
    -p RuntimeMaxSec=900 -p CPUQuota=100% -p MemoryMax=2G -p TasksMax=256 \
    -E PATH=/usr/bin:/bin -E CARGO=/usr/bin/cargo -E RUSTC=/usr/bin/rustc \
    -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
    /usr/bin/rpmbuild -bb --define "_topdir $build_root" \
    --define "greyward_cargo_target $build_root/target" \
    "$build_root/SPECS/greyward-application-security-experimental.spec" \
    > "$build_root/build.log" 2>&1
rpm_name=$(/usr/bin/rpmspec -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' "$build_root/SPECS/greyward-application-security-experimental.spec")
[[ "$rpm_name" =~ ^greyward-application-security-experimental-0\.1\.0-[1-9][0-9]*\.fc44\.x86_64\.rpm$ ]]
rpm_path=$build_root/RPMS/x86_64/$rpm_name
test -f "$rpm_path"
test -z "$(rpm -qp --scripts "$rpm_path")"
rpm -qp --qf '[%{FILEUSERNAME} %{FILEGROUPNAME} %{FILENAMES}\n]' "$rpm_path" > "$build_root/ownership.txt"
awk '$1 != "root" || $2 != "root" {exit 1}' "$build_root/ownership.txt"
rpm -qpR "$rpm_path" > "$build_root/requires.txt"
sha256sum "$rpm_path" >> "$build_root/inputs.txt"
printf '%s\n' "$build_root" > "$build_parent/read-broker-package-build.path"
cat "$build_root/inputs.txt"
