#!/usr/bin/env bash
set -euo pipefail

# Factory/component-build step. The resulting RPMs are inputs to the
# production provisioner; the build toolchain itself is not a production
# dependency.
source_root="${GREYWARD_SECURITY_CENTER_SOURCE:-/tmp/greyward-security-center}"
output_root="${GREYWARD_SECURITY_CENTER_OUTPUT:-/tmp/greyward-production/rpms}"
test -d "$source_root"
for command in cargo rpmbuild rpm desktop-file-validate pkg-config tar sha256sum find sort; do
  command -v "$command" >/dev/null
done
pkg-config --exists webkit2gtk-4.1

build_parent="${GREYWARD_RPMBUILD_PARENT:-${HOME}/.cache/greyward-build}"
cargo_target="${GREYWARD_CARGO_TARGET_DIR:-${HOME}/.cache/greyward/package-cargo-target}"
install -d -m 0700 "$cargo_target"
install -d -m 0700 "$build_parent"
build_root=$(mktemp -d "$build_parent/rpmbuild.XXXXXX")
trap 'rm -rf "$build_root"' EXIT
mkdir -p "$build_root"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

rpm_common_args=(
  --define "_topdir $build_root"
  --define "debug_package %{nil}"
  --define "greyward_cargo_target $cargo_target"
)
# Source archives have normalized timestamps. Cargo's timestamp fast path must
# not reuse an older workspace binary when the source content changed. Clean
# only changed first-party crates; keep all external compiler/dependency caches.
python3 - "$source_root" "$cargo_target" "$build_root" <<'PY'
import hashlib,json,pathlib,subprocess,sys
root,target,build=map(pathlib.Path,sys.argv[1:])
import os
if target.is_symlink() or target.stat().st_uid != os.getuid() or target.resolve() in {pathlib.Path('/'),pathlib.Path.home(),root.resolve()}:
 raise SystemExit('Unsafe Cargo cache directory')
# Existing factory caches can predate Cargo's CACHEDIR.TAG clean guard.
# This dedicated, user-owned target is explicitly a disposable compiler cache.
tag=target/'CACHEDIR.TAG'
if not tag.exists():
 tag.write_text('Signature: 8a477f597d28d172789f06886806bc55\n# GREYWARD dedicated Cargo build cache\n')
stamp=target/'.greyward-component-inputs.json'
previous=json.loads(stamp.read_text()) if stamp.exists() else {}
packages={'greyward-security-domain':[root/'crates/greyward-security-domain'],
          'greyward-security-backends':[root/'crates/greyward-security-backends'],
          'greyward-security-center':[root/'tauri/src-tauri',root/'tauri/frontend']}
current={}
for name,paths in packages.items():
 files={root/'Cargo.toml',root/'Cargo.lock'}
 for path in paths:
  files.update(p for p in path.rglob('*') if p.is_file() and not any(x in {'target','node_modules','__pycache__'} for x in p.parts))
 content=''.join(p.relative_to(root).as_posix()+'\0'+hashlib.sha256(p.read_bytes()).hexdigest()+'\n' for p in sorted(files))
 current[name]=hashlib.sha256(content.encode()).hexdigest()
 if previous.get(name)!=current[name]:
  for profile_args in ([],['--release']):
   subprocess.run(['cargo','clean','--manifest-path',str(root/'Cargo.toml'),'--target-dir',str(target),'-p',name,*profile_args],check=True)
(build/'cargo-inputs.json').write_text(json.dumps(current))
PY
if [[ "${GREYWARD_SKIP_RUST_TESTS:-0}" == "1" ]]; then
  rpm_common_args+=(--define 'greyward_skip_rust_tests 1')
fi

make_source_tar() {
  local name="$1"
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    --exclude='target' --exclude='node_modules' --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --transform="s,^$(basename "$source_root"),${name}-0.1.0," \
    -czf "$build_root/SOURCES/${name}-0.1.0.tar.gz" \
    -C "$(dirname "$source_root")" "$(basename "$source_root")"
}

# This fingerprint describes the source that produced the RPMs. Build output,
# vendored package caches, and node_modules are excluded because they are not
# part of the component source contract and are not reproducible inputs.
source_tree_sha256() {
  (
    cd "$source_root"
    LC_ALL=C find . -type f \
      ! -path '*/target/*' \
      ! -path '*/node_modules/*' \
      ! -path '*/__pycache__/*' ! -name '*.pyc' \
      ! -path './.git/*' \
      -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' file; do
        sha256sum "$file"
      done | sha256sum | awk '{print $1}'
  )
}

make_source_tar greyward-security-center
install -m 0644 "$source_root/packaging/greyward-security-center.spec" "$build_root/SPECS/"
# Rust source files commonly start with `#![allow(...)]`. Fedora's
# brp-mangle-shebangs treats those Rust attributes as executable shebangs when
# scanning generated debug sources. The application package does not need a
# debug-source subpackage for this internal component build, so disable only
# that generated subpackage while keeping the normal binary checks intact.
center_started=$SECONDS
rpmbuild -ba "${rpm_common_args[@]}" "$build_root/SPECS/greyward-security-center.spec"
printf 'GREYWARD_TIMING stage=center-rpm-build seconds=%s\n' "$((SECONDS - center_started))"
install -m0600 "$build_root/cargo-inputs.json" "$cargo_target/.greyward-component-inputs.json"

make_source_tar greyward-security-context
install -m 0644 "$source_root/packaging/greyward-security-context.spec" "$build_root/SPECS/"
context_started=$SECONDS
rpmbuild -ba "${rpm_common_args[@]}" "$build_root/SPECS/greyward-security-context.spec"
printf 'GREYWARD_TIMING stage=context-rpm-build seconds=%s\n' "$((SECONDS - context_started))"

rm -rf "$output_root"
install -d -m 0755 "$output_root"
find "$build_root/RPMS" -type f \( \
  -name 'greyward-security-center-*.x86_64.rpm' -o \
  -name 'greyward-security-context-*.noarch.rpm' \
\) ! -name '*-debugsource-*' ! -name '*-debuginfo-*' \
  -exec install -m 0644 {} "$output_root/" \;
test -n "$(find "$output_root" -type f -name 'greyward-security-*.rpm' -print -quit)"
center_rpm=$(find "$output_root" -type f -name 'greyward-security-center-*.x86_64.rpm' | sort -V | tail -n 1)
context_rpm=$(find "$output_root" -type f -name 'greyward-security-context-*.noarch.rpm' | sort -V | tail -n 1)
test -n "$center_rpm"
test -n "$context_rpm"
source_fingerprint=$(source_tree_sha256)
center_nevra=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$center_rpm")
context_nevra=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$context_rpm")
cat > "$output_root/security-center-build-manifest.tsv" <<EOF
schema=greyward.security-center-build/v1
source_tree_sha256=$source_fingerprint
center_filename=$(basename "$center_rpm")
center_sha256=$(sha256sum "$center_rpm" | awk '{print $1}')
center_nevra=$center_nevra
context_filename=$(basename "$context_rpm")
context_sha256=$(sha256sum "$context_rpm" | awk '{print $1}')
context_nevra=$context_nevra
EOF
printf '%s\n' 'GREYWARD SECURITY COMPONENTS BUILT'
