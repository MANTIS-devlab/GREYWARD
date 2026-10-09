#!/bin/bash
# Synthetic pure-policy source measurements, never enrollment or release acceptance.
set -euo pipefail
test "$(id -u)" != 0
test "$(getenforce)" = Enforcing
source=/var/tmp/greyward-application-security-build/security-center
log=$(mktemp /var/tmp/greyward-application-security-build/policy-artifact.XXXXXXXX)
trap 'rm -f -- "$log"' EXIT
systemd-run --user --quiet --wait --pipe --collect --unit=greyward-appsec-policy-profile-build \
    -p RuntimeMaxSec=180 -p MemoryMax=1G -p CPUQuota=100% -p "WorkingDirectory=$source" \
    -E PATH=/usr/bin:/bin -E CARGO=/usr/bin/cargo -E RUSTC=/usr/bin/rustc \
    -E RUSTDOC=/usr/bin/rustdoc -E CARGO_BUILD_JOBS=1 \
    /usr/bin/cargo test -p greyward-application-security --test policy \
        --no-run --message-format=json --offline --locked > "$log"
binary=$(/usr/bin/python3 -I - "$source" "$log" <<'PY'
import json, pathlib, sys
base = pathlib.Path(sys.argv[1]) / 'target/debug/deps'
matches = []
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    item = json.loads(line)
    if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'policy' and item.get('executable'):
        candidate = pathlib.Path(item['executable'])
        if candidate.parent != base or not candidate.name.startswith('policy-'):
            raise SystemExit('Unexpected policy test artifact')
        matches.append(str(candidate))
if len(matches) != 1:
    raise SystemExit('Exactly one current policy test artifact required')
print(matches[0])
PY
)
sha256sum -- "$binary"
systemd-run --user --wait --pipe --collect --unit=greyward-appsec-policy-profile \
    -p RuntimeMaxSec=30 -p MemoryMax=128M -p CPUQuota=100% \
    -p PrivateNetwork=yes -E PATH=/usr/bin:/bin \
    "$binary" --exact profile_two_thousand_policy_records --ignored --nocapture
