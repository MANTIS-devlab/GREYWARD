#!/usr/bin/env bash
set -uo pipefail

# Fedora/VM release gate. This runner intentionally fails closed: a missing
# runtime environment is BLOCKED, never silently converted into PASS.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
report=""
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

usage() {
  cat <<'EOF'
Usage: security-center/tests/session10-gate.sh [--report PATH]

Run the available fast checks and record the Fedora/VM evidence needed for the
Session 10 release gate. Runtime checks may be supplied as command paths using
GREYWARD_SESSION10_<CHECK>_CMD; unset runtime commands are BLOCKED.

Supported runtime command variables: TAURI_RUNTIME, RPM_LIFECYCLE,
NETWORK_RUNTIME, FILE_SECURITY, RECOVERY_RESTIC, TELEMETRY_PRIVACY,
SECURITY_CENTER_UX, NO_REMOTE_REQUESTS, DEPENDENCY_ARTIFACTS.
EOF
}

while (($#)); do
  case "$1" in
    --report) (($# >= 2)) || { usage >&2; exit 2; }; report=$(realpath -m "$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [[ -z "$report" ]]; then
  report="$tmp_dir/session-10-run.md"
fi
mkdir -p "$(dirname "$report")"

results=()
commands=()
outputs=()
add_result() { results+=("$1|$2|$3"); commands+=("$1|$3"); }

run_command() {
  local name=$1 command=$2 output_file="$tmp_dir/${#results[@]}.log"
  commands+=("$name|$command")
  if bash -lc "$command" >"$output_file" 2>&1; then
    results+=("$name|PASS|$output_file")
  else
    results+=("$name|BLOCKED|$output_file")
  fi
}

run_optional_runtime() {
  local name=$1 variable=$2 command=${!2:-}
  if [[ -z "$command" ]]; then
    results+=("$name|BLOCKED|No ${variable} command was supplied")
    commands+=("$name|not supplied")
    return
  fi
  run_command "$name" "$command"
}

if [[ -f /etc/fedora-release ]]; then
  run_command "Rust build" "cd '$repo_root/security-center' && cargo build --workspace --release --locked --features greyward-security-center/custom-protocol"
  run_command "Rust tests" "cd '$repo_root/security-center' && cargo test --workspace --locked"
  run_command "Rust clippy" "cd '$repo_root/security-center' && cargo clippy --workspace --all-targets --locked -- -D warnings"
else
  add_result "Rust build" "BLOCKED" "Fedora is required for the Session 10 Rust gate"
  add_result "Rust tests" "BLOCKED" "Fedora is required for the Session 10 Rust gate"
  add_result "Rust clippy" "BLOCKED" "Fedora is required for the Session 10 Rust gate"
fi

if command -v python3 >/dev/null 2>&1; then
  run_command "Python Security Context tests" "cd '$repo_root' && PYTHONPATH=security-center/security-context python3 -m unittest discover -s security-center/security-context/tests -p 'test_*.py'"
else
  add_result "Python Security Context tests" "BLOCKED" "python3 is unavailable"
fi

if command -v node >/dev/null 2>&1; then
  run_command "Frontend contract tests" "cd '$repo_root' && node --test security-center/tauri/frontend/ux-contract.test.mjs"
else
  add_result "Frontend contract tests" "BLOCKED" "node is unavailable"
fi

run_optional_runtime "Real Tauri interaction tests" GREYWARD_SESSION10_TAURI_RUNTIME_CMD
run_optional_runtime "RPM install/update/uninstall and ownership" GREYWARD_SESSION10_RPM_LIFECYCLE_CMD
run_optional_runtime "Network Activity real traffic" GREYWARD_SESSION10_NETWORK_RUNTIME_CMD
run_optional_runtime "File Security lifecycle" GREYWARD_SESSION10_FILE_SECURITY_CMD
run_optional_runtime "Recovery and Restic failure states" GREYWARD_SESSION10_RECOVERY_RESTIC_CMD
run_optional_runtime "Telemetry privacy and retention" GREYWARD_SESSION10_TELEMETRY_PRIVACY_CMD
run_optional_runtime "Security Center UX lifecycle" GREYWARD_SESSION10_SECURITY_CENTER_UX_CMD
run_optional_runtime "No remote requests" GREYWARD_SESSION10_NO_REMOTE_REQUESTS_CMD
if [[ -n "${GREYWARD_SESSION10_DEPENDENCY_ARTIFACTS_CMD:-}" ]]; then
  run_command "Dependency and artifact traceability" "$GREYWARD_SESSION10_DEPENDENCY_ARTIFACTS_CMD"
elif [[ -d /var/lib/greyward/build-artifacts ]] &&
     find /var/lib/greyward/build-artifacts -maxdepth 1 -type f -size +0c -print -quit | grep -q . &&
     ! grep -R -q 'UNRESOLVED' /var/lib/greyward/build-artifacts; then
  results+=("Dependency and artifact traceability|PASS|Installed image artifacts contain no unresolved markers")
  commands+=("Dependency and artifact traceability|built-in installed-image artifact check")
else
  results+=("Dependency and artifact traceability|BLOCKED|Installed image artifacts are missing or contain unresolved records")
  commands+=("Dependency and artifact traceability|built-in installed-image artifact check")
fi

status="PASS"
for result in "${results[@]}"; do
  [[ "${result#*|}" == "PASS|"* ]] || status="BLOCKED"
done

{
  printf '# GREYWARD Security Center — Session 10 run\n\n'
  printf 'Status: **%s**\n\n' "$status"
  printf 'Generated: `%s`\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'This is an evidence runner, not an acceptance downgrade. Any missing Fedora, VM, device, or real-window evidence remains BLOCKED.\n\n'
  printf '| Check | Result | Evidence / blocker |\n|---|---|---|\n'
  for result in "${results[@]}"; do
    IFS='|' read -r name result_value evidence <<< "$result"
    if [[ -f "$evidence" ]]; then
      printf '| %s | **%s** | `%s` |\n' "$name" "$result_value" "$evidence"
    else
      printf '| %s | **%s** | %s |\n' "$name" "$result_value" "$evidence"
    fi
  done
  printf '\n## Commands\n\n'
  for command in "${commands[@]}"; do
    IFS='|' read -r name command_text <<< "$command"
    printf -- '- **%s:** `%s`\n' "$name" "$command_text"
  done
} > "$report"

printf 'Session 10: %s\nReport: %s\n' "$status" "$report"
if [[ "$status" == "PASS" ]]; then exit 0; else exit 1; fi
