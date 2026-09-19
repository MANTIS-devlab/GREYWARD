#!/usr/bin/env bash
set -euo pipefail

# Install the production interactive shell for one already-created human
# account. This is intentionally separate from the image stage: Anaconda owns
# account creation, so the first-boot finalizer calls this after the account and
# account are available. ISO installations use the shipped source cache.
if [[ "$(id -u)" -ne 0 ]]; then
  echo 'greyward-configure-zsh must run as root' >&2
  exit 2
fi

target_user="${1:-}"
if [[ -z "$target_user" ]]; then
  echo "usage: $0 USER" >&2
  exit 2
fi

passwd_entry=$(getent passwd "$target_user")
test -n "$passwd_entry"
IFS=: read -r _ _ uid _ _ target_home _ <<< "$passwd_entry"
test "$uid" -ge 1000
target_group=$(id -gn "$target_user")
test -d "$target_home"
test -x /usr/bin/git
test -x /usr/bin/zsh

source /usr/share/greyward/zsh/sources.env

run_as_user() {
  runuser -u "$target_user" -- env HOME="$target_home" "$@"
}

clone_at_ref() {
  local destination="$1"
  local repository="$2"
  local ref="$3"

  if [[ -d "$destination/.git" ]] && run_as_user git -C "$destination" rev-parse --verify HEAD >/dev/null 2>&1; then
    if [[ "$(run_as_user git -C "$destination" rev-parse HEAD)" == "$ref" ]]; then
      return 0
    fi
  fi
  if [[ -e "$destination" && ! -d "$destination/.git" ]]; then
    echo "Refusing to replace existing non-repository directory: $destination" >&2
    exit 1
  fi

  run_as_user git init --quiet "$destination"
  if ! run_as_user git -C "$destination" remote get-url origin >/dev/null 2>&1; then
    run_as_user git -C "$destination" remote add origin "$repository"
  fi
  local cache="/usr/share/greyward/zsh/vendor/$ref"
  if [[ -d "$cache" ]]; then
    # The offline builder exposes the pinned object through the stable local
    # branch `greyward`; fetching that ref is reliable across Git versions,
    # whereas asking a local bare repository to advertise a raw SHA can leave
    # a partial clone without a checkoutable FETCH_HEAD.
    run_as_user git -C "$destination" fetch --quiet --update-shallow "$cache" refs/heads/greyward
  elif [[ -f /usr/share/greyward/zsh/vendor/required ]]; then
    echo "Missing offline shell source: $ref" >&2
    exit 1
  else
    run_as_user git -C "$destination" fetch --quiet --depth=1 origin "$ref"
  fi
  run_as_user git -C "$destination" checkout --quiet --detach FETCH_HEAD
  test "$(run_as_user git -C "$destination" rev-parse HEAD)" = "$ref"
}

clone_at_ref "$target_home/.oh-my-zsh" \
  "$GREYWARD_OH_MY_ZSH_REPO" "$GREYWARD_OH_MY_ZSH_REF"
clone_at_ref "$target_home/.oh-my-zsh/custom/themes/powerlevel10k" \
  "$GREYWARD_POWERLEVEL10K_REPO" "$GREYWARD_POWERLEVEL10K_REF"

# Anaconda may create a non-empty shell file before this finalizer runs. The
# production contract requires the GREYWARD Oh My Zsh entrypoint and theme,
# so do not mistake an arbitrary pre-existing file for the canonical config.
# This runs only for the newly-created production account during first boot.
install -o "$target_user" -g "$target_group" -m 0644 \
  /usr/share/greyward/zsh/zshrc "$target_home/.zshrc"
install -o "$target_user" -g "$target_group" -m 0644 \
  /usr/share/greyward/zsh/p10k.zsh "$target_home/.p10k.zsh"
usermod --shell /usr/bin/zsh "$target_user"
