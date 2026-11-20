#!/usr/bin/env bash
set -euo pipefail

source_dir=$1
icon=$2
state=/var/lib/greyward/mailcraft
rpm -q --quiet mailcraft

install -D -m 0755 "$source_dir/launch.py" /usr/libexec/greyward-mailcraft-launch
install -D -m 0755 "$source_dir/refresh.py" /usr/libexec/greyward-mailcraft-refresh
install -D -m 0644 "$source_dir/io.github.billsecond.mailcraft.desktop" \
  /usr/local/share/applications/io.github.billsecond.mailcraft.desktop
install -D -m 0644 "$icon" /usr/share/icons/hicolor/scalable/apps/greyward-mailcraft.svg
install -D -m 0644 /dev/null /etc/mailcraft/no-automatic-updates

install -d -m 0755 "$state/repo"
if [[ ! -f "$state/repo/repodata/repomd.xml" ]]; then
  createrepo_c --quiet --excludes '*.rpm' "$state/repo"
fi
install -D -m 0644 "$source_dir/greyward-mailcraft.repo" /etc/yum.repos.d/greyward-mailcraft.repo
for unit in greyward-mailcraft-refresh.service greyward-mailcraft-refresh.timer; do
  install -D -m 0644 "$source_dir/$unit" "/usr/lib/systemd/system/$unit"
done
systemctl --no-reload enable greyward-mailcraft-refresh.timer

if command -v update-desktop-database >/dev/null; then
  update-desktop-database -q /usr/local/share/applications
fi
