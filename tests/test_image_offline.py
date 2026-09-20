"""Standalone media failure and network-boundary regression tests."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("offline", ROOT / "environment/image/build-offline.py")
offline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(offline)


class OfflineTests(unittest.TestCase):
    def test_changed_pin_format_fails_instead_of_using_latest(self):
        with self.assertRaises(ValueError):
            offline.pinned("DMS_VERSION=latest", "DMS_VERSION")

    def test_canonical_desktop_pins_are_readable(self):
        text = (ROOT / "environment/production/install-dms.sh").read_text()
        self.assertRegex(offline.pinned(text, "DMS_ARCHIVE_SHA256"), r"^[a-f0-9]{64}$")
        self.assertRegex(offline.pinned(text, "DMS_VERSION"), r"^v\d+\.\d+\.\d+$")

    def test_duplicate_rpm_identity_is_rejected(self):
        with patch.object(offline, "run", return_value="pkg.x86_64|0|1|1"):
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                offline.rpm_inventory([Path("a.rpm"), Path("b.rpm")])

    def test_installer_solver_includes_implicit_core_and_efi_tools(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(offline, "run") as run:
            offline.verify_installer_repository(Path(temp) / "repo", Path(temp) / "empty-root")
            args = run.call_args.args
            self.assertEqual(args[:3], ("unshare", "--net", "dnf5"))
            self.assertIn("@core", args)
            self.assertIn("grub2-tools-extra", args)
            self.assertIn("mtools", args)
            self.assertIn("grubby", args)
            self.assertIn("nvme-cli", args)
            self.assertIn("--downloadonly", args)

    def test_networked_builder_resolution_is_ipv4_pinned(self):
        source = (ROOT / "environment/image/build-offline.py").read_text()
        self.assertIn('run("curl", "--ipv4"', source)
        self.assertIn('"--setopt=ip_resolve=4"', source)

    def test_iso_composer_reexecutes_with_noninteractive_sudo(self):
        source = (ROOT / "environment/image/build-iso.sh").read_text()
        self.assertIn('sudo -n env "GREYWARD_ISO_WORK_ROOT=$work_root" bash "$0" "$@"', source)

    def test_both_repositories_retain_group_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp) / "stage"
            target = stage / "offline"
            (target / "rpm/Packages").mkdir(parents=True)
            (stage / "rpms").mkdir()
            calls = []
            inventory = {"package%d.noarch" % i: ["0", "1", "1"] for i in range(100)}
            with patch.object(offline, "rpm_inventory", side_effect=[inventory, {}]), \
                 patch.object(offline, "check_floors"), patch.object(offline, "verify_signatures"), \
                 patch.object(offline, "verify_installer_repository"), \
                 patch.object(offline, "run", side_effect=lambda *args: calls.append(args)):
                offline.verify_rpms(stage, Path(temp), target, {})
            self.assertIn(("createrepo_c", "--groupfile", target / "comps.xml", target / "rpm"), calls)
        compose = (ROOT / "environment/image/build-iso.sh").read_text()
        self.assertIn('--groupfile "$iso_tree/greyward/production/offline/comps.xml"', compose)
        self.assertIn('--location-prefix greyward/production/offline/rpm', compose)
        self.assertNotIn('--location-prefix greyward/production/offline/rpm/Packages', compose)
        self.assertIn('--verify-media-repo "$iso_tree"', compose)

    def test_core_keeps_fedora_packages_but_omits_production_exclusions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "comps.xml"
            path.write_text('<comps><group><id>core</id><packagelist>'
                            '<packagereq type="mandatory">bash</packagereq>'
                            '<packagereq type="default">openssh-server</packagereq>'
                            '</packagelist></group></comps>')
            offline.prune_excluded_group_packages(path)
            group = offline.ET.parse(path).find('group')
            self.assertEqual(group.findtext('id'), 'core')
            self.assertEqual([p.text for p in group.findall('packagelist/packagereq')], ['bash'])

    def test_flatpak_cache_is_separate_from_host(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "isolated"
            env = offline.flatpak_env(path)
            for key in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                        "FLATPAK_SYSTEM_DIR", "FLATPAK_SYSTEM_CACHE_DIR", "FLATPAK_USER_DIR"):
                self.assertTrue(Path(env[key]).is_relative_to(path))

    def test_create_usb_repo_is_promoted_to_a_summarized_local_remote(self):
        source = (ROOT / "environment/image/build-offline.py").read_text()
        self.assertIn("prepare_sideload_repo(repo, refs)", source)
        self.assertIn('"flatpak", "build-update-repo"', source)
        install = (ROOT / "environment/production/install-offline-flatpaks.sh").read_text()
        self.assertIn('offline_remote=greyward-offline', install)
        self.assertIn('--no-gpg-verify', install)
        self.assertIn('"$offline_remote" "${refs[@]}"', install)
        self.assertIn('flatpak remote-delete "$scope" --force "$offline_remote"', install)
        self.assertNotIn('--commit=', install)

    def test_offline_validation_cannot_silently_use_network(self):
        source = (ROOT / "environment/production/provision-firstboot.sh").read_text()
        self.assertIn("GREYWARD_OFFLINE_INSTALL=1", source)
        provision = (ROOT / "environment/production/provision.sh").read_text()
        self.assertIn("unshare --net -- /usr/bin/dnf", provision)
        self.assertIn('unshare --net -- bash "$stage/install-offline-flatpaks.sh"', provision)
        self.assertNotIn("nm-online", source)
        self.assertIn("preflight_check 'staged offline manifest'", source)

    def test_offline_flatpak_install_does_not_pull_from_remote(self):
        source = (ROOT / "environment/production/install-offline-flatpaks.sh").read_text()
        self.assertIn("--sideload-repo=", source)
        self.assertIn("unshare --net", (ROOT / "environment/production/provision.sh").read_text())
        self.assertIn('flatpak remote-modify "$scope" --disable flathub', source)
        self.assertIn('flatpak remote-modify "$scope" --enable flathub', source)

    def test_first_boot_enables_security_context_user_service(self):
        source = (ROOT / "environment/production/provision.sh").read_text()
        self.assertIn("systemctl --global enable greyward-security-context-user.service", source)
        self.assertIn('stage/security-context/greyward-security-context-user.service', source)

    def test_firstboot_starts_security_provider_services_before_acceptance(self):
        provision = (ROOT / "environment/production/provision.sh").read_text()
        acceptance = (ROOT / "environment/production/production-acceptance.sh").read_text()
        self.assertIn("required_services=(", provision)
        for service in ("NetworkManager", "greyward-opensnitch-control-plane", "opensnitch", "greyward-secure-dns", "usbguard-dbus"):
            self.assertIn(service, provision)
        self.assertIn('systemctl enable --now "$required_service"', provision)
        self.assertIn('systemctl status --no-pager --full "$required_service"', provision)
        self.assertIn('systemctl is-active --quiet "$provider_service"', acceptance)

    def test_hardware_conditional_bluetooth_does_not_fail_vm_provisioning(self):
        provision = (ROOT / "environment/production/provision.sh").read_text()
        self.assertIn(
            'if [[ "$required_service" == bluetooth && ! -d /sys/class/bluetooth ]]; then',
            provision,
        )
        self.assertIn(
            "Skipping conditionally applicable production service: bluetooth",
            provision,
        )

    def test_firstboot_persists_the_failed_phase_and_greeter_readiness(self):
        provision = (ROOT / "environment/production/provision.sh").read_text()
        firstboot = (ROOT / "environment/production/provision-firstboot.sh").read_text()
        acceptance = (ROOT / "environment/production/production-acceptance.sh").read_text()
        status = (ROOT / "environment/production/firstboot-status.sh").read_text()
        self.assertIn("provision-current-phase.txt", provision)
        self.assertIn("provision-failure.txt", provision)
        self.assertIn("BASH_COMMAND", provision)
        self.assertIn("pgrep -u greeter -x dms-greeter", firstboot)
        self.assertIn("pgrep -u greeter -x labwc", firstboot)
        self.assertIn("loginctl list-sessions --no-legend", firstboot)
        self.assertIn("pgrep -x dms", firstboot)
        self.assertIn("greetd-failure.txt", firstboot)
        self.assertIn("finalizer entered; validating staged inputs", firstboot)
        self.assertIn("timeout --foreground 10m", firstboot)
        self.assertIn("timeout --foreground 120s systemctl start greetd.service", firstboot)
        self.assertIn("timeout --foreground 120s systemctl enable --now", provision)
        self.assertIn("timeout --foreground 30s systemctl is-active", provision)
        self.assertIn("/usr/bin/env WLR_RENDERER=pixman", provision)
        self.assertNotIn("WLR_DRM_DEVICES=", provision)
        self.assertIn("XDG_CONFIG_HOME=/var/cache/dms-greeter/.config", provision)
        self.assertIn("only into that greeter process", provision)
        self.assertIn('greyward-start-labwc', provision)
        self.assertIn('greyward-start-labwc', (ROOT / "environment/image/build.sh").read_text())
        self.assertIn('Exec=/usr/local/libexec/greyward-start-labwc', (ROOT / "environment/session/greyward-labwc.desktop").read_text())
        launcher = (ROOT / "environment/production/greyward-start-labwc").read_text()
        self.assertIn('/sys/class/dmi/id/sys_vendor', launcher)
        self.assertIn("grep -Eiq 'vmware|hyper-?v|virtual machine'", launcher)
        self.assertIn("grep -Eiq '^(0x)?(15ad|1414)$'", launcher)
        self.assertIn('/dev/dri/renderD*', launcher)
        self.assertIn('has_render_node=false', launcher)
        self.assertIn('export WLR_RENDERER=pixman', launcher)
        self.assertIn('exec uwsm start -D Labwc:GREYWARD labwc', launcher)
        self.assertNotIn("/usr/libexec/greyward-dms-greeter", provision)

        self.assertNotIn('test -r "$stage/greyward-dms-greeter"', provision)
        self.assertNotIn("greetd-renderer.conf", provision)
        self.assertIn('"$stage/labwc-environment"', provision)
        self.assertIn("GREYWARD acceptance:", acceptance)
        self.assertIn("last check:", acceptance)
        self.assertIn("provision-current-phase.txt", status)
        self.assertIn("tail -n 20", status)
        self.assertGreater(
            firstboot.index('rm -f "$pending"'),
            firstboot.index('if [[ "$greeter_ready" != true ]]'),
        )
        self.assertGreater(
            firstboot.index('rm -rf "$stage"'),
            firstboot.index('if [[ "$greeter_ready" != true ]]'),
        )

    def test_session_autostart_preserves_a_selected_wallpaper(self):
        autostart = (ROOT / "environment/production/labwc-autostart").read_text()
        self.assertIn("ipc call wallpaper get", autostart)
        self.assertIn("wallpaper_state", autostart)
        self.assertIn("ipc call wallpaper set /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg", autostart)

    def test_session_lock_uses_secure_greyward_session_presentation(self):
        lock = (ROOT / "environment/session/greyward-session-lock").read_text()
        for argument in (
            "/usr/local/bin/greyward-dms",
            "ipc call lock lock",
        ):
            self.assertIn(argument, lock)
        self.assertNotIn("swaylock", lock)
        self.assertNotIn("gtklock", lock)
        self.assertNotIn("--ignore-empty-password", lock)
        self.assertNotIn("loginctl terminate", lock)
        self.assertNotIn("systemctl restart greetd", lock)
        self.assertIn("WlSessionLock", (ROOT / "environment/production/production-acceptance.sh").read_text())
        self.assertIn("Modules/Lock/Pam.qml", (ROOT / "environment/production/production-acceptance.sh").read_text())

    def test_image_stage_carries_canonical_security_context_unit(self):
        source = (ROOT / "environment/image/build.sh").read_text()
        self.assertIn('security_context_unit="$repo_root/security-center/security-context/systemd/greyward-security-context-user.service"', source)
        self.assertIn('cp -a "$security_context_unit" "$output/security-context/"', source)

    def test_security_context_user_service_starts_without_wayland_condition(self):
        source = (ROOT / "security-center/security-context/systemd/greyward-security-context-user.service").read_text()
        self.assertNotIn("ConditionEnvironment=WAYLAND_DISPLAY", source)
        self.assertIn("WantedBy=default.target graphical-session.target", source)

    def test_secure_dns_allows_read_only_state_to_security_context(self):
        source = (ROOT / "security-center/security-context/dbus/systems.mantis.greyward.SecureDns1.conf").read_text()
        self.assertIn('send_interface="org.freedesktop.DBus.Introspectable"', source)
        self.assertIn('send_member="GetState"', source)
        for member in ("SetMode", "SetProvider", "RetrySecureDns"):
            self.assertRegex(
                source,
                rf'<deny\s+send_destination="systems\.mantis\.greyward\.SecureDns1"'
                rf'[^>]*send_member="{member}"\s*/>',
            )

    def test_production_zsh_config_replaces_anaconda_shell_files(self):
        source = (ROOT / "environment/production/configure-zsh.sh").read_text()
        self.assertIn('install -o "$target_user" -g "$target_group" -m 0644 \\\n  /usr/share/greyward/zsh/zshrc "$target_home/.zshrc"', source)
        self.assertIn('install -o "$target_user" -g "$target_group" -m 0644 \\\n  /usr/share/greyward/zsh/p10k.zsh "$target_home/.p10k.zsh"', source)

    def test_offline_zsh_reuses_pinned_local_branch(self):
        source = (ROOT / "environment/production/configure-zsh.sh").read_text()
        self.assertIn("refs/heads/greyward", source)
        self.assertIn('rev-parse HEAD)" == "$ref"', source)

    def test_installer_has_only_local_source(self):
        source = (ROOT / "environment/image/installer.ks.tmpl").read_text()
        self.assertIn("\ncdrom\n", source)
        self.assertNotRegex(source, r"(?m)^(url|repo) ")
        self.assertNotIn("--activate", source)
        self.assertIn("offline/installer-packages.ks", source)

    def test_stager_uses_the_canonical_installer_template(self):
        source = (ROOT / "environment/image/build.sh").read_text()
        self.assertIn('kickstart="$repo_root/environment/image/installer.ks.tmpl"', source)
        self.assertIn('"$output/installer.ks.tmpl"', source)
        self.assertNotIn("environment/http/greyward.ks.tmpl", source)

    def test_installer_boot_theme_rebuild_targets_installed_kernels(self):
        source = (ROOT / "environment/image/installer.ks.tmpl").read_text()
        theme = "chroot /mnt/sysroot /usr/bin/plymouth-set-default-theme greyward"
        rebuild = "chroot /mnt/sysroot /usr/bin/dracut --regenerate-all --force"
        self.assertNotIn("plymouth-set-default-theme -R", source)
        self.assertLess(source.index(theme), source.index(rebuild))
        self.assertIn("%post --nochroot --erroronfail", source)

    def test_installer_records_and_confirms_the_post_install_reboot_handoff(self):
        installer = (ROOT / "environment/image/installer.ks.tmpl").read_text()
        firstboot = (ROOT / "environment/production/provision-firstboot.sh").read_text()
        self.assertIn("bootloader --timeout=5", installer)
        self.assertIn("reboot --eject", installer)
        self.assertIn("anaconda-reboot-requested", installer)
        self.assertIn("reboot_requested=/var/lib/greyward/installer/anaconda-reboot-requested", firstboot)
        self.assertIn("anaconda-firstboot-entered", firstboot)

    def test_greeter_uses_the_canonical_desktop_wallpaper_before_each_start(self):
        provision = (ROOT / "environment/production/provision.sh").read_text()
        acceptance = (ROOT / "environment/production/production-acceptance.sh").read_text()
        helper = (ROOT / "environment/production/greyward-sync-greeter-wallpaper").read_text()
        builder = (ROOT / "environment/image/build.sh").read_text()
        self.assertIn("greyward-sync-greeter-wallpaper", provision)
        self.assertIn("greyward-wallpaper-black-art-4k.jpg", helper)
        self.assertIn("greeter_wallpaper_override.jpg", helper)
        self.assertIn("/var/cache/dms-greeter/session.json", helper)
        self.assertIn('"wallpaperFillMode": "PreserveAspectCrop"', helper)
        self.assertIn("ExecStartPre=/usr/local/libexec/greyward-sync-greeter-wallpaper", provision)
        self.assertIn("greyward-wallpaper-black-art-4k.jpg", acceptance)
        self.assertIn("cmp -s /usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg", acceptance)
        self.assertIn("/var/cache/dms-greeter/session.json", acceptance)
        self.assertIn("greyward-sync-greeter-wallpaper", builder)

    def test_payload_is_checked_at_copy_and_first_boot_boundaries(self):
        installer = (ROOT / "environment/image/installer.ks.tmpl").read_text()
        firstboot = (ROOT / "environment/production/provision-firstboot.sh").read_text()
        builder = (ROOT / "environment/image/build-iso.sh").read_text()
        self.assertIn("sha256sum --quiet -c payload.sha256", installer)
        self.assertIn("greyward-payload-check.log", installer)
        self.assertIn("media_root", installer)
        self.assertIn("payload copy did not create", installer)
        self.assertIn("temporary_media_mount", installer)
        self.assertIn("target_stage=/mnt/sysroot/usr/lib/greyward/installer/production", installer)
        self.assertNotIn("target_stage=/mnt/sysroot/var/lib/greyward/installer/production", installer)
        self.assertIn("install -d -m 0755 /mnt/sysroot/var/lib/greyward/installer", installer)
        self.assertIn("touch /mnt/sysroot/var/lib/greyward/installer/production-pending", installer)
        self.assertIn("stage=/usr/lib/greyward/installer/production", firstboot)
        self.assertIn("sha256sum --quiet -c payload.sha256", firstboot)
        self.assertIn("payload-check.txt", firstboot)
        self.assertIn("payload-copy", builder)

    def test_fresh_anaconda_install_skips_duplicate_rpm_resolution_only_with_marker(self):
        installer = (ROOT / "environment/image/installer.ks.tmpl").read_text()
        provision = (ROOT / "environment/production/provision.sh").read_text()
        marker = "anaconda-package-closure-installed"
        self.assertIn(marker, installer)
        self.assertIn(marker, provision)
        self.assertIn("missing_packages=()", provision)
        self.assertIn("rpm -q \"$package\"", provision)
        self.assertIn("dnf -y --refresh upgrade", provision)
        self.assertIn("if [[ \"$anaconda_closure_ready\" != true ]]", provision)
        self.assertIn('dnf -y install "${branding_rpms[0]}" "${security_rpms[@]}"', provision)

    def test_final_payload_closure_is_checked_against_provisioner_contract(self):
        validator = (ROOT / "environment/image/validate-production-stage.sh").read_text()
        builder = (ROOT / "environment/image/build-iso.sh").read_text()
        self.assertIn('payload.sha256', validator)
        self.assertIn('require_file', validator)
        self.assertIn('provisioner', validator)
        self.assertIn('stage_validator', builder)
        self.assertIn('publication/production', builder)
        self.assertLess(
            builder.index('python3 "$repo_root/environment/image/build-offline.py" --stage'),
            builder.index('bash "$stage_validator" "$stage/production"'),
        )
        self.assertLess(
            builder.index('find . -type f ! -name payload.sha256'),
            builder.index('bash "$stage_validator" "$stage/production"'),
        )

    def test_vmware_validator_checks_embedded_installer_copy_boundary(self):
        validator = (ROOT / "tools/greyward-dev/validate-vmware-iso.py").read_text()
        self.assertIn('read_iso_path("/INSTALLER.KS;1")', validator)
        self.assertIn('media_root', validator)
        self.assertIn('payload copy did not create', validator)
        self.assertIn('target_stage=/mnt/sysroot/usr/lib/greyward/installer/production', validator)
        self.assertIn('still stages production under the variable /var mount', validator)
        self.assertIn('obsolete single-path production copy', validator)

    def test_iso_builder_syntax_check_normalizes_windows_line_endings(self):
        builder = (ROOT / "environment/image/build-iso.sh").read_text()
        self.assertIn("tr -d '\\r' < \"$path\" | bash -n", builder)
        self.assertNotIn('bash -n "$repo_root/environment/production/provision.sh"', builder)

    def test_baseline_excludes_retired_desktop_packages_from_floor_checks(self):
        baseline = (ROOT / "environment/image/baseline.py").read_text()
        offline = (ROOT / "environment/image/build-offline.py").read_text()
        self.assertIn('"kitty-kitten"', baseline)
        self.assertIn('"tabby"', baseline)
        self.assertIn('OMITTED_RPM_NAMES', offline)

    def test_vmware_candidate_preflight_refuses_persistent_iso_boot(self):
        source = (ROOT / "tools/greyward-dev/validate-vmware-candidate.ps1").read_text()
        iso_checker = (ROOT / "tools/greyward-dev/validate-vmware-iso.py").read_text()
        self.assertIn('bios.bootOrder', source)
        self.assertIn('sata0:1.fileName', source)
        self.assertIn('vmrun.exe', source)
        self.assertIn('pycdlib', iso_checker)
        self.assertIn('Rock Ridge', iso_checker)

    def test_dms_offline_missing_archive_has_no_download_fallback(self):
        source = (ROOT / "environment/production/install-dms.sh").read_text()
        offline_branch = source.split('elif [[ "${GREYWARD_OFFLINE_INSTALL:-0}" == 1 ]]; then')[1].split("else")[0]
        self.assertIn("exit 1", offline_branch)
        self.assertNotIn("curl", offline_branch)


if __name__ == "__main__":
    unittest.main()
