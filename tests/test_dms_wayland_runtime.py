"""Protect the private DMS runtime while making its Wayland path resolvable."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SESSION = ROOT / 'security-center/packaging/application-security/desktop/session.py'
OUTPUT_PATCH = ROOT / 'environment/patches/dms/greyward-wlr-output-readiness.patch'
UNIT = ROOT / 'environment/session/greyward-dms.service'


class DmsWaylandRuntimeTests(unittest.TestCase):
    def test_auth_shell_uses_relative_socket_in_its_private_runtime(self):
        source = SESSION.read_text()
        self.assertIn("'XDG_RUNTIME_DIR': str(auth / 'runtime')", source)
        self.assertIn("'WAYLAND_DISPLAY': 'wayland-0'", source)
        self.assertNotIn("'WAYLAND_DISPLAY': f'/run/user/{uid}/wayland-0'", source)

    def test_fixed_socket_alias_is_created_in_auth_worker_startup(self):
        source = SESSION.read_text()
        launch = source.index("for kind in ['display', 'authentication']:")
        alias_creation = source.index("os.symlink(str(target), runtime / 'wayland-0')")
        spawn = source.index("subprocess.Popen(['/usr/bin/python3', '-I', str(BASE / 'session.py')")
        wait_for_display = source.index("if kind == 'display':\n                end = time.monotonic()")
        self.assertGreater(alias_creation, launch)
        self.assertLess(alias_creation, spawn)
        self.assertGreater(wait_for_display, spawn)
        self.assertIn("if not target.is_socket() or socket_stat.st_uid != uid:", source)
        self.assertIn("runtime_stat.st_mode & 0o077", source)

    def test_dms_unit_overrides_absolute_manager_display_path(self):
        unit = UNIT.read_text()
        service = unit.split('[Service]', 1)[1].split('[Install]', 1)[0]
        self.assertEqual(service.count('Environment=WAYLAND_DISPLAY=wayland-0'), 1)
        self.assertNotIn('Environment=WAYLAND_DISPLAY=/run/', service)

    def test_stale_alias_cleanup_rejects_non_symlink_objects(self):
        source = SESSION.read_text()
        cleanup = source.index("['authentication.log', 'authentication-ready.json', 'bus', 'wayland-0']")
        check = source.index("if name == 'wayland-0' and not old.is_symlink():", cleanup)
        self.assertGreater(check, cleanup)

    def test_wlr_output_readiness_comes_from_actual_state_response(self):
        patch = OUTPUT_PATCH.read_text()
        additions = '\n'.join(line[1:] for line in patch.splitlines()
                              if line.startswith('+') and not line.startswith('+++'))
        self.assertIn('Component.onCompleted: requestState()', additions)
        self.assertIn('onWlrOutputAvailableChanged:', additions)
        self.assertIn('DMS connection state changed:', additions)
        self.assertIn('interval: 1000', additions)
        self.assertIn('running: DMSService.isConnected && !wlrOutputAvailable', additions)
        self.assertIn('onTriggered: requestState()', additions)
        self.assertIn('requestState();', additions)
        self.assertIn('DMSService.sendRequest("wlroutput.getState", null, response => {', additions)
        self.assertIn('if (response.error || !response.result || !Array.isArray(response.result.outputs)) {', additions)
        self.assertIn('wlrOutputAvailable = true;', additions)
        self.assertIn('}, 5000);', additions)
        self.assertNotIn('checkCapabilities', additions)
        self.assertNotIn('DMSService.capabilities', additions)


if __name__ == '__main__':
    unittest.main()
