"""Exercise packaged session startup against an unmodified UWSM Labwc plugin."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'Run on Fedora with the real upstream UWSM plugin')
class SessionPolicyTests(unittest.TestCase):
    def test_fresh_home_and_runtime_parents_make_upstream_quirk_work(self):
        plugin = Path('/usr/share/uwsm/plugins/labwc.sh')
        if not plugin.exists():
            self.skipTest('UWSM is required')
        original = plugin.read_bytes()
        self.assertNotIn(b'GREYWARD_UWSM_LABWC_DROPIN_DIRECTORY', original)
        for rung in ('run', 'home'):
            with self.subTest(rung=rung), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); binaries = root/'bin'; binaries.mkdir()
                runtime = root/'run'; runtime.mkdir(mode=0o700)
                (binaries/'systemctl').write_text('#!/bin/sh\nexit 0\n')
                (binaries/'uwsm').write_text('''#!/bin/sh
set -e
test "$*" = 'start -D Labwc:GREYWARD labwc'
__WM_ID_UNIT_STRING__=labwc
__WM_ID__=labwc
__WM_DESKTOP_NAMES_EXCLUSIVE__=false
XDG_CURRENT_DESKTOP=Labwc
UWSM_FINALIZE_VARNAMES=''
UWSM_WAIT_VARNAMES=''
. /usr/share/uwsm/plugins/labwc.sh
quirks_labwc
''')
                for file in binaries.iterdir(): file.chmod(0o755)
                env = dict(os.environ, HOME=str(root/'home'), XDG_CONFIG_HOME=str(root/'config'),
                           XDG_RUNTIME_DIR=str(runtime), PATH=str(binaries)+':'+os.environ['PATH'], UWSM_UNIT_RUNG=rung)
                subprocess.run(['sh', str(ROOT/'environment/production/greyward-start-labwc')], env=env, check=True)
                for parent in (root/'config', runtime):
                    self.assertTrue((parent/'systemd/user/wayland-wm@labwc.service.d').is_dir())
                self.assertIn('ExecReload=kill -SIGHUP', (runtime/'systemd/user/wayland-wm@labwc.service.d/55_reload.conf').read_text())
                self.assertEqual(plugin.read_bytes(), original)


if __name__ == '__main__': unittest.main()
