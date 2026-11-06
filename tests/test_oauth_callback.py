"""Native CIL linking, including installation before ordinary-role enrollment."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'environment/session/greyward_oauth_callback.cil'
BASE = '''
(class tcp_socket (name_bind))
(classorder (tcp_socket))
(sid kernel)
(sidorder (kernel))
(type kernel_t)
(typeattribute port_type)
(typeattribute unreserved_port_type)
(role object_r)
(roletype object_r kernel_t)
(user system_u)
(userrole system_u object_r)
(sensitivity s0)
(sensitivityorder (s0))
(level l0 (s0))
(levelrange r0 (l0 l0))
(userlevel system_u l0)
(userrange system_u r0)
(sidcontext kernel (system_u object_r kernel_t r0))
(allow kernel_t kernel_t (tcp_socket (name_bind)))
'''


class OAuthCallback(unittest.TestCase):
    @unittest.skipUnless(shutil.which('secilc'), 'Native SELinux CIL compiler')
    def test_before_and_after_enrollment_link_with_only_the_named_bind_grant(self):
        import setools
        for enrolled in (False, True):
            with self.subTest(enrolled=enrolled), tempfile.TemporaryDirectory() as raw:
                work = Path(raw)
                (work / 'base.cil').write_text(BASE + ('\n(type greyward_guard_t)\n' if enrolled else ''))
                subprocess.run(['secilc', '-M', 'true', '-o', str(work / 'policy'),
                                '-f', str(work / 'contexts'), str(work / 'base.cil'), str(MODULE)],
                               check=True, capture_output=True, text=True)
                policy = setools.SELinuxPolicy(str(work / 'policy'))
                ports = list(policy.portcons())
                self.assertEqual(len(ports), 1)
                self.assertEqual((ports[0].ports.low, ports[0].ports.high), (1455, 1455))
                self.assertEqual(str(ports[0].protocol), 'tcp')
                grants = list(setools.TERuleQuery(policy, target='greyward_oauth_callback_port_t',
                                                 ruletype=['allow']).results())
                self.assertEqual(len(grants), int(enrolled))
                if grants:
                    self.assertEqual(str(grants[0].source), 'greyward_guard_t')
                    self.assertEqual(str(grants[0].tclass), 'tcp_socket')
                    self.assertEqual(set(grants[0].perms), {'name_bind'})

    def test_package_installs_removes_and_checks_the_same_policy_input(self):
        spec = (ROOT / 'packaging/greyward-session/greyward-session.spec').read_text()
        self.assertIn('%selinux_modules_install -s targeted /usr/share/selinux/packages/greyward_oauth_callback.cil', spec)
        self.assertIn('%selinux_modules_uninstall -s targeted greyward_oauth_callback', spec)
        self.assertNotIn('setsebool', spec)
        verifier = (ROOT / 'environment/image/verify-usbguard-inputs.py').read_text()
        self.assertIn("'environment/session/greyward_oauth_callback.cil': '/usr/share/selinux/packages/greyward_oauth_callback.cil'", verifier)
        acceptance = (ROOT / 'environment/production/production-acceptance.sh').read_text()
        self.assertIn("setools.SELinuxPolicy('/sys/fs/selinux/policy')", acceptance)
        self.assertIn("str(row.context.type_) == 'greyward_oauth_callback_port_t'", acceptance)
