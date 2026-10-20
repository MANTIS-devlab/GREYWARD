import tempfile
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from greyward_security_context.network_applications import launch_target, describe, packaged_target


class ApplicationCatalogTests(unittest.TestCase):
    def test_env_is_parsed_without_launching_and_shared_runtimes_are_not_app_scopes(self):
        with patch('greyward_security_context.network_applications.shutil.which', return_value='/usr/bin/editor'):
            self.assertEqual(launch_target('/usr/bin/env FOO=1 editor %F'), ('/usr/bin/editor', None))
        for command in ('flatpak run org.example.App', 'bwrap --args 1', 'python3 app.py', 'bash -c anything'):
            self.assertIsNone(launch_target(command)[0])
        self.assertIsNone(launch_target('env -S ambiguous')[0])
        self.assertIsNone(launch_target('"broken')[0])

    @unittest.skipUnless(os.name == "posix", "Native Unix executable metadata")
    def test_native_catalog_does_not_execute_desktop_commands_or_guess_wrapper_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'editor';binary.write_bytes(b'\x7fELFmock');binary.chmod(0o755)
            info=SimpleNamespace(get_id=lambda:'org.example.Editor.desktop',get_display_name=lambda:'Editor',get_name=lambda:'Editor',get_commandline=lambda:str(binary)+' %F')
            result=describe(info)
            self.assertTrue(result['supported']);self.assertEqual(result['path'],str(binary));self.assertEqual(result['name'],'Editor')
            info.get_string=lambda key:'org.example.Flatpak'
            self.assertFalse(describe(info)['supported']);self.assertEqual(describe(info)['reason'],'flatpak')

    def test_only_unique_packaged_same_name_elf_may_resolve_a_launcher(self):
        result=SimpleNamespace(returncode=0,stdout=b'/usr/lib64/editor/editor\n/usr/libexec/editor\n')
        with patch('greyward_security_context.network_applications.subprocess.run',return_value=result) as query,patch('greyward_security_context.network_applications.elf_target',side_effect=lambda p:p):
            self.assertIsNone(packaged_target('/usr/share/applications/editor.desktop','/usr/bin/editor'))
            query.assert_called_once()
        with patch('greyward_security_context.network_applications.subprocess.run') as query:
            self.assertIsNone(packaged_target('/home/user/.local/share/applications/fake.desktop','/usr/bin/editor'))
            query.assert_not_called()

if __name__=='__main__':unittest.main()
