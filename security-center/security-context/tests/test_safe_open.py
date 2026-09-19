import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess
from greyward_security_context.safe_open import SafeOpenError, build_command, resolve_application, validate_path

class SafeOpenTests(unittest.TestCase):
 def test_permitted_file_is_bound_read_only_and_network_is_unshared(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"sample.txt"; path.write_text("fixture",encoding="utf-8")
   selected=validate_path(str(path),[Path(root)])
   bwrap=Path(root)/"bwrap"; bwrap.write_text("",encoding="utf-8")
   command=build_command(selected,bwrap=str(bwrap),runtime=root)
   self.assertIn("--unshare-net",command)
   self.assertIn("--ro-bind",command)
   self.assertIn(str(path),command)
   self.assertNotIn(str(Path.home()),command)
 def test_secret_and_directory_are_refused(self):
  with tempfile.TemporaryDirectory() as root:
   secret=Path(root)/".ssh"; secret.mkdir(); (secret/"id_rsa").write_text("x",encoding="utf-8")
   with self.assertRaises(SafeOpenError): validate_path(str(secret/"id_rsa"),[Path(root)])
   with self.assertRaises(SafeOpenError): validate_path(root,[Path(root)])
 def test_malformed_and_relative_paths_are_refused(self):
  with self.assertRaises(SafeOpenError): validate_path("",[])
  with self.assertRaises(SafeOpenError): validate_path("relative.txt",[])
 def test_outside_explicit_roots_is_refused(self):
  with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as other:
   path=Path(other)/"sample.txt"; path.write_text("fixture",encoding="utf-8")
   with self.assertRaises(SafeOpenError): validate_path(str(path),[Path(allowed)])

 def test_supported_type_uses_system_flatpak_export_and_preserves_special_name(self):
  import greyward_security_context.safe_open as safe_open
  with tempfile.TemporaryDirectory() as root:
   root=Path(root); path=root/"report [copy] ; $HOME.txt"; path.write_text("fixture",encoding="utf-8")
   directories={name:root/name for name in safe_open.DESKTOP_ENTRY_DIRS}
   for directory in directories.values(): directory.mkdir()
   desktop=directories["system-flatpak"] / "org.example.Viewer.desktop"
   desktop.write_text("[Desktop Entry]\nType=Application\nMimeType=text/plain;\nExec=flatpak run org.example.Viewer %F\n",encoding="utf-8")
   responses=[type("Result",(),{"stdout":"  standard::content-type: text/plain\n"})(), type("Result",(),{"stdout":"\n"})()]
   with patch.object(safe_open,"_desktop_dirs",return_value=directories), patch("greyward_security_context.safe_open.subprocess.run",side_effect=responses), patch("greyward_security_context.safe_open.shutil.which",return_value="/usr/bin/flatpak"):
    command=resolve_application(path)
   self.assertEqual(command[:4],["/usr/bin/flatpak","run","org.example.Viewer",safe_open._display_path(path)])

 def test_unsupported_type_and_missing_handler_are_truthful(self):
  import greyward_security_context.safe_open as safe_open
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"sample.bin"; path.write_bytes(b"fixture")
   with patch("greyward_security_context.safe_open.subprocess.run",return_value=type("Result",(),{"stdout":"standard::content-type: application/octet-stream\n"})()):
    with self.assertRaisesRegex(SafeOpenError,"does not support"):
     resolve_application(path)
   responses=[type("Result",(),{"stdout":"standard::content-type: text/plain\n"})(),type("Result",(),{"stdout":"\n"})()]
   with patch("greyward_security_context.safe_open.subprocess.run",side_effect=responses), patch.object(safe_open,"_desktop_dirs",return_value={name:Path(root)/name for name in safe_open.DESKTOP_ENTRY_DIRS}):
    with self.assertRaisesRegex(SafeOpenError,"No compatible"):
     resolve_application(path)

 def test_handler_discovery_timeout_fails_closed(self):
  import greyward_security_context.safe_open as safe_open
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"sample.txt"; path.write_text("fixture",encoding="utf-8")
   with patch("greyward_security_context.safe_open.subprocess.run",side_effect=subprocess.TimeoutExpired("gio",5)):
    with self.assertRaisesRegex(SafeOpenError,"could not determine"):
     resolve_application(path)
if __name__=="__main__": unittest.main()
