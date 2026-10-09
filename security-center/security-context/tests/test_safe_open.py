import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess
from greyward_security_context.safe_open import SafeOpenError, SelectedFile, resolve_application, validate_path, launch
import os
import sys
from types import SimpleNamespace
from greyward_security_context.application_security import ApplicationReadError

class SafeOpenTests(unittest.TestCase):
 def test_flatpak_handler_is_truthfully_unavailable_without_wrapping_or_fallback(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"selected.txt"; path.write_text("ordinary")
   with patch("greyward_security_context.safe_open.resolve_application",return_value=["/usr/bin/flatpak","run","org.example.Viewer","/run/greyward-open/input"]), patch("greyward_security_context.safe_open.subprocess.Popen") as start:
    with self.assertRaisesRegex(SafeOpenError,"Flatpak handler"):
     launch(str(path),[Path(root)])
    start.assert_not_called()
 def test_shared_runner_receives_held_selection_and_no_legacy_launch(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"selected.txt"; path.write_text("original")
   process=object(); actor=(1002,123,456); calls=[]
   def prepare(peer, descriptor, **options):
    self.assertEqual(peer,actor)
    self.assertEqual(os.pread(descriptor,64,0),b"original")
    self.assertEqual(options,{"handler":"/usr/bin/cat","arguments":["/run/guard-document"]})
    calls.append(descriptor)
    return {"launch_ref":"prepared"}
   workflows=SimpleNamespace(prepare_launch=prepare,start_launch=lambda peer,ref:(process,{}))
   with patch.dict(sys.modules,{"dbus":SimpleNamespace(types=SimpleNamespace(UnixFd=lambda fd:fd))}), patch("greyward_security_context.safe_open.resolve_application",return_value=["/usr/bin/cat","/run/greyward-open/input"]), patch("greyward_security_context.safe_open.subprocess.Popen") as legacy:
    self.assertEqual(launch(str(path),[Path(root)],workflows=workflows,actor=actor),(process,path))
    legacy.assert_not_called()
   with self.assertRaises(OSError): os.fstat(calls[0])

 def test_shared_runner_failure_never_launches_legacy_fallback(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"selected.txt"; path.write_text("original")
   def unavailable(*args,**kwargs): raise ApplicationReadError("BROKER_UNAVAILABLE")
   workflows=SimpleNamespace(prepare_launch=unavailable)
   with patch.dict(sys.modules,{"dbus":SimpleNamespace(types=SimpleNamespace(UnixFd=lambda fd:fd))}), patch("greyward_security_context.safe_open.resolve_application",return_value=["/usr/bin/cat","/run/greyward-open/input"]), patch("greyward_security_context.safe_open.subprocess.Popen") as legacy:
    with self.assertRaisesRegex(SafeOpenError,"no fallback"):
     launch(str(path),[Path(root)],workflows=workflows,actor=(1002,123,456))
    legacy.assert_not_called()

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

 def test_replacement_after_preparation_does_not_change_the_inherited_selection(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"selected.txt"; path.write_text("original")
   replacement=Path(root)/"replacement.txt"; replacement.write_text("replacement")
   saved=[]
   def prepare(actor,fd,**options):
    replacement.replace(path)
    saved.append(fd)
    self.assertEqual(os.pread(fd,64,0),b"original")
    self.assertNotIn(str(path),options["arguments"])
    return {"launch_ref":"prepared"}
   workflows=SimpleNamespace(prepare_launch=prepare,start_launch=lambda actor,reference:(object(),{}))
   with patch.dict(sys.modules,{"dbus":SimpleNamespace(types=SimpleNamespace(UnixFd=lambda fd:fd))}), patch("greyward_security_context.safe_open.resolve_application",return_value=["/usr/bin/cat","/run/greyward-open/input"]):
    launch(str(path),[Path(root)],workflows=workflows,actor=(1002,123,456))
   with self.assertRaises(OSError): os.fstat(saved[0])

 def test_content_mutation_during_handler_resolution_refuses_launch(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"selected.txt"; path.write_text("original")
   def handler(*args,**kwargs):
    path.write_text("changed content")
    return ["/usr/bin/cat","/run/greyward-open/input"]
   with patch("greyward_security_context.safe_open.resolve_application",side_effect=handler), patch("greyward_security_context.safe_open.subprocess.Popen") as start:
    with self.assertRaisesRegex(SafeOpenError,"changed"):
     launch(str(path),[Path(root)])
    start.assert_not_called()

 def test_parent_symlink_replacement_is_refused_without_opening_its_target(self):
  import greyward_security_context.safe_open as module
  with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
   parent=Path(root)/"documents"; parent.mkdir()
   path=parent/"selected.txt"; path.write_text("original")
   (Path(outside)/"selected.txt").write_text("outside")
   original=module.validate_path
   def changed(*args,**kwargs):
    result=original(*args,**kwargs)
    parent.rename(Path(root)/"saved")
    parent.symlink_to(outside,target_is_directory=True)
    return result
   with patch.object(module,"validate_path",side_effect=changed):
    with self.assertRaises(SafeOpenError): SelectedFile(str(path),[Path(root)])

 def test_spawn_failure_closes_the_held_descriptor(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"selected.txt"; path.write_text("original")
   saved=[]
   def failed(actor,fd,**options):
    saved.append(fd)
    raise ApplicationReadError("WORKER_FAILED")
   with patch.dict(sys.modules,{"dbus":SimpleNamespace(types=SimpleNamespace(UnixFd=lambda fd:fd))}), patch("greyward_security_context.safe_open.resolve_application",return_value=["/usr/bin/cat"]):
    with self.assertRaisesRegex(SafeOpenError,"no fallback"):
     launch(str(path),[Path(root)],workflows=SimpleNamespace(prepare_launch=failed),actor=(1002,123,456))
   with self.assertRaises(OSError): os.fstat(saved[0])

 def test_type_detection_uses_the_held_descriptor(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root)/"selected.bin"; path.write_text("original")
   with SelectedFile(str(path),[Path(root)]) as held:
    with patch("greyward_security_context.safe_open.subprocess.run",return_value=type("Result",(),{"stdout":"standard::content-type: application/octet-stream\n"})()) as run:
     with self.assertRaisesRegex(SafeOpenError,"does not support"):
      resolve_application(path,selected_fd=held.fd)
     self.assertEqual(run.call_args.args[0][-1],f"/proc/self/fd/{held.fd}")
     self.assertEqual(run.call_args.kwargs["pass_fds"],(held.fd,))
if __name__=="__main__": unittest.main()
