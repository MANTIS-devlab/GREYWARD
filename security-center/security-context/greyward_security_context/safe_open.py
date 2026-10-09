"""Descriptor-bound selected documents through the shared Application Guard."""
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import threading
import stat

SECRET_DIRS={".ssh",".gnupg",".pki","private","secrets","credentials"}
SECRET_NAMES={"passwd","shadow","gshadow","authorized_keys","id_rsa","id_ed25519","credentials.json","secrets.json"}
SUPPORTED_IMAGE_TYPES={"image/png","image/jpeg","image/gif","image/webp","image/svg+xml","image/tiff","image/bmp"}
DESKTOP_ENTRY_DIRS=("user", "user-flatpak", "system-flatpak", "system", "system-local")
HANDLER_COMMAND_TIMEOUT=5
class SafeOpenError(Exception): pass

def _roots(home=None):
 home=Path(home or Path.home())
 return [home/"Downloads",home/"Documents",home/"Desktop",Path("/run/media")/str(os.getuid()),Path("/media")/str(os.getuid()),Path("/mnt")]

def validate_path(raw, roots=None):
 if not isinstance(raw,str) or not raw.strip(): raise SafeOpenError("A file must be explicitly selected.")
 if len(raw)>4096 or "\0" in raw: raise SafeOpenError("The selected file path is invalid.")
 candidate=Path(raw).expanduser()
 if not candidate.is_absolute(): raise SafeOpenError("Safe Open requires an absolute file path.")
 try: path=candidate.resolve(strict=True)
 except (OSError,ValueError,RuntimeError) as error: raise SafeOpenError("The selected file is unavailable.") from error
 if not path.is_file(): raise SafeOpenError("Safe Open accepts regular files only.")
 allowed=False
 for root in (roots or _roots()):
  try:
   allowed=path.is_relative_to(Path(root).resolve())
  except (OSError,ValueError): allowed=False
  if allowed: break
 if not allowed: raise SafeOpenError("Safe Open permits only Downloads, Documents, Desktop, removable media, or /mnt.")
 lowered={part.lower() for part in path.parts}
 if lowered & SECRET_DIRS or path.name.lower() in SECRET_NAMES:
  raise SafeOpenError("Safe Open refuses credential and secret locations.")
 return path

class SelectedFile:
 """Held selected inode, not Protected Data classification or an immutable copy."""
 def __init__(self,raw,roots=None):
  self.fd=None
  self.path=validate_path(raw,roots)
  parent=None
  try:
   expected=self.path.stat(follow_symlinks=False)
   parent=os.open("/",os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
   for component in self.path.parts[1:-1]:
    next_parent=os.open(component,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)
    os.close(parent); parent=next_parent
   self.fd=os.open(self.path.name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
   current=os.fstat(self.fd)
   if not stat.S_ISREG(current.st_mode) or self._stamp(current)!=self._stamp(expected):
    raise SafeOpenError("The selected file changed; select it again.")
   self.stamp=self._stamp(current)
  except (OSError,ValueError) as error:
   self.close()
   raise SafeOpenError("The selected file is unavailable or changed.") from error
  except SafeOpenError:
   self.close(); raise
  finally:
   if parent is not None: os.close(parent)
 @staticmethod
 def _stamp(value):
  return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_nlink)
 def revalidate(self):
  if self.fd is None or self._stamp(os.fstat(self.fd))!=self.stamp:
   raise SafeOpenError("The selected file changed; select it again.")
 def close(self):
  if self.fd is not None:
   os.close(self.fd); self.fd=None
 def __enter__(self): return self
 def __exit__(self,*unused): self.close()

def _display_path(path):
 name=path.name[:160]
 return "/run/greyward-open/Safe Open - " + name

def _desktop_dirs():
 home=Path.home()
 data=Path(os.environ.get("XDG_DATA_HOME",str(home/".local/share")))
 if not data.is_absolute(): data=home/".local/share"
 return {
  "user":data/"applications",
  "user-flatpak":data/"flatpak/exports/share/applications",
  "system-flatpak":Path("/var/lib/flatpak/exports/share/applications"),
  "system":Path("/usr/share/applications"),
  "system-local":Path("/usr/local/share/applications"),
 }

def _desktop_value(desktop_path,key):
 try: lines=desktop_path.read_text(encoding="utf-8",errors="replace").splitlines()
 except OSError: return ""
 return next((line[len(key)+1:].strip() for line in lines if line.startswith(key+"=")),"")

def _desktop_supports(desktop_path,content_type):
 mime_types={item.strip() for item in _desktop_value(desktop_path,"MimeType").split(";") if item.strip()}
 return content_type in mime_types or (content_type.startswith("text/") and "text/*" in mime_types) or (content_type.startswith("image/") and "image/*" in mime_types)

def _supported_type(content_type):
 return content_type.startswith("text/") or content_type in SUPPORTED_IMAGE_TYPES

def resolve_application(path,selected_fd=None):
 """Resolve an explicit supported text/image handler without a shell."""
 try:
  source=str(path) if selected_fd is None else f"/proc/self/fd/{selected_fd}"
  info=subprocess.run(["gio","info","-a","standard::content-type",source],capture_output=True,text=True,check=False,timeout=HANDLER_COMMAND_TIMEOUT,pass_fds=() if selected_fd is None else (selected_fd,))
 except (OSError,subprocess.SubprocessError) as error:
  raise SafeOpenError("Safe Open could not determine the file type.") from error
 content_type=""
 for line in info.stdout.splitlines():
  if "standard::content-type:" in line:
   content_type=line.split("standard::content-type:",1)[1].strip().split()[0]
   break
 if not content_type: raise SafeOpenError("Safe Open could not determine the file type.")
 if not _supported_type(content_type): raise SafeOpenError(f"Safe Open does not support this file type ({content_type}).")
 try:
  default=subprocess.run(["xdg-mime","query","default",content_type],capture_output=True,text=True,check=False,timeout=HANDLER_COMMAND_TIMEOUT)
 except (OSError,subprocess.SubprocessError) as error:
  raise SafeOpenError("Safe Open could not determine the configured file handler.") from error
 desktop=default.stdout.strip()
 directories=_desktop_dirs()
 candidates=[directories[name]/desktop for name in DESKTOP_ENTRY_DIRS] if desktop else []
 desktop_path=next((item for item in candidates if item.is_file()),None)
 if desktop_path is None:
  fallback=[]
  for name in DESKTOP_ENTRY_DIRS:
   directory=directories[name]
   try: fallback.extend(item for item in directory.glob("*.desktop") if item.is_file() and _desktop_supports(item,content_type))
   except OSError: pass
  desktop_path=next(iter(fallback),None)
 if desktop_path is None:
  if desktop: raise SafeOpenError("The configured file handler is unavailable or does not support this file type.")
  raise SafeOpenError("No compatible Safe Open handler is installed for this file type.")
 exec_line=_desktop_value(desktop_path,"Exec")
 if not exec_line: raise SafeOpenError("The configured file handler has no launch command.")
 try: tokens=shlex.split(exec_line)
 except ValueError as error: raise SafeOpenError("The configured file handler is invalid.") from error
 argv=[]; inserted=False
 for token in tokens:
  if token in {"%f","%F","%u","%U"}:
   argv.append(_display_path(path)); inserted=True
  elif token in {"%i","%c","%k"} or token.startswith("%"):
   continue
  else: argv.append(token)
 if not argv: raise SafeOpenError("The configured file handler is unsupported.")
 executable=shutil.which(argv[0])
 if not executable: raise SafeOpenError("The configured file handler is unavailable.")
 argv[0]=executable
 if not inserted: argv.append("/run/greyward-open/input")
 return argv
def launch(raw, roots=None, workflows=None, actor=None):
 with SelectedFile(raw,roots) as selected:
  application=resolve_application(selected.path,selected_fd=selected.fd)
  selected.revalidate()
  if Path(application[0]).name == "flatpak":
   raise SafeOpenError("The configured Flatpak handler has no supported private Safe Open launch. Choose a native handler; existing Flatpak permissions were not changed.")
  if workflows is not None:
   # The broker classifies the held inode against mandatory resource labels.
   # No generic document export or path-based reopening can override a grant.
   from .application_security import ApplicationReadError
   import dbus
   arguments=["/run/guard-document" if item in {_display_path(selected.path),"/run/greyward-open/input"} else item for item in application[1:]]
   if any("/run/greyward-open/" in item for item in arguments):
    raise SafeOpenError("The configured file handler requires an unsupported selection format.")
   try:
    review=workflows.prepare_launch(actor,dbus.types.UnixFd(selected.fd),handler=application[0],arguments=arguments)
    process,_=workflows.start_launch(actor,review["launch_ref"])
   except ApplicationReadError as error:
    raise SafeOpenError("Application Guard could not establish the selected-file isolation; no fallback was launched.") from error
   return process,selected.path
  raise SafeOpenError("Application Guard is unavailable; Safe Open refused to launch a standalone fallback.")

def redact_error(error):
 return str(error).replace(str(Path.home()),"~")[:240]

def monitor(process, callback):
 def wait():
  from .application_security import ApplicationReadError
  try: code=process.wait()
  except (OSError,RuntimeError,ApplicationReadError): code=None
  callback(code)
 threading.Thread(target=wait,daemon=True).start()
