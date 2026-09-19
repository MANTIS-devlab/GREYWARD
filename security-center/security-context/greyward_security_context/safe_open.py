"""Disposable, fail-closed file opening using bubblewrap."""
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import threading

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
 candidate=Path(raw).expanduser()
 if not candidate.is_absolute(): raise SafeOpenError("Safe Open requires an absolute file path.")
 try: path=candidate.resolve(strict=True)
 except OSError as error: raise SafeOpenError("The selected file is unavailable.") from error
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

def _display_path(path):
 name=path.name[:160]
 return "/run/greyward-open/Safe Open - " + name

def _desktop_dirs():
 home=Path.home()
 return {
  "user":home/".local/share/applications",
  "user-flatpak":home/".local/share/flatpak/exports/share/applications",
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

def resolve_application(path):
 """Resolve an explicit supported text/image handler without a shell."""
 try:
  info=subprocess.run(["gio","info","-a","standard::content-type",str(path)],capture_output=True,text=True,check=False,timeout=HANDLER_COMMAND_TIMEOUT)
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
def build_command(path, bwrap="/usr/bin/bwrap", runtime=None, application=None):
 if not Path(bwrap).is_file(): raise SafeOpenError("bubblewrap is unavailable; Safe Open refused to fall back.")
 runtime=Path(runtime or os.environ.get("XDG_RUNTIME_DIR",""))
 if not runtime.is_dir(): raise SafeOpenError("The graphical session runtime is unavailable.")
 application=application or ["/usr/bin/xdg-open"]
 command=[bwrap,"--die-with-parent","--new-session","--unshare-all","--unshare-net","--clearenv",
          "--ro-bind","/usr","/usr","--ro-bind","/bin","/bin","--ro-bind","/lib","/lib"]
 if Path("/lib64").exists(): command += ["--ro-bind","/lib64","/lib64"]
 command += ["--proc","/proc","--dev","/dev",
             "--tmpfs","/tmp","--dir","/run","--dir","/run/greyward-open",
             "--ro-bind",str(path),"/run/greyward-open/input",
             "--ro-bind",str(path),_display_path(path),
             "--ro-bind","/etc/passwd","/etc/passwd","--ro-bind","/etc/group","/etc/group",
             "--ro-bind","/etc/nsswitch.conf","/etc/nsswitch.conf",
             "--ro-bind","/etc/mime.types","/etc/mime.types","--ro-bind","/etc/xdg","/etc/xdg",
             "--ro-bind","/usr/share/applications","/usr/share/applications"]
 mimeapps=Path.home()/".config/mimeapps.list"
 if mimeapps.is_file():
  command += ["--dir","/tmp/.config","--ro-bind",str(mimeapps),"/tmp/.config/mimeapps.list"]
 wayland_display=os.environ.get("WAYLAND_DISPLAY","")
 wayland_socket=runtime/wayland_display if wayland_display else None
 if wayland_socket and wayland_socket.is_socket():
  command += ["--ro-bind",str(wayland_socket),"/run/wayland-0"]
 user_apps=Path.home()/".local/share/applications"
 if user_apps.is_dir(): command += ["--dir","/tmp/.local/share/applications","--ro-bind",str(user_apps),"/tmp/.local/share/applications"]
 flatpak_store=Path.home()/".local/share/flatpak"
 if flatpak_store.is_dir(): command += ["--dir","/tmp/.local/share/flatpak","--ro-bind",str(flatpak_store),"/tmp/.local/share/flatpak"]
 if Path("/var/lib/flatpak").is_dir(): command += ["--ro-bind","/var/lib/flatpak","/var/lib/flatpak"]
 if Path("/var/lib/flatpak/exports/share/applications").is_dir(): command += ["--ro-bind","/var/lib/flatpak/exports/share/applications","/var/lib/flatpak/exports/share/applications"]
 executable=Path(str(application[0]))
 if executable.is_absolute() and executable.exists() and len(executable.parts)>1 and executable.parts[1] not in {"usr","bin","lib","lib64"}:
  command += ["--ro-bind",str(executable),str(executable)]
 command += ["--setenv","HOME","/tmp","--setenv","PATH","/usr/bin:/bin",
             "--setenv","XDG_CURRENT_DESKTOP","GNOME","--setenv","GIO_USE_PORTALS","0",
             "--setenv","GTK_THEME","Adwaita:dark",
             "--setenv","GTK_APPLICATION_PREFER_DARK_THEME","1",
             "--setenv","ADW_DEBUG_COLOR_SCHEME","prefer-dark",
             "--setenv","QT_QPA_PLATFORMTHEME","gtk3",
             "--setenv","GREYWARD_SAFE_OPEN","1",
             "--setenv","WAYLAND_DISPLAY","wayland-0",
             "--setenv","XDG_RUNTIME_DIR","/run","--chdir","/tmp",
             "--"] + application
 return command

def launch(raw, roots=None, popen=subprocess.Popen):
 path=validate_path(raw,roots)
 application=resolve_application(path)
 command=build_command(path,application=application)
 try: process=popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 except OSError as error: raise SafeOpenError("The restricted Safe Open process could not start.") from error
 return process, path

def redact_error(error):
 return str(error).replace(str(Path.home()),"~")[:240]

def monitor(process, callback):
 def wait():
  code=process.wait()
  callback(code)
 threading.Thread(target=wait,daemon=True).start()
