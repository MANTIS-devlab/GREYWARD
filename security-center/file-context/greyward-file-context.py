#!/usr/bin/env python3
import ast
import datetime as dt
import json
import logging
import subprocess
import sys
from threading import Thread
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, GLib, Gtk

BUS_NAME = "systems.mantis.greyward.SecurityContext1"
OBJECT_PATH = "/systems/mantis/greyward/SecurityContext1"
INTERFACE = "systems.mantis.greyward.SecurityContext1"

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("greyward-file-context")


def display_path(path: str) -> str:
    try:
        home = Path.home().resolve()
        selected = Path(path).resolve()
        return "~/" + str(selected.relative_to(home))
    except (OSError, ValueError):
        return Path(path).name or "Selected file"


def dbus_call(method: str, path: str | None = None) -> object:
    args = ["gdbus", "call", "--session", "--dest", BUS_NAME,
            "--object-path", OBJECT_PATH, "--method", f"{INTERFACE}.{method}"]
    if path is not None:
        args.append(path)
    completed = subprocess.run(args, text=True, capture_output=True, check=False, timeout=20)
    if completed.returncode != 0:
        raise RuntimeError("Security Context request failed")
    try:
        value = ast.literal_eval(completed.stdout.strip())[0]
        return json.loads(value) if isinstance(value, str) else value
    except (ValueError, SyntaxError, IndexError, json.JSONDecodeError) as exc:
        raise RuntimeError("Security Context returned an invalid result") from exc


def state(value, fallback="UNKNOWN") -> str:
    if isinstance(value, dict):
        return str(value.get("state") or fallback).upper()
    return str(value or fallback).upper()


def detail(value, fallback="Unknown") -> str:
    if isinstance(value, dict):
        return str(value.get("detail") or fallback)
    return str(value or fallback)


def first_item(data, key, fallback):
    values = data.get(key) or []
    return values[0] if isinstance(values, list) and values else fallback


def last_item(data, key, fallback):
    values = data.get(key) or []
    return values[-1] if isinstance(values, list) and values else fallback


def friendly_status(data) -> str:
    value = state(data.get("state") or data.get("security_status") or data.get("posture"), "UNAVAILABLE")
    return value if value in {"SECURE", "PROTECTED", "REVIEW NEEDED", "UNAVAILABLE"} else "UNAVAILABLE"


def friendly_source(value):
    current = state(value)
    if current in {"UNKNOWN", "UNAVAILABLE"}:
        return "Unknown origin" if current == "UNKNOWN" else "Unavailable"
    return detail(value, "Known source")


def pretty_time(value):
    stamp = value.get("occurred_at") if isinstance(value, dict) else None
    if not stamp:
        return "Unknown"
    try:
        parsed = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        return parsed.astimezone().strftime("%d %b %Y %H:%M")
    except (ValueError, TypeError):
        return "Unknown"

def friendly_seen(value):
    current = state(value)
    if current == "UNAVAILABLE":
        return "Unavailable"
    if current == "UNKNOWN":
        return "Before GREYWARD monitoring"
    return pretty_time(value)


def friendly_scan(value):
    current = state(value)
    if current in {"CLEAN", "NO_THREATS", "NO THREATS DETECTED"}:
        return "No threats detected"
    if current in {"THREAT", "THREAT DETECTED"}:
        return "Threat detected"
    if current == "UNAVAILABLE":
        return "Unavailable"
    return "Unknown"


def friendly_signature(value):
    current = state(value)
    if current in {"VERIFIED", "VALID"}:
        return "Verified"
    if current == "UNAVAILABLE":
        return "Unavailable"
    if current == "UNKNOWN":
        return "Not available"
    return "Not available"


def friendly_safe(value):
    current = state(value)
    if current in {"OBSERVED", "LAUNCHED", "OPENED", "SUCCESS"}:
        stamp = pretty_time(value)
        return stamp if stamp != "Unknown" else "Yes"
    if current in {"FAILED", "REFUSED", "DENIED"}:
        return "No"
    return "Never"


def scan_message(result):
    current = state(result)
    if current in {"CLEAN", "NO_THREATS", "NO THREATS DETECTED"}:
        return "No threats detected"
    if current in {"THREAT", "THREAT DETECTED"}:
        return "Threat detected"
    if current in {"FAILED", "ERROR"}:
        return "Scan failed"
    if current == "UNAVAILABLE":
        return "Scan unavailable"
    return "Scan completed"


def notify_scan(path, result):
    if state(result) in {"THREAT", "THREAT DETECTED"}:
        return
    message = scan_message(result)
    body = f"{message}:\n{Path(path).name}"
    subprocess.run(["notify-send", "GREYWARD Security", body], check=False, capture_output=True, text=True)

def friendly_sanitized(value):
    current = state(value)
    if current in {"SANITIZED", "CREATED", "SUCCESS"}:
        stamp = pretty_time(value)
        return "Created: " + stamp if stamp != "Unknown" else "Available"
    return "Not created"


class FileContext(Gtk.Application):
    def __init__(self, path: str):
        super().__init__(application_id="systems.mantis.greyward.filecontext")
        self.path = path
        self.window = None
        self.status = None
        self.context_box = None
        self._held = False
        self.scanning = False
        self.scan_button = None

    def do_activate(self):
        if self.window is None:
            self.hold()
            self._held = True
            self.window = Gtk.ApplicationWindow(application=self)
            self.window.set_title("Security Context")
            self.window.set_default_size(720, 680)
            self.window.set_resizable(True)
            self.window.set_decorated(True)
            self.window.connect("close-request", self._close_window)
            self._build_window()
        self.window.present()
        self._load_context()

    def _close_window(self, _window):
        if self._held:
            self.release()
            self._held = False
        self.scanning = False
        self.scan_button = None
        self.quit()
        return False

    def _build_window(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.add_css_class("file-context-window")
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        body.set_margin_top(30); body.set_margin_bottom(30)
        body.set_margin_start(32); body.set_margin_end(32)
        scroller = Gtk.ScrolledWindow(); scroller.set_child(body); scroller.set_vexpand(True)
        outer.append(scroller)
        self.window.set_child(outer)

        eyebrow = Gtk.Label(label="FILE SECURITY CONTEXT", xalign=0); eyebrow.add_css_class("eyebrow"); body.append(eyebrow)
        title = Gtk.Label(xalign=0); title.add_css_class("title-1"); body.append(title); self.file_title = title
        path_label = Gtk.Label(xalign=0); path_label.add_css_class("dim-label"); path_label.set_wrap(True); body.append(path_label); self.path_label = path_label
        warning = Gtk.Label(label="Security context provides useful evidence; it does not prove that a file is safe.", xalign=0)
        warning.add_css_class("warning"); warning.set_wrap(True); body.append(warning)

        status_heading = Gtk.Label(label="SECURITY STATUS", xalign=0); status_heading.add_css_class("section-heading"); body.append(status_heading)
        self.security_status = Gtk.Label(xalign=0); self.security_status.add_css_class("security-status"); body.append(self.security_status)

        provenance_heading = Gtk.Label(label="PROVENANCE", xalign=0); provenance_heading.add_css_class("section-heading"); body.append(provenance_heading)
        self.provenance_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8); body.append(self.provenance_box)
        checks_heading = Gtk.Label(label="SECURITY CHECKS", xalign=0); checks_heading.add_css_class("section-heading"); body.append(checks_heading)
        self.checks_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8); body.append(self.checks_box)
        safe_heading = Gtk.Label(label="SAFE OPEN", xalign=0); safe_heading.add_css_class("section-heading"); body.append(safe_heading)
        self.safe_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8); body.append(self.safe_box)
        sharing_heading = Gtk.Label(label="SHARING", xalign=0); sharing_heading.add_css_class("section-heading"); body.append(sharing_heading)
        self.sharing_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8); body.append(self.sharing_box)

        self.status = Gtk.Label(xalign=0); self.status.set_wrap(True); self.status.add_css_class("dim-label"); body.append(self.status)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10); body.append(actions)
        safe_button = Gtk.Button(label="Open with Safe Open"); safe_button.connect("clicked", self._action, "SafeOpen"); actions.append(safe_button)
        self.scan_button = Gtk.Button(label="Scan Again"); self.scan_button.connect("clicked", self._start_scan); actions.append(self.scan_button)
        sanitize_button = Gtk.Button(label="Create Sanitized Copy"); sanitize_button.connect("clicked", self._action, "SanitizeCopy"); actions.append(sanitize_button)
        self._install_css()

    def _install_css(self):
        css = Gtk.CssProvider()
        css.load_from_data(b"""
        .file-context-window { background: #0b0e12; color: #eef1f2; }
        .file-context-window .eyebrow, .file-context-window .section-heading { color: #9aa4ae; font-size: 10pt; font-weight: 700; letter-spacing: 1px; }
        .file-context-window .title-1 { color: #eef1f2; }
        .file-context-window .dim-label { color: #9aa4ae; }
        .file-context-window .warning { color: #e7c580; }
        .file-context-window .security-status { color: #c7dcd0; font-size: 16pt; font-weight: 700; }
        .context-row { padding: 13px 15px; border: 1px solid #2b333c; border-radius: 10px; background: #171d24; }
        .context-label { color: #9aa4ae; }
        .context-value { color: #eef1f2; font-weight: 600; }
        """)
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def _row(self, label: str, value: str):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16); row.add_css_class("context-row")
        name = Gtk.Label(label=label, xalign=0); name.add_css_class("context-label"); name.set_hexpand(True); row.append(name)
        result = Gtk.Label(label=value, xalign=1); result.add_css_class("context-value"); result.set_wrap(True); row.append(result)
        return row

    def _clear(self, box):
        while child := box.get_first_child():
            box.remove(child)

    def _unavailable(self):
        self.security_status.set_label("UNAVAILABLE")
        self.security_status.remove_css_class("secure")
        self.status.set_label("Security context unavailable\nGREYWARD could not retrieve file security information.")

    def _load_context(self):
        self.file_title.set_label(Path(self.path).name or "Selected file")
        self.path_label.set_label(display_path(self.path))
        self.status.set_label("Loading security context…")
        try:
            data = dbus_call("GetProvenance", self.path)
            summary = dbus_call("GetSummary")
            self.security_status.set_label(friendly_status(summary))
            source = data.get("source", {"state": "UNKNOWN"})
            file_ref = data.get("file_ref")
            first = data.get("first_observed", {"state": "UNKNOWN"})
            last = data.get("last_observed", {"state": "UNKNOWN"})
            scan = last_item(data, "scan", {"state": "UNKNOWN"})
            signature = data.get("signature", {"state": "UNKNOWN"})
            safe = last_item(data, "safe_open", {"state": "UNKNOWN"})
            sanitize = last_item(data, "sanitization", {"state": "UNKNOWN"})
            for box in (self.provenance_box, self.checks_box, self.safe_box, self.sharing_box):
                self._clear(box)
            self.provenance_box.append(self._row("Source", friendly_source(source)))
            self.provenance_box.append(self._row("Downloaded by", friendly_source(data.get("downloaded_by", {"state": "UNKNOWN"}))))
            self.provenance_box.append(self._row("Source URL", friendly_source(data.get("source_url", {"state": "UNKNOWN"}))))
            self.provenance_box.append(self._row("First seen", friendly_seen(first)))
            self.provenance_box.append(self._row("Last seen", friendly_seen(last)))
            self.checks_box.append(self._row("Malware scan", friendly_scan(scan)))
            self.checks_box.append(self._row("Signature", friendly_signature(signature)))
            self.safe_box.append(self._row("Opened with Safe Open", friendly_safe(safe)))
            self.sharing_box.append(self._row("Sanitized copy", friendly_sanitized(sanitize)))
            self.status.set_label("Evidence is limited to this selected file.")
        except Exception:
            logger.exception("Unable to load file security context")
            self._unavailable()

    def _start_scan(self, _button):
        if self.scanning:
            return
        self.scanning = True
        self.scan_button.set_sensitive(False)
        self.scan_button.set_label("Scanning…")
        self.status.set_label("Scanning…")
        Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            result = dbus_call("ScanHighRiskPath", self.path)
            GLib.idle_add(self._scan_finished, result, None)
        except Exception as error:
            logger.exception("File scan failed")
            GLib.idle_add(self._scan_finished, None, error)

    def _scan_finished(self, result, error):
        self.scanning = False
        self.scan_button.set_sensitive(True)
        self.scan_button.set_label("Scan Again")
        if error:
            self.status.set_label("Security context unavailable\nGREYWARD could not complete the scan.")
            subprocess.run(["notify-send", "GREYWARD Security", f"Scan failed:\n{Path(self.path).name}"], check=False, capture_output=True, text=True)
        else:
            message = scan_message(result)
            self._load_context()
            self.status.set_label(message + ".")
            notify_scan(self.path, result)
        return False

    def _action(self, _button, method: str):
        try:
            result = dbus_call(method, self.path)
            current = state(result)
            if method == "SafeOpen":
                message = "Opened with Safe Open." if current in {"LAUNCHED", "OPENED", "SUCCESS"} else "Safe Open could not open this file."
            else:
                message = "Sanitized copy created." if current in {"SANITIZED", "CREATED", "SUCCESS"} else "Sanitized copy was not created."
            self.status.set_label(message)
            self._load_context()
        except Exception:
            logger.exception("File security context action failed")
            self.status.set_label("Security context unavailable\nGREYWARD could not complete that action.")

def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--scan":
        path = sys.argv[2]
        try:
            result = dbus_call("ScanHighRiskPath", path)
            notify_scan(path, result)
            return 0
        except Exception:
            logger.exception("Nautilus scan action failed")
            subprocess.run(["notify-send", "GREYWARD Security", f"Scan failed:\n{Path(path).name}"], check=False, capture_output=True, text=True)
            return 1
    if len(sys.argv) != 2:
        print("A file must be selected.", file=sys.stderr)
        return 2
    return FileContext(sys.argv[1]).run(["greyward-file-context"])


if __name__ == "__main__":
    raise SystemExit(main())
