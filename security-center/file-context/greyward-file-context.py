#!/usr/bin/env python3
import ast
import datetime as dt
import json
import logging
import subprocess
import sys
import time
import signal
from threading import Thread, Event
from pathlib import Path, PurePosixPath

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, GLib, Gtk, Gio, Pango

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


def scan_selection(path, progress=None, cancellation=None):
    operation = {}
    for _attempt in range(5):
        operation = dbus_call("StartScan", json.dumps({"mode": "FOLDER" if Path(path).is_dir() else "FILE", "paths": [path]}))
        if operation.get("operation_id") or "already running" not in operation.get("detail", ""):
            break
        time.sleep(1)
    operation_id = operation.get("operation_id")
    if not operation_id:
        return {"state": "UNAVAILABLE", "detail": operation.get("detail", "The scanner is busy or unavailable.")}
    deadline = time.monotonic() + 7300
    try:
        while time.monotonic() < deadline:
            if cancellation is not None and cancellation.is_set():
                dbus_call("CancelScan", operation_id)
                return {"state": "CANCELLED", "detail": "The scan was cancelled before completion."}
            result = dbus_call("GetScanStatus", operation_id)
            current = result.get("state")
            if progress:
                progress(result)
            if current not in {"QUEUED", "SCANNING", "FINALIZING"}:
                return {**result, "state": ("THREAT" if result.get("detection_count") else "PARTIAL" if result.get("error_count") or result.get("skipped_count") else "CLEAN")
                    if current == "COMPLETED" else current or "UNAVAILABLE"}
            time.sleep(1)
    except BaseException:
        dbus_call("CancelScan", operation_id)
        raise
    dbus_call("CancelScan", operation_id)
    return {"state": "TIMEOUT", "detail": "The scan did not complete within the allowed time."}


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
    if current in {"PARTIAL", "INTERRUPTED", "TIMEOUT"}:
        return "Scan incomplete"
    if current == "CANCELLED":
        return "Scan cancelled"
    if current == "UNAVAILABLE":
        return "Scan unavailable"
    return "Scan result unavailable"


def friendly_sanitized(value):
    current = state(value)
    if current in {"SANITIZED", "CREATED", "SUCCESS"}:
        stamp = pretty_time(value)
        return "Created: " + stamp if stamp != "Unknown" else "Available"
    return "Not created"


class FileContext(Gtk.Application):
    def __init__(self, path: str, scan_now=False):
        super().__init__(application_id="systems.mantis.greyward.filecontext", flags=Gio.ApplicationFlags.NON_UNIQUE)
        self.path = path
        self.scan_now = scan_now
        self.window = None
        self.status = None
        self.context_box = None
        self._held = False
        self.scanning = False
        self.scan_button = None
        self.cancellation = Event()
        self.cancel_button = None
        self.result_title = None
        self.result_detail = None
        self._pulse_source = None

    def do_activate(self):
        if self.window is None:
            self.hold()
            self._held = True
            self.window = Gtk.ApplicationWindow(application=self)
            self.window.set_title("GREYWARD · File security")
            self.window.set_default_size(640, 610)
            self.window.set_resizable(True)
            self.window.set_decorated(True)
            self.window.connect("close-request", self._close_window)
            self._build_window()
        self.window.present()
        self._load_context()

    def _close_window(self, _window):
        if self.scanning:
            self.cancellation.set()
            self.status.set_label("Cancelling scan…")
            return True
        if self._held:
            self.release()
            self._held = False
        self.scanning = False
        self.scan_button = None
        self.quit()
        return False

    @staticmethod
    def _label(text, style, wrap=False):
        label = Gtk.Label(label=text, xalign=0)
        label.add_css_class(style)
        label.set_wrap(wrap)
        if wrap:
            label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        return label

    def _build_window(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.add_css_class("file-context-window")
        self.window.set_child(outer)
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header.add_css_class("scan-header")
        brand = Gtk.Image.new_from_file("/usr/share/icons/hicolor/scalable/apps/greyward-security-status.svg")
        brand.set_pixel_size(30)
        header.append(brand)
        identity = self._label("GREYWARD", "brand-name")
        identity.set_hexpand(True)
        header.append(identity)
        header.append(self._label("File security", "header-caption"))
        outer.append(header)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=22)
        for setter in (body.set_margin_start, body.set_margin_end):
            setter(30)
        body.set_margin_top(26)
        body.set_margin_bottom(24)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(body)
        scroller.set_vexpand(True)
        outer.append(scroller)

        selected = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        selected.append(self._label("SELECTED ITEM", "section-heading"))
        self.file_title = self._label("", "file-name", True)
        self.file_title.set_lines(2)
        self.file_title.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        selected.append(self.file_title)
        self.path_label = self._label("", "file-path", True)
        self.path_label.set_lines(2)
        self.path_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        selected.append(self.path_label)
        body.append(selected)

        self.result_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.result_panel.add_css_class("scan-result")
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        self.result_image = Gtk.Image()
        self.result_image.set_pixel_size(66)
        self.result_image.set_valign(Gtk.Align.START)
        top.append(self.result_image)
        message = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        message.set_hexpand(True)
        message.append(self._label("MALWARE SCAN", "section-heading"))
        self.result_title = self._label("Not scanned", "result-title", True)
        self.result_detail = self._label("Run a scan to check this selection.", "result-detail", True)
        message.append(self.result_title)
        message.append(self.result_detail)
        top.append(message)
        self.result_panel.append(top)
        self.progress = Gtk.ProgressBar()
        self.progress.add_css_class("scan-progress")
        self.progress.set_visible(False)
        self.result_panel.append(self.progress)
        self.metrics = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.metrics.add_css_class("scan-metrics")
        self.count_labels = {}
        for key, title in (("files_inspected", "Checked"), ("detection_count", "Detections"), ("skipped_count", "Skipped"), ("error_count", "Errors")):
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
            column.set_hexpand(True)
            number = self._label("—", "metric-number")
            self.count_labels[key] = number
            column.append(number)
            column.append(self._label(title, "metric-label"))
            self.metrics.append(column)
        self.metrics.set_visible(False)
        self.result_panel.append(self.metrics)
        body.append(self.result_panel)

        self.status = self._label("", "context-note", True)
        self.details = Gtk.Expander(label="File context & options")
        self.details.add_css_class("context-details")
        sections = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        sections.set_margin_top(18)
        self.details.set_child(sections)
        sections.append(self.status)
        self.security_status = self._label("", "context-value", True)
        sections.append(self._label("Device protection", "section-heading"))
        sections.append(self.security_status)
        for attr, title in (("provenance_box", "Origin"), ("checks_box", "Checks"), ("safe_box", "Safe Open"), ("sharing_box", "Sharing")):
            sections.append(self._label(title, "section-heading"))
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            setattr(self, attr, box)
            sections.append(box)
        tools = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        for label, method in (("Open with Safe Open", "SafeOpen"), ("Create sanitized copy", "SanitizeCopy")):
            button = Gtk.Button(label=label)
            button.connect("clicked", self._action, method)
            button.set_sensitive(not Path(self.path).is_dir())
            tools.append(button)
        sections.append(tools)
        body.append(self.details)
        note = self._label("A scan checks for known threats. It cannot guarantee that a file is safe.", "scope-note", True)
        body.append(note)

        footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        footer.add_css_class("scan-footer")
        engine = self._label("ClamAV engine", "engine-label")
        engine.set_hexpand(True)
        footer.append(engine)
        self.cancel_button = Gtk.Button(label="Cancel scan")
        self.cancel_button.connect("clicked", self._cancel_scan)
        self.cancel_button.set_visible(False)
        footer.append(self.cancel_button)
        self.scan_button = Gtk.Button(label="Scan now")
        self.scan_button.add_css_class("scan-primary")
        self.scan_button.connect("clicked", self._start_scan)
        footer.append(self.scan_button)
        outer.append(footer)
        self._install_css()
        self._set_result("neutral", "Not scanned", "Run a scan to check this selection.")
        if self.scan_now:
            self.scan_now = False
            GLib.idle_add(self._start_scan, self.scan_button)

    def _install_css(self):
        css = Gtk.CssProvider()
        css.load_from_data(b"""
        .file-context-window { background: #111518; color: #e4e8eb; font-family: Inter, sans-serif; font-size: 14px; }
        .scan-header { padding: 19px 30px; border-bottom: 1px solid #2b3136; }
        .brand-name { color: #dce2e6; font-size: 12px; font-weight: 650; letter-spacing: 2px; }
        .header-caption, .engine-label { color: #a9b3bc; font-size: 13px; }
        .file-name { font-size: 22px; font-weight: 550; letter-spacing: -0.5px; color: #ecf0f2; }
        .file-path { font-size: 12px; color: #a5b0b9; }
        .section-heading { font-size: 10px; font-weight: 650; letter-spacing: 1.2px; color: #a9b5bf; }
        .scan-result { padding: 24px; border-radius: 16px; border: 1px solid #343c42; background: linear-gradient(to bottom, #1d2429, #191f23); }
        .result-title { font-size: 25px; font-weight: 550; letter-spacing: -0.65px; color: #eef2f4; }
        .result-detail { font-size: 14px; color: #b8c2c9; }
        .scan-result.clean { border-top-color: #536b5b; }
        .scan-result.clean .result-title { color: #b8ddc3; }
        .scan-result.review { border-top-color: #7b6746; }
        .scan-result.review .result-title { color: #e6c991; }
        .scan-result.threat { border-top-color: #81565b; }
        .scan-result.threat .result-title { color: #edaeb5; }
        .scan-metrics { padding-top: 17px; border-top: 1px solid #343c42; }
        .metric-number { font-size: 22px; font-weight: 500; font-feature-settings: "tnum"; }
        .metric-label { color: #a9b4bd; font-size: 12px; }
        .context-note { color: #bdc6cc; font-size: 13px; }
        .scope-note { color: #98a5ae; font-size: 12px; }
        .context-details { padding-top: 18px; border-top: 1px solid #2b3136; color: #c9d2d9; }
        .context-row { padding: 11px 0; border-bottom: 1px solid #2b3136; }
        .context-label { color: #a6b2bc; font-size: 13px; }
        .context-value { color: #dee4e8; font-size: 13px; }
        .scan-footer { padding: 16px 30px; border-top: 1px solid #2b3136; background: #151a1e; }
        .file-context-window button { min-height: 32px; padding: 3px 15px; border-radius: 8px; border: 1px solid #48535c; background: #252d34; color: #e3e9ed; box-shadow: none; font-size: 13px; font-weight: 500; }
        .file-context-window button:hover { background: #303a42; border-color: #74818b; }
        .file-context-window button:focus-visible { outline: 2px solid #b8cbd8; outline-offset: 3px; }
        .file-context-window button:disabled { opacity: .5; }
        .file-context-window button.scan-primary { background: #d4dde3; color: #172027; border-color: #e2e8ec; }
        .file-context-window button.scan-primary:hover { background: #edf2f5; }
        .context-details > title > expander { margin-right: 8px; }
        .scan-progress trough { background: #343e46; min-height: 3px; min-width: 0; padding: 0; border: none; }
        .scan-progress progress { background: #b5c7d4; min-height: 3px; min-width: 1px; padding: 0; border: none; }
        """)
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def _row(self, label: str, value: str):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        row.add_css_class("context-row")
        name = self._label(label, "context-label")
        name.set_hexpand(True)
        row.append(name)
        result = self._label(value, "context-value", True)
        result.set_xalign(1)
        result.set_max_width_chars(35)
        row.append(result)
        return row

    def _set_result(self, tone, title, description, result=None):
        for value in ("clean", "review", "threat", "neutral"):
            self.result_panel.remove_css_class(value)
        self.result_panel.add_css_class(tone)
        self.result_image.set_from_file("/usr/share/greyward-security-center/scan-notifications/greyward-scan-" + tone + ".svg")
        self.result_title.set_label(title)
        self.result_detail.set_label(description)
        counts = result or {}
        for key, label in self.count_labels.items():
            value = counts.get(key)
            label.set_label(str(value) if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else "—")
        self.metrics.set_visible(bool(result))

    def _present_receipt(self, receipt):
        if self.scanning:
            return
        current = state(receipt)
        valid = receipt.get("validity") == "VALID"
        if valid and current in {"CLEAN", "NO_THREATS", "NO THREATS DETECTED"}:
            self._set_result("clean", "No threats detected", "The recorded scan is still current.")
        elif valid and current in {"THREAT", "THREAT DETECTED"}:
            self._set_result("threat", "Threat detected", "Review the finding in Security Center before opening this item.")
        elif valid and current in {"PARTIAL", "FAILED", "INTERRUPTED"}:
            self._set_result("review", "Scan incomplete", receipt.get("detail", "Some files could not be checked."))
        else:
            self._set_result("neutral", "No current scan", receipt.get("detail", "Scan this selection to get a current result."))

    def _cancel_scan(self, *_args):
        self.cancellation.set()
        self.cancel_button.set_sensitive(False)
        self.result_title.set_label("Cancelling scan…")

    def _clear(self, box):
        while child := box.get_first_child():
            box.remove(child)

    def _unavailable(self):
        self.security_status.set_label("UNAVAILABLE")
        self.security_status.remove_css_class("secure")
        self.status.set_label("GREYWARD could not retrieve file security information.")
        if not self.scanning:
            self._set_result("review", "Scan status unavailable", "The current result could not be read. Try again.")

    def _load_context(self):
        self.file_title.set_label(Path(self.path).name or "Selected file")
        self.path_label.set_label(display_path(self.path))
        self.status.set_label("Loading security context…")
        try:
            # Provenance and Safe Open apply to supported individual documents.
            # Their absence must not hide authoritative folder/drive scan data.
            try:
                data = {} if Path(self.path).is_dir() else dbus_call("GetProvenance", self.path)
            except Exception:
                data = {}
            try:
                summary = dbus_call("GetSummary")
            except Exception:
                summary = {"state": "UNAVAILABLE"}
            receipt = dbus_call("GetFileScanInfo", self.path)
            self.security_status.set_label(friendly_status(summary))
            source = data.get("source", {"state": "UNKNOWN"})
            file_ref = data.get("file_ref")
            first = data.get("first_observed", {"state": "UNKNOWN"})
            last = data.get("last_observed", {"state": "UNKNOWN"})
            scan = receipt
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
            self.checks_box.append(self._row("Malware scan", (friendly_scan(scan) if scan.get("validity") == "VALID" else scan.get("detail", "No current scan result"))))
            if not Path(self.path).is_dir():
                self.checks_box.append(self._row("Signature", friendly_signature(signature)))
            self.safe_box.append(self._row("Opened with Safe Open", friendly_safe(safe)))
            self.sharing_box.append(self._row("Sanitized copy", friendly_sanitized(sanitize)))
            self.status.set_label(receipt.get("detail", "No scan recorded."))
            self._present_receipt(receipt)
        except Exception:
            logger.exception("Unable to load file security context")
            self._unavailable()

    def _start_scan(self, _button):
        if self.scanning:
            return
        self.scanning = True
        self.cancellation.clear()
        self.cancel_button.set_sensitive(True)
        self.cancel_button.set_visible(True)
        self.progress.set_visible(True)
        self._set_result("neutral", "Scanning…", "Checking this selection for known threats.")
        self.scan_button.set_sensitive(False)
        self.scan_button.set_label("Scanning…")
        self.status.set_label("Scanning…")
        self._pulse_source = GLib.timeout_add(150, self._pulse_progress)
        Thread(target=self._scan_worker, daemon=True).start()

    def _pulse_progress(self):
        if not self.scanning:
            self._pulse_source = None
            return False
        self.progress.pulse()
        return True

    def _scan_progress(self, value):
        inspected = value.get("files_inspected")
        if isinstance(inspected, int) and not isinstance(inspected, bool) and inspected >= 0:
            self.result_detail.set_label(f"{inspected} files checked so far.")
        return False

    def _scan_worker(self):
        try:
            result = scan_selection(self.path, lambda value: GLib.idle_add(self._scan_progress, value), self.cancellation)
            GLib.idle_add(self._scan_finished, result, None)
        except Exception as error:
            logger.exception("File scan failed")
            GLib.idle_add(self._scan_finished, None, error)

    def _scan_finished(self, result, error):
        self.scanning = False
        if self._pulse_source is not None:
            GLib.source_remove(self._pulse_source)
            self._pulse_source = None
        self.cancel_button.set_sensitive(False)
        self.cancel_button.set_visible(False)
        self.progress.set_visible(False)
        self.scan_button.set_sensitive(True)
        self.scan_button.set_label("Scan again")
        if error:
            self._set_result("review", "Scan unavailable", "GREYWARD could not complete the scan. Try again when the scanner is available.")
            self.status.set_label("No complete scan result was recorded.")
        else:
            message = scan_message(result)
            self._load_context()
            current = state(result)
            tone = "clean" if current == "CLEAN" else "threat" if current == "THREAT" else "neutral" if current == "CANCELLED" else "review"
            description = {"CLEAN": "Files checked with the current virus definitions.", "THREAT": "Review the finding in Security Center before opening this item.", "CANCELLED": "No complete scan result was recorded."}.get(current, "Some files could not be checked. Review the scan details.")
            if current == "CLEAN":
                checked = result.get("files_inspected")
                complete = all(isinstance(result.get(key), int) and not isinstance(result.get(key), bool) and result[key] >= 0 for key in ("files_inspected", "detection_count", "error_count", "skipped_count"))
                if not complete or result.get("error_count") or result.get("skipped_count"):
                    tone, message, description = "review", "Scan incomplete", "A complete result could not be confirmed."
                elif checked == 0:
                    tone, message, description = "neutral", "No files checked", "The selection contained no scannable files."
            self._set_result(tone, message, description, result)
            self.status.set_label("Scan finished" if current in {"CLEAN", "THREAT"} else "Scan stopped without a complete result")
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
    # Strata's existing Jobs cancellation sends SIGTERM to this companion.
    # Raise through scan_selection so its finally/error path cancels the root
    # operation too; never leave an invisible worker holding the scan slot.
    def terminate(_signal, _frame):
        raise SystemExit(130)
    signal.signal(signal.SIGTERM, terminate)
    if len(sys.argv) == 3 and sys.argv[1] == "--scan-window":
        return FileContext(sys.argv[2], scan_now=True).run(["greyward-file-context"])
    if len(sys.argv) == 3 and sys.argv[1] in {"--scan", "--safe-open"}:
        path = sys.argv[2]
        if not PurePosixPath(path).is_absolute() or len(path) > 4096 or "\0" in path:
            print("An absolute local file must be selected.", file=sys.stderr)
            return 2
        try:
            if sys.argv[1] == "--safe-open":
                result = dbus_call("SafeOpen", path)
                # Launch evidence is not a successful workload outcome. Refused,
                # missing or contradictory results must never fall back to open.
                started = isinstance(result, dict) and result.get("ok") is True and state(result) == "LAUNCHED"
                subprocess.run(["notify-send", "Safe Open started" if started else "Safe Open refused",
                                "Restricted application started. Its outcome is recorded in Security Center."
                                if started else "The selected file could not be opened safely."],
                               check=False, capture_output=True, text=True)
                return 0 if started else 1
            result = scan_selection(path, lambda value: print(f"Inspected: {value.get('files_inspected', 0)} | {value.get('state', 'UNKNOWN')}", flush=True))
            return 0 if state(result) in {"CLEAN", "NO_THREATS", "NO THREATS DETECTED", "THREAT", "THREAT DETECTED"} else 1
        except Exception:
            logger.warning("Selected file action unavailable", exc_info=False)
            if sys.argv[1] == "--safe-open":
                subprocess.run(["notify-send", "GREYWARD Security", "The selected file action could not be completed."],
                               check=False, capture_output=True, text=True)
            else:
                print("The selected scan could not be completed. Review File Security.", file=sys.stderr)
            return 1
    if len(sys.argv) != 2:
        print("A file must be selected.", file=sys.stderr)
        return 2
    return FileContext(sys.argv[1]).run(["greyward-file-context"])


if __name__ == "__main__":
    raise SystemExit(main())
