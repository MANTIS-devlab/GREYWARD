"""Confirm one console-compatible layout before Anaconda opens storage."""
from pathlib import Path

from gi.repository import Gtk

from pyanaconda.keyboard import normalize_layout_variant
from pyanaconda.modules.common.constants.services import LOCALIZATION
from pyanaconda.ui.gui.xkl_wrapper import XklWrapper

CONFIRMATION = Path("/run/greyward-installer-keymap")
LAYOUTS = (
    ("English (US) · QWERTY", "us", "us"),
    ("French · AZERTY (Latin-9, no dead keys)", "fr (latin9_nodeadkeys)", "fr-latin9_nodeadkeys"),
    ("German · QWERTZ (no dead keys)", "de (nodeadkeys)", "de-nodeadkeys"),
)


def confirm_keyboard(stack):
    """Apply and read back the layout before enabling the confirmation."""
    CONFIRMATION.unlink(missing_ok=True)
    keyboard = LOCALIZATION.get_proxy()
    compositor = XklWrapper.get_instance()
    confirmed = False

    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    content = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL, spacing=16, border_width=24,
        halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER,
    )
    content.set_size_request(520, -1)
    page.pack_start(content, True, True, 0)

    mark = Gtk.Image.new_from_file("/usr/share/anaconda/pixmaps/greyward-anaconda-logo.png")
    mark.set_halign(Gtk.Align.START)
    content.pack_start(mark, False, False, 0)
    heading = Gtk.Label(xalign=0)
    heading.set_markup("<big><b>Choose your keyboard layout</b></big>")
    content.pack_start(heading, False, False, 0)
    explanation = Gtk.Label(
        label="GREYWARD uses this layout for disk encryption during installation "
              "and every time you unlock the disk at startup.",
        xalign=0, wrap=True, max_width_chars=56,
    )
    content.pack_start(explanation, False, False, 0)

    choices = Gtk.ComboBoxText()
    for label, _, keymap in LAYOUTS:
        choices.append(keymap, label)
    content.pack_start(choices, False, False, 0)

    test = Gtk.Entry(placeholder_text="Type a few test characters here (optional)")
    test.set_sensitive(False)
    content.pack_start(test, False, False, 0)
    status = Gtk.Label(xalign=0, wrap=True, max_width_chars=56)
    content.pack_start(status, False, False, 0)

    actions = Gtk.ButtonBox(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    actions.set_layout(Gtk.ButtonBoxStyle.END)
    cancel = Gtk.Button(label="Quit installation")
    cancel.connect("clicked", lambda _button: Gtk.main_quit())
    actions.add(cancel)
    confirm = Gtk.Button(label="Confirm and continue", sensitive=False)
    confirm.get_style_context().add_class("suggested-action")
    actions.add(confirm)
    content.pack_start(actions, False, False, 0)

    def active_layout():
        current = compositor.get_current_layout()
        return normalize_layout_variant(current) if current else None

    def select_layout(combo):
        confirm.set_sensitive(False)
        test.set_text("")
        test.set_sensitive(False)
        _, layout, _ = LAYOUTS[combo.get_active()]
        compositor.replace_layouts([layout])
        compositor.activate_default_layout()
        if active_layout() != layout:
            status.set_text("The installer could not apply this layout. Choose another "
                            "layout or restart the installer.")
            return
        status.set_text("Check the layout before continuing. Use sample text here.")
        test.set_sensitive(True)
        confirm.set_sensitive(True)

    def finish(_button):
        nonlocal confirmed
        _, layout, keymap = LAYOUTS[choices.get_active()]
        if active_layout() != layout:
            select_layout(choices)
            return
        keyboard.XLayouts = [layout]
        keyboard.VirtualConsoleKeymap = keymap
        CONFIRMATION.write_text(keymap + "\n", encoding="ascii")
        confirmed = True
        Gtk.main_quit()

    choices.connect("changed", select_layout)
    confirm.connect("clicked", finish)
    stack.add_named(page, "greyward-keyboard")
    page.show_all()
    stack.set_visible_child(page)
    choices.set_active(0)
    choices.grab_focus()
    try:
        Gtk.main()
        return confirmed
    finally:
        page.destroy()
