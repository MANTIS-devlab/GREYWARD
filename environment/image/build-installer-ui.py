#!/usr/bin/env python3
"""Add the keyboard gate to the reviewed Fedora installer entry points."""
import argparse
import hashlib
from pathlib import Path
import subprocess

PYANACONDA = "usr/lib64/python3.14/site-packages/pyanaconda"
GUI = f"{PYANACONDA}/ui/gui/__init__.py"
KEYBOARD = f"{PYANACONDA}/ui/gui/greyward_keyboard.py"
TUI = f"{PYANACONDA}/ui/tui/__init__.py"
STARTUP = f"{PYANACONDA}/startup_utils.py"
UI_FILES = (GUI, KEYBOARD, TUI, STARTUP)
FEDORA_STARTUP_SHA256 = "c859735194b8d053324c93981d5fc9679ea6ac9b7486d3c0368bf2d8d6f40c6e"
FEDORA_GUI_SHA256 = "6809357cb4d6226cc39010171f511931c7dd3aefbfc7bd2bbf2d665cff955ffc"
FEDORA_TUI_SHA256 = "5e3cb64cb4befe6eeafcf541a2e78b91ef4d2578ce9596c17ae81e23b8425b4b"
TUI_ENTRY = "        # Use GLib event loop for the Simpleline TUI\n"
TUI_GUARD = """        print("GREYWARD requires the graphical keyboard confirmation for disk encryption. "
              "Use Install GREYWARD with diagnostic logs to investigate the display.", flush=True)
        if sys.stdin.isatty():
            input("Press Enter to exit the installer.")
        sys.exit(1)
"""
GUI_ENTRY = "            while not self._currentAction:\n"
NEW_SCREEN = "        if child not in self._stack_contents:\n"
SCREEN_TITLE = """            if isinstance(child.window, (AnacondaWidgets.BaseStandalone, AnacondaWidgets.SpokeWindow)):
                child.window.set_property("distribution", "GREYWARD INSTALLATION")
"""
HOOK = """            # Confirm the disk-unlock keyboard before storage initialization.
            from pyanaconda.ui.gui.greyward_keyboard import confirm_keyboard
            if not confirm_keyboard(self.mainWindow._stack):
                sys.exit(0)
            self._distributionText = lambda: "GREYWARD INSTALLATION"

"""


def vendor_source(stage2, path, expected_sha):
    source = subprocess.check_output(["unsquashfs", "-cat", stage2, path])
    if hashlib.sha256(source).hexdigest() != expected_sha:
        raise ValueError(f"Anaconda entry point changed: {path}. Review the keyboard order on the new media.")
    return source.decode("utf-8")


def build(stage2, destination):
    gui = vendor_source(stage2, GUI, FEDORA_GUI_SHA256)
    tui = vendor_source(stage2, TUI, FEDORA_TUI_SHA256)
    if gui.count(GUI_ENTRY) != 1 or gui.count(NEW_SCREEN) != 1 or tui.count(TUI_ENTRY) != 1:
        raise ValueError("Unexpected Anaconda installer entry points")
    gui = gui.replace(GUI_ENTRY, HOOK + GUI_ENTRY).replace(NEW_SCREEN, NEW_SCREEN + SCREEN_TITLE)
    tui = tui.replace(TUI_ENTRY, TUI_GUARD + TUI_ENTRY)
    startup = vendor_source(stage2, STARTUP, FEDORA_STARTUP_SHA256)
    banner = '    verdesc = "%s for %s %s" % (get_anaconda_version_string(build_time_version=True),\n' \
             '                                get_product_name(), get_product_version())'
    if startup.count(banner) != 1:
        raise ValueError("Unexpected Anaconda startup banner")
    startup = startup.replace(
        banner,
        '    verdesc = "%s for GREYWARD" % get_anaconda_version_string(build_time_version=True)',
    )
    startup = startup.replace(
        '   inst.text boot option to start text installation',
        '   Install GREYWARD with diagnostic logs boot option',
    )
    keyboard = Path(__file__).with_name("installer-keyboard.py").read_text()
    for path, text in zip(UI_FILES, (gui, keyboard, tui, startup)):
        compile(text, path, "exec")
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage2", type=Path)
    parser.add_argument("destination", type=Path)
    options = parser.parse_args()
    build(options.stage2, options.destination)
