#!/usr/bin/env python3
"""Opt-in GIO/GTK icon resolution in a disposable database; no user-state edits."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    spec = importlib.util.spec_from_file_location('office_artwork', repo / 'packaging/greyward-office/artwork.py')
    artwork = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artwork)
    manifest = json.loads((repo / 'packaging/greyward-office/source.json').read_text())
    with tempfile.TemporaryDirectory(prefix='greyward-office-mime-') as directory:
        root = Path(directory)
        packages = root / 'share/mime/packages'
        packages.mkdir(parents=True)
        shutil.copyfile('/usr/share/mime/packages/freedesktop.org.xml', packages / 'freedesktop.org.xml')
        icons = root / 'share/icons/hicolor'
        (icons / 'scalable/mimetypes').mkdir(parents=True)
        shutil.copyfile('/usr/share/icons/hicolor/index.theme', icons / 'index.theme')
        native_icons = root / 'share/icons/Greyward'
        (native_icons / 'scalable/mimetypes').mkdir(parents=True)
        shutil.copyfile('/usr/share/icons/Greyward/index.theme', native_icons / 'index.theme')
        expected = {}
        for app in manifest['applications']:
            upstream = None
            if app['slug'] == 'slides':
                # Minimal native-format fixture; real upstream bytes are checked
                # separately by the package gate before/after MIME adaptation.
                upstream = (b'<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">'
                            b'<mime-type type="application/x-deckcraft"><sub-class-of type="application/zip"/>'
                            b'<glob pattern="*.deckcraft"/></mime-type></mime-info>')
            name = artwork.document_icon_name(app)
            (packages / (app['appId'] + '.xml')).write_bytes(artwork.document_mime(app, upstream))
            shutil.copyfile(repo / 'branding/source' / (name + '.svg'), icons / 'scalable/mimetypes' / (name + '.svg'))
            shutil.copyfile(repo / 'branding/source' / (name + '.svg'), native_icons / 'scalable/mimetypes' / (name + '.svg'))
            expected.update({mime: name for mime in artwork.MIMES[app['slug']]})
        database_env = dict(os.environ, XDG_DATA_DIRS=str(root / 'share') + ':/usr/share')
        subprocess.run(['update-mime-database', str(packages.parent)], env=database_env, check=True, stdout=subprocess.DEVNULL)
        # A fresh process is essential: libgio memoizes MIME databases.
        worker = '''import gi,json,sys
from pathlib import Path
gi.require_version('Gio','2.0');gi.require_version('Gtk','4.0')
from gi.repository import Gio,Gtk
expected=json.loads(sys.argv[1]);root=Path(sys.argv[2])
theme=Gtk.IconTheme.new();theme.set_theme_name('Greyward')
theme.set_search_path([str(root/'share/icons'),'/usr/share/icons'])
for mime,name in expected.items():
 icon=Gio.content_type_get_icon(mime)
 assert icon.get_names()[0]==name,(mime,icon.to_string())
 paintable=theme.lookup_by_gicon(icon,48,1,Gtk.TextDirection.NONE,Gtk.IconLookupFlags.FORCE_REGULAR)
 path=Path(paintable.get_file().get_path())
 assert path==root/'share/icons/Greyward/scalable/mimetypes'/(name+'.svg'),(mime,path)
for file,mime in [('sample.docx','application/vnd.openxmlformats-officedocument.wordprocessingml.document'),('sample.xlsx','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),('sample.pdf','application/pdf'),('sample.pptx','application/vnd.openxmlformats-officedocument.presentationml.presentation'),('sample.deckcraft','application/x-deckcraft')]:
 assert Gio.content_type_guess(file,None)[0]==mime,(file,Gio.content_type_guess(file,None))
print('OFFICE_DOCUMENT_ICON_NATIVE=PASS: '+str(len(expected))+' MIME identities; five filename detections; GTK regular-icon fallback')
'''
        env = dict(os.environ, XDG_DATA_HOME=str(root / 'user-share'),
                   XDG_DATA_DIRS=str(root / 'share') + ':/usr/share')
        subprocess.run([sys.executable, '-c', worker, json.dumps(expected), str(root)], env=env, check=True)


if __name__ == '__main__':
    main()
