"""Public export reconciliation, journal continuity and adjacent alias rejection."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

if os.name != 'posix' or os.getuid() != 0:
    raise unittest.SkipTest('Run root-owned metadata fixtures on Fedora')

SOURCE = Path(__file__).resolve().parents[1] / 'security-center/packaging/application-security/administration/flatpak-metadata.py'
SPEC = importlib.util.spec_from_file_location('flatpak_metadata', SOURCE)
PROVIDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVIDER)

class PublicMetadataTests(unittest.TestCase):
    def fixture(self, root):
        exports=root/'exports/share/dbus-1/services'; exports.mkdir(parents=True)
        service=root/('app/org.example.App/x86_64/stable/'+'a'*64+'/export/share/dbus-1/services/org.example.App.service')
        service.parent.mkdir(parents=True);service.write_text('[D-BUS Service]\nName=org.example.App\n')
        (exports/service.name).symlink_to(service)
        return exports,service

    def test_repeat_preserves_original_labels_and_tracks_replacement(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'flatpak'; exports,service=self.fixture(root)
            journal=Path(temporary)/'labels.json';labels={}
            def get(path,*args,**kwargs):return labels.get((str(path),Path(path).lstat().st_ino),b'system_u:object_r:var_lib_t:s0')
            def put(path,attr,value,**kwargs):labels[(str(path),Path(path).lstat().st_ino)]=value
            with patch.object(PROVIDER,'ROOT',root),patch.object(PROVIDER.os,'getxattr',side_effect=get),patch.object(PROVIDER.os,'setxattr',side_effect=put):
                PROVIDER.reconcile(journal);first=json.loads(journal.read_text())
                PROVIDER.reconcile(journal);self.assertEqual(first,json.loads(journal.read_text()))
                previous=service.lstat().st_ino
                replacement=service.with_suffix('.replacement');replacement.write_text('[D-BUS Service]\nName=org.example.App\n');replacement.replace(service)
                PROVIDER.reconcile(journal)
                record=next(r for r in json.loads(journal.read_text()) if r['path']==str(service))
                self.assertNotEqual(previous,record['inode'])
                self.assertEqual(record['context'],'system_u:object_r:var_lib_t:s0')
                self.assertEqual(get(service),PROVIDER.TYPE)
                self.assertEqual(journal.stat().st_mode&0o777,0o600)

    def test_export_alias_cannot_label_private_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'flatpak';exports,service=self.fixture(root)
            secret=Path(temporary)/'private';secret.write_text('synthetic')
            (exports/service.name).unlink();(exports/service.name).symlink_to(secret)
            with patch.object(PROVIDER,'ROOT',root),patch.object(PROVIDER.os,'getxattr',return_value=PROVIDER.TYPE),patch.object(PROVIDER.os,'setxattr') as changed:
                with self.assertRaises(ValueError):PROVIDER.reconcile(Path(temporary)/'labels.json')
                changed.assert_not_called()

if __name__=='__main__':unittest.main()
