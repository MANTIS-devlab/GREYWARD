"""Directory readback and preference preservation for the ordinary 2.0 shell."""
import importlib.util
from importlib.machinery import SourceFileLoader
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
loader = SourceFileLoader('dms20_state', str(ROOT / 'environment/session/greyward-dms-state-migrate'))
spec = importlib.util.spec_from_loader(loader.name, loader)
migration = importlib.util.module_from_spec(spec)
loader.exec_module(migration)

class StateMigration(unittest.TestCase):
    def test_reference_appearance_seeds_new_accounts_but_preserves_established_layout(self):
        experience = json.loads((ROOT/'environment/session/dms-2.0-defaults/experience.json').read_text(encoding='utf-8'))
        appearance = experience['appearance']
        bar = appearance['barConfigs'][0]
        self.assertTrue(bar['noBackground'])
        self.assertEqual(bar['screenPreferences'], ['all'])
        self.assertEqual(bar['leftWidgets'][4]['appsDockIconSizePercentage'], 155)
        backgrounds = {item['id']: item.get('background') for section in ('leftWidgets','centerWidgets','rightWidgets')
                       for item in bar[section] if isinstance(item, dict) and 'background' in item}
        self.assertEqual({key for key, value in backgrounds.items() if value}, {'greywardSecure','clock','powerMenuButton'})
        self.assertEqual(appearance['dankLauncherV2BorderThickness'], 4)
        self.assertFalse(appearance['dockConfigs'][0]['enabled'])
        for established in (False, True):
            with self.subTest(established=established), tempfile.TemporaryDirectory() as directory:
                base=Path(directory); config=base/'config/dms'; config.mkdir(parents=True)
                chosen=[{'id':'personal','noBackground':False}]
                (config/'settings.json').write_text(json.dumps({'barConfigs':chosen}))
                if established:
                    (config/'.changelog-1.6').write_text('existing account')
                migration.migrate(config,base/'state/dms',base/'cache/dms',base/'system','v2.0.0-7',experience=experience)
                actual=json.loads((config/'settings.json').read_text())
                self.assertEqual(actual['barConfigs'], chosen if established else appearance['barConfigs'])

    def test_overview_reference_layout_has_explicit_nonoverlapping_grid(self):
        experience = json.loads((ROOT/'environment/session/dms-2.0-defaults/experience.json').read_text())
        cards = {card['id']: card for card in experience['dashCards'] if card['id'] != 'weather'}
        self.assertEqual({key: (value['row'], value['col'], value['w'], value['h']) for key, value in cards.items()}, {
            'plugin_greywardProtection': (0, 0, 2, 2), 'plugin_greywardNetwork': (0, 2, 2, 2),
            'plugin_greywardUpdates': (0, 4, 2, 2), 'media': (2, 0, 6, 2),
            'calendar': (4, 0, 3, 3), 'disk': (4, 3, 3, 1), 'memory': (5, 3, 3, 1), 'cpu': (6, 3, 3, 1)})
        occupied = set()
        for card in cards.values():
            cells = {(row, col) for row in range(card['row'], card['row'] + card['h'])
                     for col in range(card['col'], card['col'] + card['w'])}
            self.assertTrue(occupied.isdisjoint(cells), card['id'])
            occupied.update(cells)
        self.assertFalse(experience['privacyDefaults']['weatherEnabled'])

    def roots(self, base):
        roots = {name: base / name for name in ('config','state','cache','data')}
        for name, path in roots.items():
            (path / 'DankMaterialShell').mkdir(parents=True)
            (path / 'DankMaterialShell/fixture').write_bytes((name + '-original').encode())
        return roots

    def test_conflicting_generations_refuse_before_any_upstream_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); roots=self.roots(base)
            (roots['config'] / 'dms').mkdir()
            (roots['config'] / 'dms/settings.json').write_text('{"user":"other"}')
            with patch.object(migration.subprocess, 'run') as execute:
                with self.assertRaisesRegex(ValueError, 'Both DMS directory generations'):
                    migration.directory_migration(roots, 'v2.0.0-7', Path('/not-executed'))
                execute.assert_not_called()
            self.assertFalse((roots['state'] / 'greyward').exists())
            self.assertEqual((roots['config'] / 'DankMaterialShell/fixture').read_bytes(), b'config-original')

    def test_backup_precedes_cli_and_success_without_directory_readback_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            roots=self.roots(Path(directory))
            def no_migration(_args, **options):
                for name,path in roots.items():
                    saved=roots['state'] / 'greyward/dms-migration/v2.0.0-7' / name / 'DankMaterialShell/fixture'
                    self.assertEqual(saved.read_bytes(), (name+'-original').encode())
                    self.assertEqual(options['env']['XDG_'+name.upper()+'_HOME'], str(path))
            with patch.object(migration.subprocess, 'run', side_effect=no_migration):
                with self.assertRaisesRegex(ValueError, 'did not complete'):
                    migration.directory_migration(roots, 'v2.0.0-7', Path('/not-executed'))

    def test_previous_system_copy_is_replaced_but_customized_copy_survives(self):
        for customized in (False,True):
            with self.subTest(customized=customized), tempfile.TemporaryDirectory() as directory:
                base=Path(directory); config=base/'config/dms'; user=config/'plugins/greywardSecure'; user.mkdir(parents=True)
                original=b'previous validated plugin'
                (user/'Widget.qml').write_bytes(original+b' user edit' if customized else original)
                system=base/'system/greywardSecure'; system.mkdir(parents=True)
                (system/'Widget.qml').write_bytes(b'new 2.0 plugin')
                previous={'greywardSecure/Widget.qml':hashlib.sha256(original).hexdigest()}
                backup=migration.migrate(config,base/'state/dms',base/'cache/dms',base/'system','v2.0.0-7',previous_plugins=previous)
                self.assertEqual(user.exists(),customized)
                self.assertTrue((backup/'config/plugins/greywardSecure/Widget.qml').is_file())

    def test_factory_layout_is_additive_and_existing_empty_layout_and_optouts_survive(self):
        experience=json.loads((ROOT/'environment/session/dms-2.0-defaults/experience.json').read_text(encoding='utf-8'))
        for existing in (False,True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                base=Path(directory);config=base/'config/dms';config.mkdir(parents=True)
                settings={'acLockTimeout':123,'wallpaperPath':'user wallpaper'}
                if existing:settings.update(dashCards=[],dashTabs=[],weatherEnabled=True,dashOptions={'media':{'lyrics':True,'animatedArt':True}})
                (config/'settings.json').write_text(json.dumps(settings))
                (config/'plugin_settings.json').write_text(json.dumps({'greywardSecure':{'enabled':False},'personal':{'enabled':True}}))
                migration.migrate(config,base/'state/dms',base/'cache/dms',base/'system','v2.0.0-7',experience=experience)
                actual=json.loads((config/'settings.json').read_text())
                self.assertEqual(actual['dashCards'],[] if existing else experience['dashCards'])
                self.assertEqual(actual['acLockTimeout'],123)
                self.assertEqual(actual['wallpaperPath'],'user wallpaper')
                self.assertEqual(actual['weatherEnabled'],existing)
                self.assertEqual(actual['dashOptions']['media']['lyrics'],existing)
                self.assertEqual(actual['dashOptions']['media']['animatedArt'],existing)
                plugins=json.loads((config/'plugin_settings.json').read_text())
                self.assertFalse(plugins['greywardSecure']['enabled'])
                self.assertFalse(plugins['greywardProtection']['enabled'])
                self.assertTrue(plugins['personal']['enabled'])
                actual['dashCards']=[];(config/'settings.json').write_text(json.dumps(actual))
                migration.migrate(config,base/'state/dms',base/'cache/dms',base/'system','v2.0.0-7',experience=experience)
                self.assertEqual(json.loads((config/'settings.json').read_text())['dashCards'],[])

    @unittest.skipUnless(os.name == 'posix' and os.environ.get('GREYWARD_DMS20_BINARY'), 'explicit unprivileged native binary fixture')
    def test_actual_native_cli_moves_all_roots_and_repeat_keeps_initial_backup(self):
        self.assertNotEqual(os.geteuid(),0,'native directory migration must run as an ordinary account')
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);roots=self.roots(base)
            (base/'runtime').mkdir(mode=0o700);(base/'home').mkdir()
            env={'HOME':str(base/'home'),'XDG_RUNTIME_DIR':str(base/'runtime'),
                 'DBUS_SESSION_BUS_ADDRESS':'unix:path=/nonexistent','DBUS_SYSTEM_BUS_ADDRESS':'unix:path=/nonexistent'}
            with patch.dict(os.environ,env):
                backup=migration.directory_migration(roots,'v2.0.0-7',Path(os.environ['GREYWARD_DMS20_BINARY']))
                for name,path in roots.items():
                    self.assertTrue((path/'DankMaterialShell').is_symlink())
                    self.assertEqual((path/'dms/fixture').read_bytes(),(name+'-original').encode())
                (roots['config']/'dms/fixture').write_bytes(b'user changed after migration')
                self.assertEqual(migration.directory_migration(roots,'v2.0.0-7',Path(os.environ['GREYWARD_DMS20_BINARY'])),backup)
            self.assertEqual((backup/'config/DankMaterialShell/fixture').read_bytes(),b'config-original')
            self.assertEqual((roots['config']/'dms/fixture').read_bytes(),b'user changed after migration')

    @unittest.skipUnless(os.name == 'posix' and __import__('shutil').which('jq'), 'native Bash/jq pin fixture')
    def test_session_pin_seed_uses_selected_generation_and_preserves_choices(self):
        import shlex
        for release, name in (('v1.6.2-26','DankMaterialShell'),('v2.0.0-7','dms')):
            with self.subTest(release=release), tempfile.TemporaryDirectory() as directory:
                base=Path(directory); state=base/'state';(state/name).mkdir(parents=True)
                selected=base/'selector';selected.write_text(release+'\n')
                source=(ROOT/'environment/session/greyward-dms-session-migrate').read_text()
                source=source.replace('/usr/local/libexec/greyward-dms-state-migrate', 'true')
                source=source.replace('/etc/greyward/dms-release', shlex.quote(str(selected)))
                script=base/'migrate.sh';script.write_text(source)
                target=state/name/'session.json';target.write_text('{"barPinnedApps":[]}')
                env=dict(os.environ,HOME=str(base),XDG_STATE_HOME=str(state))
                subprocess.run(['bash',str(script)],env=env,check=True)
                self.assertEqual(json.loads(target.read_text())['barPinnedApps'],[])
                target.write_text('{}')
                subprocess.run(['bash',str(script)],env=env,check=True)
                expected=['brave-browser','com.raggesilver.BlackBox','io.github.lgse.Strata']
                if release=='v2.0.0-7':
                    expected.append('dms_settings')
                self.assertEqual(json.loads(target.read_text())['barPinnedApps'],expected)
                self.assertFalse((state/('dms' if name=='DankMaterialShell' else 'DankMaterialShell')).exists())


if __name__ == '__main__':
    unittest.main()
