#!/usr/bin/env python3
"""Generate reviewed shell, Strata, private Qt and Security Center color adapters."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'branding/source/greyward-desktop-palette.json'
NOTICE = 'Generated from branding/source/greyward-desktop-palette.json; do not edit colors here.'
DMS_ROLES = {'primary', 'primaryText', 'onPrimary', 'primaryContainer', 'onPrimaryContainer',
             'secondary', 'secondaryContainer', 'onSecondaryContainer', 'surface', 'surfaceText',
             'surfaceVariant', 'surfaceVariantText', 'surfaceTint', 'background', 'backgroundText',
             'outline', 'outlineVariant', 'surfaceContainer', 'surfaceContainerHigh',
             'surfaceContainerHighest', 'error', 'warning', 'success', 'info'}


def load(path=SOURCE):
    palette = json.loads(path.read_text(encoding='utf-8-sig'))
    if palette.get('schema') != 'greyward.desktop-palette/v1':
        raise ValueError('Unknown palette schema')
    if set(palette) != {'schema', 'dark', 'light', 'dms'}:
        raise ValueError('Unreviewed palette sections')
    keys = {'name','canvas','deep','surface','soft','raised','highest','text','primary','onPrimary','accent',
            'muted','subtle','border','outline','positive','warning','error','uncertain','shellCanvas'}
    for mode in ('dark','light'):
        values = palette[mode]
        if set(values) != keys or not re.fullmatch(r'GREYWARD [A-Za-z]+', values['name']):
            raise ValueError('Unreviewed palette roles/name')
        if any(not isinstance(value,str) or not re.fullmatch(r'#[0-9A-Fa-f]{6}',value)
               for key,value in values.items() if key != 'name'):
            raise ValueError('Palette colors must be six-digit RGB values')
    # Native shell surfaces have a different visual weight from application
    # surfaces. Keep the observed reference roles here, alongside their common
    # defaults, rather than shipping a separately maintained live-only theme.
    shell = palette['dms']
    if not isinstance(shell, dict) or set(shell) - {'dark', 'light'}:
        raise ValueError('Unreviewed DMS palette modes')
    for values in shell.values():
        if not isinstance(values, dict) or set(values) - (DMS_ROLES | {'matugen_type'}):
            raise ValueError('Unreviewed DMS palette roles')
        if any(not isinstance(value, str) or not re.fullmatch(r'#[0-9A-Fa-f]{6}', value)
               for key, value in values.items() if key != 'matugen_type'):
            raise ValueError('DMS colors must be six-digit RGB values')
        if values.get('matugen_type', 'scheme-neutral') not in {'scheme-neutral', 'scheme-monochrome'}:
            raise ValueError('Unreviewed DMS color scheme')
    return palette


def rgb(color):
    return ', '.join(str(int(color[i:i+2],16)) for i in (1,3,5))


def outputs(palette):
    dms = {}
    for mode in ('dark','light'):
        p = palette[mode]
        mapping = {'primary':'primary','primaryText':'onPrimary','onPrimary':'onPrimary',
                   'primaryContainer':'raised','onPrimaryContainer':'text','secondary':'muted',
                   'secondaryContainer':'soft','onSecondaryContainer':'text',
                   'surface':'surface','surfaceText':'text','surfaceVariant':'soft',
                   'surfaceVariantText':'muted','surfaceTint':'accent','background':'shellCanvas','backgroundText':'text',
                   'outline':'outline','outlineVariant':'border','surfaceContainer':'soft',
                   'surfaceContainerHigh':'raised','surfaceContainerHighest':'highest',
                   'error':'error','warning':'warning','success':'positive','info':'accent'}
        dms[mode] = {'name':p['name'], **{key:p[value] for key,value in mapping.items()}, 'matugen_type':'scheme-neutral'}
        dms[mode].update(palette['dms'].get(mode, {}))
    result = {'environment/session/dankmaterialshell/greyward-obsidian.json': json.dumps(dms,indent=2)+'\n'}
    states = {mode: {role: palette[mode][role] for role in ('positive', 'warning', 'error')}
              for mode in ('dark', 'light')}
    result['environment/session/dms-2.0-plugins/greywardSecure/StatePalette.js'] = (
        '.pragma library\n// ' + NOTICE + '\nvar modes = ' + json.dumps(states, indent=2) + ';\n'
        'function color(tone, light) {\n'
        '    return modes[light ? "light" : "dark"][tone === "positive" ? "positive" : tone === "critical" ? "error" : "warning"];\n'
        '}\n')
    for mode,file in (('dark','obsidian.toml'),('light','silver.toml')):
        p = palette[mode]
        fields = {'name':'name','background':'shellCanvas','surface':'surface','text':'text','accent':'accent',
                  'danger':'error','muted':'subtle','highlight':'raised','border':'border','dim_text':'muted'}
        result['environment/session/desktop/'+file] = '# '+NOTICE+'\n'+''.join(f'{key} = "{p[role]}"\n' for key,role in fields.items())
    fields = ('surface','deep','soft','raised','text','subtle','accent','onPrimary','border')
    header = '// '+NOTICE+'\n#pragma once\nnamespace GreywardPalette {\nstruct Colors {\n'
    header += ''.join('    const char* '+field+';\n' for field in fields)+'};\n'
    for mode in ('dark','light'):
        header += 'inline constexpr Colors '+mode+' = {'+', '.join('"'+palette[mode][field]+'"' for field in fields)+'};\n'
    result['environment/session/desktop/style/palette.h'] = header+'}\n'
    p = palette['dark']
    css = '/* '+NOTICE+' */\n:root {\n  color-scheme: dark;\n'
    mapping = {'canvas':'canvas','canvas-deep':'deep','graphite':'surface','graphite-soft':'soft',
               'graphite-raised':'raised','text':'text','pearl':'primary','muted':'muted','subtle':'subtle',
               'positive':'positive','review':'warning','critical':'error','uncertain':'uncertain','accent':'accent',
               'tone-yellow':'warning','tone-green':'positive','tone-red':'error','glass-surface':'raised'}
    css += ''.join(f'  --{name}: {p[role]};\n' for name,role in mapping.items())
    css += ''.join(f'  --{role}-rgb: {rgb(p[role])};\n' for role in fields+('primary','canvas','muted','positive','warning','error','highest'))
    result['security-center/tauri/frontend/theme-tokens.css'] = css+'}\n'
    return {ROOT/name:content.encode('utf-8') for name,content in result.items()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    generated=outputs(load())
    if args.check:
        changed=[str(path.relative_to(ROOT)) for path,content in generated.items() if not path.is_file() or path.read_bytes()!=content]
        if changed:raise SystemExit('Stale desktop color adapters: '+', '.join(changed))
    else:
        for path,content in generated.items():
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(content)
    print('Desktop palette adapters verified: '+str(len(generated)))


if __name__ == '__main__':main()
