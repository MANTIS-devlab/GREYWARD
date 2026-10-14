#!/usr/bin/env python3
"""Build one native icon theme and the matching Strata resource overlay.

The caller verifies the pinned upstream archive before extracting it. This
generator consumes only bounded embedded SVG assets, not arbitrary user files.
It never edits the upstream ELF, the host theme or any runtime configuration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

NS = 'http://www.w3.org/2000/svg'
ET.register_namespace('', NS)


def svg_body(path):
    data = path.read_bytes()
    if len(data) > 65536 or b'<!DOCTYPE' in data or b'<!ENTITY' in data:
        raise ValueError('Unsupported icon input: ' + path.name)
    root = ET.fromstring(data)
    if root.tag != '{'+NS+'}svg':
        raise ValueError('Not an SVG: '+path.name)
    for element in root.iter():
        if element.tag.rsplit('}',1)[-1] in ('script','image','foreignObject'):
            raise ValueError('External or active SVG content')
        if any(key.rsplit('}',1)[-1] == 'href' for key in element.attrib):
            raise ValueError('External SVG reference')
    return root, ''.join(ET.tostring(child,encoding='unicode') for child in root)


def svg(body):
    return f'<svg xmlns="{NS}" width="24" height="24" viewBox="0 0 24 24">{body}</svg>\n'


def glyph(source, name, color='#e0e7ea'):
    # Content marks avoid drawing a second document inside the document frame.
    marks={
        'file-text':'<path d="M5 6h10M5 12h14M5 18h11"/>',
        'file-code':'<path d="m9 6-6 6 6 6m6-12 6 6-6 6"/>',
        'file-terminal':'<path d="m4 5 6 6-6 6m9 1h7"/>',
        'file-spreadsheet':'<rect x="4" y="4" width="16" height="16" rx="1"/><path d="M4 10h16M10 4v16M4 15h16"/>',
        'file-archive':'<path d="M9 3h6v4H9v4h6v4H9v5h6v-5M12 3v17"/>',
        'database':'<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v13c0 4 16 4 16 0V5M4 11c0 4 16 4 16 0"/>',
        'pdf':'<path d="M2 18V6h4a3 3 0 0 1 0 6H2m8 6V6h2c5 0 5 12 0 12Zm10 0V6h4m-4 6h3"/>',
    }
    if name in marks:
        return f'<g fill="none" stroke="{color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{marks[name]}</g>'
    path = source/'data/icons/scalable/actions'/f'strata-{name}.svg'
    if not path.is_file() and name == 'file':
        return '<path d="M7 3h7l4 4v14H7Z M14 3v5h4"/>'
    _,body = svg_body(path)
    # Explicit child strokes also survive Strata's folder-badge composition.
    return f'<g color="{color}" fill="none" stroke="{color}" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">{body}</g>'


def folder(palette, badge=''):
    p=palette
    body=f'''<defs>
<linearGradient id="gw-back" x2="0.8" y2="1"><stop stop-color="{p['slate']}"/><stop offset="1" stop-color="{p['obsidian']}"/></linearGradient>
<linearGradient id="gw-paper" x2="0.7" y2="1"><stop stop-color="{p['highlight']}"/><stop offset="1" stop-color="{p['paperShade']}"/></linearGradient>
<linearGradient id="gw-front" x2="0.4" y2="1"><stop stop-color="{p['slate']}"/><stop offset="0.4" stop-color="{p['obsidian']}"/><stop offset="1" stop-color="{p['obsidianShade']}"/></linearGradient>
</defs>
<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" fill="#00060b" opacity=".5" transform="translate(0 .6)"/>
<path d="M3 6.5a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" fill="url(#gw-back)" stroke="{p['edge']}" stroke-width=".4"/>
<path d="M5 8.5h14v8H5Z" fill="url(#gw-paper)"/>
<path d="M5 9h14M5.6 10h12.8" stroke="{p['highlight']}" stroke-width=".35" opacity=".8"/>
<path d="M3 11a1.3 1.3 0 0 1 1.3-1.3h15.4A1.3 1.3 0 0 1 21 11v7.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" fill="url(#gw-front)" stroke="{p['edge']}" stroke-width=".4"/>
<path d="M4.3 10h15.4" stroke="{p['highlight']}" stroke-width=".35" opacity=".8"/>
<path d="M5 18.8h14" stroke="{p['slate']}" stroke-width=".3" opacity=".8"/>
'''
    if badge:
        body+=f'<g transform="translate(8.5 11.4) scale(.3)">{badge}</g>'
    return svg(body)


def document(palette, badge, accent):
    p=palette
    return svg(f'''<defs><linearGradient id="gw-page" x2=".8" y2="1"><stop stop-color="{p['paper']}"/><stop offset="1" stop-color="{p['paperShade']}"/></linearGradient></defs>
<path d="M6 3.5h8l4 4V21H6Z" fill="#00060b" opacity=".5" transform="translate(0 .6)"/>
<path d="M6 3h8l4 4v13.5H6Z" fill="url(#gw-page)" stroke="{p['edge']}" stroke-width=".4"/>
<path d="M14 3v4h4" fill="{p['highlight']}" stroke="{p['edge']}" stroke-width=".35"/>
<rect x="4.5" y="10" width="15" height="10.5" rx="1.6" fill="{p['obsidian']}" stroke="{accent}" stroke-width=".4"/>
<g transform="translate(7.6 10.6) scale(.37)">{badge}</g>
<path d="M6.1 10.4h11.8" stroke="{accent}" stroke-width=".35" opacity=".7"/>
''')


def tile(palette, badge, accent):
    p=palette
    return svg(f'''<defs><linearGradient id="gw-tile" x2=".4" y2="1"><stop stop-color="{p['slate']}"/><stop offset="1" stop-color="{p['obsidianShade']}"/></linearGradient></defs>
<rect x="3" y="3.5" width="18" height="18" rx="4" fill="#00060b" opacity=".5"/>
<rect x="3" y="3" width="18" height="18" rx="4" fill="url(#gw-tile)" stroke="{accent}" stroke-width=".4"/>
<path d="M6 3.5h12" stroke="{p['highlight']}" stroke-width=".35" opacity=".4"/>
<g transform="translate(5 5) scale(.58)">{badge}</g>''')


def generate(catalog, upstream, destination):
    model=json.loads(catalog.read_text())
    if model['schema'] != 'greyward.icon-family/v1':
        raise ValueError('Unsupported icon catalog')
    if destination.exists():
        raise ValueError('Use a new output directory')
    p=model['palette']
    theme=destination/'theme/Greyward'
    overlay=destination/'strata'
    written={}

    def write(path, content):
        path.parent.mkdir(parents=True,exist_ok=True)
        data=content.encode() if isinstance(content,str) else content
        path.write_bytes(data)
        written[path.relative_to(destination).as_posix()]=hashlib.sha256(data).hexdigest()

    for name,badge in model['folderBadges'].items():
        write(theme/'scalable/places'/f'{name}.svg', folder(p,glyph(upstream,badge) if badge else ''))
        write(theme/'scalable/places'/f'{name}-symbolic.svg', svg(glyph(upstream,badge or 'folder')))
    for name,(badge,color) in model['mimeTypes'].items():
        write(theme/'scalable/mimetypes'/f'{name}.svg',document(p,glyph(upstream,badge),p[color]))
    for name,(badge,color) in model['objects'].items():
        write(theme/'scalable/devices'/f'{name}.svg',tile(p,glyph(upstream,badge),p[color]))

    # Shared upstream action shapes; neutral Platinum treatment. Rich folder/file
    # assets replace only object icons; each unrelated action keeps its own glyph.
    document_kinds={'file-text':'blue','file-code':'amber','file-terminal':'amber',
        'file-spreadsheet':'green','file-archive':'amber','file-type':'blue',
        'image':'violet','audio-lines':'green','video':'violet','presentation':'amber'}
    folder_names={'folder':None,'folder-open':None,'folder-archive':'file-archive',
                  'folder-input':'arrow-down','folder-output':'arrow-up','folder-plus':'plus'}
    for path in sorted((upstream/'data/icons/scalable/actions').glob('*.svg')):
        name=path.stem.removeprefix('strata-')
        root,body=svg_body(path)
        if name in folder_names:
            badge=folder_names[name]
            content=folder(p, glyph(upstream,badge) if badge else '')
        elif name in document_kinds:
            content=document(p,glyph(upstream,name),p[document_kinds[name]])
        else:
            # Preserve upstream geometry and separate function identities.
            color=p['obsidian'] if name=='check-on-primary' else p['text']
            children=list(root)
            for child in children:
                root.remove(child)
            group=ET.SubElement(root,'{'+NS+'}g',{'stroke':color,'color':color,'stroke-width':'1.65'})
            for child in children:
                group.append(child)
            root.set('stroke',color)
            root.set('stroke-width','1.65')
            content=ET.tostring(root,encoding='unicode')+'\n'
        write(overlay/'icons/scalable/actions'/path.name,content)
        write(theme/'scalable/actions'/f'{name}.svg',content)
        write(theme/'scalable/actions'/f'{name}-symbolic.svg',svg(glyph(upstream,name)))

    # Strata resolves many filenames through its own extension catalog instead
    # of the native MIME theme. Resolve those names to the SAME complete asset;
    # framing the old Catppuccin logos still produced a second visual language.
    kinds=model['strataFileKinds']
    for path in sorted((upstream/'data/icons/catppuccin').glob('*.svg')):
        svg_body(path)
        name=path.stem.removeprefix('strata-ctp-')
        kind=kinds['overrides'].get(name,kinds['default'])
        badge,color=model['mimeTypes'][kind]
        content=document(p,glyph(upstream,badge),p[color])
        write(overlay/'icons/catppuccin'/path.name,content)

    # GTK can resolve the embedded application icon before the installed theme.
    # Cover that resource too; the previous overlay left Strata's old logo here.
    identity=catalog.parent/'greyward-files.svg'
    svg_body(identity)
    write(overlay/'icons/scalable/apps/io.github.lgse.Strata.svg',identity.read_bytes())
    write(theme/'scalable/apps/io.github.lgse.Strata.svg',identity.read_bytes())
    write(theme/'scalable/apps/greyward-files.svg',identity.read_bytes())

    directories=['scalable/'+x for x in ('places','mimetypes','devices','actions','apps')]
    index='[Icon Theme]\nName=Greyward\nComment=GREYWARD Obsidian / Platinum\nInherits=breeze-dark,Adwaita,hicolor\nDirectories='+','.join(directories)+'\n'
    for directory in directories:
        context={'places':'Places','mimetypes':'MimeTypes','devices':'Devices','actions':'Actions','apps':'Applications'}[directory.rsplit('/',1)[1]]
        index+=f'\n[{directory}]\nSize=48\nMinSize=16\nMaxSize=512\nType=Scalable\nContext={context}\n'
    write(theme/'index.theme',index)
    write(destination/'LICENSES/Lucide-Feather.txt',(upstream/'data/licenses/Lucide-ISC.txt').read_bytes())
    write(destination/'LICENSES/Catppuccin.txt',(upstream/'data/licenses/Catppuccin-VSCode-Icons-MIT.txt').read_bytes())
    receipt={'schema':'greyward.generated-icon-family/v1','catalogSha256':hashlib.sha256(catalog.read_bytes()).hexdigest(),'files':written}
    (destination/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return {'files':len(written),'theme':str(theme),'overlay':str(overlay)}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog',type=Path,required=True)
    parser.add_argument('--upstream',type=Path,required=True)
    parser.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(generate(args.catalog,args.upstream,args.destination)))
