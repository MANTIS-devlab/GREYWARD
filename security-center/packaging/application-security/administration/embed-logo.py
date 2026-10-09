#!/usr/bin/python3 -I
"""Embed the canonical, self-contained SVG at build time; no runtime asset I/O."""
import argparse
import hashlib
from pathlib import Path
import xml.etree.ElementTree as ET


def embed(source, output):
    data = source.read_bytes()
    if len(data) > 131072 or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('Bounded self-contained branding SVG required')
    root = ET.fromstring(data)
    ns = '{http://www.w3.org/2000/svg}'
    if root.tag != ns + 'svg' or root.get('viewBox') != '0 0 1024 1024' or set(root.attrib) - {'width', 'height', 'viewBox'}:
        raise ValueError('Canonical symbol geometry required')
    # The symbol uses filled paths and a local gradient; metadata is inert. Reject
    # external assets, text/font lookup, scripts and additions to that contract.
    for child in root:
        if child.tag == ns + 'metadata':
            continue
        allowed = {'path': {'d', 'fill', 'fill-opacity'}, 'defs': set(),
                   'linearGradient': {'id', 'gradientUnits', 'x1', 'y1', 'x2', 'y2'},
                   'stop': {'offset', 'stop-color', 'stop-opacity'}}
        for element in child.iter():
            tag = element.tag.removeprefix(ns)
            if element.tag != ns + tag or tag not in allowed or set(element.attrib) - allowed[tag]:
                raise ValueError('Self-contained symbol paths required')
            fill = element.get('fill', '')
            if 'url(' in fill and fill != 'url(#gradient_0)':
                raise ValueError('Only the canonical local gradient is supported')
    rows = [','.join(str(b) for b in data[i:i+24]) for i in range(0, len(data), 24)]
    output.write_text('/* Generated from the canonical GREYWARD SVG; reserved branding.\n'
                      f' * Source SHA-256: {hashlib.sha256(data).hexdigest()} */\n'
                      'static const unsigned char greyward_logo_svg[] = {\n' +
                      ',\n'.join(rows) + '\n};\n', encoding='ascii')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    embed(args.source, args.output)
