#!/usr/bin/python3
"""Verify pinned offline artwork, safe SVG closure and its browser allowlist."""
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'security-center/tauri/frontend/assets/country-flags'

def verify():
    source = json.loads((ASSETS / 'provenance.json').read_text(encoding='utf-8'))
    assert source['license'] == 'MIT'
    assert len(source['iso_codes']) == len(set(source['iso_codes'])) == 249
    codes = sorted(set(source['iso_codes'] + source['additional_codes']))
    assert len(codes) == 250 and all(re.fullmatch('[A-Z]{2}', c) for c in codes)
    names = {c.lower() + '.svg' for c in codes}
    assert set(source['files']) == names == {p.name for p in ASSETS.glob('*.svg')}
    assert hashlib.sha256((ASSETS / 'LICENSE.flag-icons').read_bytes()).hexdigest() == source['license_sha256']
    for name, digest in source['files'].items():
        data = (ASSETS / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, name
        tree = ET.fromstring(data)
        for node in tree.iter():
            assert node.tag.rsplit('}', 1)[-1].lower() not in {'script', 'foreignobject', 'image', 'iframe'}, name
            for key, value in node.attrib.items():
                local = key.rsplit('}', 1)[-1].lower()
                assert not local.startswith('on'), name
                if local == 'href':
                    assert value.startswith('#'), name
                for ref in re.findall(r'url\(([^)]+)\)', value):
                    assert ref.strip(' \"\'').startswith('#'), name
    catalog = '/* Generated from provenance.json; offline country artwork only. */\nglobalThis.GREYWARD_COUNTRY_FLAGS = Object.freeze(' + json.dumps({c:c.lower() for c in codes}, separators=(',', ':'), sort_keys=True) + ');\n'
    assert (ASSETS / 'catalog.js').read_text(encoding='utf-8') == catalog
    print('Verified 250 offline country flags, SVG references, MIT license and catalog.')

if __name__ == '__main__':
    verify()
