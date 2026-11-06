#!/usr/bin/python3
"""Generate the scan-result instrument family from the canonical vector source."""
from pathlib import Path
import argparse
ROOT=Path(__file__).resolve().parents[1]
STATES={
 'clean':('#A7D8B7','<path d="m43 65 14 14 29-31"/>'),
 'review':('#E9C484','<path d="M64 43v25"/><circle cx="64" cy="83" r=".5"/>'),
 'threat':('#F0A3AA','<path d="m48 48 32 32m0-32L48 80"/>'),
 'neutral':('#BDCADA','<path d="M47 64h34"/>'),
}
def generate(check=False):
 template=(ROOT/'branding/source/scan-notification.svg.in').read_text(encoding='utf-8')
 for folder in (ROOT/'branding/generated/scan-notifications',ROOT/'security-center/data/scan-notifications'):
  if not check:folder.mkdir(parents=True,exist_ok=True)
  for name,(accent,badge) in STATES.items():
   data=template.format(accent=accent,badge=badge).encode()
   path=folder/('greyward-scan-'+name+'.svg')
   if check:
    if path.read_bytes()!=data:raise ValueError('Stale scan artwork: '+str(path))
   else:path.write_bytes(data)
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');generate(parser.parse_args().check)
