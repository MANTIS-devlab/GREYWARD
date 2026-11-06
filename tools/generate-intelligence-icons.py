#!/usr/bin/python3
"""Generate the GREYWARD severity instrument family from its canonical SVG."""
from pathlib import Path
import argparse,math
root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
template=(root/'branding/source/intelligence-gauge.svg.in').read_text(encoding='utf-8')
for directory in (root/'branding/generated/intelligence',root/'security-center/data/intelligence-icons'):
 if not args.check:directory.mkdir(parents=True,exist_ok=True)
 for score in range(101):
  color='#e48383' if score>=75 else '#e5a274' if score>=35 else '#90bfa6'
  svg=template.format(score=score,color=color,font_size=52 if score==100 else 64,baseline=82 if score==100 else 86,dash=f'{score*2*math.pi*55/100:.3f}',circumference=f'{2*math.pi*55:.3f}')
  p=directory/f'greyward-intelligence-{score}.svg'
  if args.check:
   assert p.read_bytes()==svg.encode('utf-8'),p
  else:p.write_text(svg,encoding='utf-8',newline='\n')
