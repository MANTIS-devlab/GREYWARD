#!/usr/bin/env python3
"""Explicitly requested, redacted desktop diagnostics; never security evidence."""
import argparse
import json
from pathlib import Path
import subprocess


def redact(value):
    if isinstance(value, dict):
        private=('password','token','secret','clipboard','history','account','calendar','plugin','username','location','address','path','file','pins','weather','ssid')
        return {key: '<redacted>' if any(word in key.lower() for word in private) else redact(item) for key,item in value.items()}
    if isinstance(value, list): return [redact(item) for item in value]
    if isinstance(value, str): return '<redacted>'
    return value


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result={'scope':'Redacted desktop settings/session diagnostics; not security evidence'}
    for method in ('dump','dumpSession'):
        raw=subprocess.check_output(['/usr/local/bin/greyward-dms','ipc','call','settings',method],text=True)
        result[method]=redact(json.loads(raw))
    # Never include private strings, addresses, clipboard text, tokens or paths.
    args.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with args.output.open('x') as stream:
        args.output.chmod(0o600)
        json.dump(result,stream,indent=2)
