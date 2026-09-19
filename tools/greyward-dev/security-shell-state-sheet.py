#!/usr/bin/env python3
"""Render labelled design fixtures; never connects to a live security provider."""
import copy
import html
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'security-center/security-context'))
from greyward_security_context.shell_experience import build_experience


def main():
    base = dict(shell={'posture': {'state': 'SECURE'}}, capsule={}, devices=[], usb_error=None, files={}, network={})
    mic = {'signal_id': 'microphone:recorder', 'category': 'ACTIVE_SENSOR', 'state': 'ACTIVE', 'application': 'Voice Recorder'}
    camera = {**mic, 'signal_id': 'camera:meeting', 'application': 'Meeting'}
    usb = {'connection_ref': 'fixture', 'name': 'Portable drive', 'device_class': 'EXTERNAL_STORAGE', 'state': 'BLOCK', 'can_persist': True}
    threat = {'detections': [{'detection_id': 'fixture', 'state': 'DETECTED', 'original_path': '/fixture/download.zip'}]}
    scenarios = [
        ('Idle', {}), ('Microphone', {'capsule': {'signals': [mic]}}), ('Camera', {'capsule': {'signals': [camera]}}),
        ('Trusted presence', {'devices': [{**usb, 'state': 'ALLOW', 'authorized': True, 'trusted': True}]}),
        ('Approval', {'devices': [usb]}),
        ('Authorizing', {'devices': [usb], 'operations': {'fixture': {'state': 'PENDING', 'detail': 'Waiting for authorization…'}}}),
        ('Degraded protection', {'network': {'threat_intel': {'enabled': True, 'state': 'ERROR'}}}),
        ('Threat', {'files': threat}), ('Scan progress', {'files': {'active_scan': {'operation_id': 'fixture'}}}),
        ('Action failure', {'devices': [usb], 'operations': {'fixture': {'state': 'DENIED', 'detail': 'USBGuard did not authorize the device change.'}}}),
        ('Simultaneous signals', {'files': threat, 'devices': [usb], 'capsule': {'signals': [mic, camera]}}),
        ('Provider unavailable', {'usb_error': 'fixture'}),
    ]
    emblem = (ROOT / 'branding/source/greyward-security-status.svg').read_text()
    cards = []
    for name, changes in scenarios:
        value = build_experience(**(copy.deepcopy(base) | changes))
        activity = value['activity']
        items = value['items']
        e = html.escape
        badges = ''.join(f'<span class="badge">{e(x["kind"])}</span>' for x in activity[:2])
        actions = ''.join(f'<button>{e(a["label"])}</button>' for a in (items[0]['actions'] if items else []))
        primary = f'<div class="event"><b>{e(items[0]["title"])}</b><p>{e(items[0]["detail"])}</p>{actions}</div>' if items else ''
        activities = ''.join(f'<p class="activity"><b>{e(x["title"])}</b><br>{e(x["detail"])}</p>' for x in activity)
        notification = f'<aside>{emblem}<div><small>GREYWARD Security Center</small><b>{e(items[0].get("notification_title",items[0]["title"]))}</b><p>{e(items[0].get("notification_detail",items[0]["detail"]))}</p>{actions or "<button>Review</button>"}</div></aside>' if items else '<p class="quiet">No notification</p>'
        cards.append(f'<section><h2>{e(name)}</h2><div class="pill">{emblem}{badges}{"<sup>!</sup>" if items else ""}</div><article class="{value["severity"].lower()}"><header>{emblem}<div><small>Security Center</small><h3>{e(value["label"])}</h3></div></header><p>{e(value["reason"])}</p>{primary}{f"<small>{len(items)-1} more items</small>" if len(items)>1 else ""}{activities}<footer><button>Protection details</button><button class="primary">Open Security Center</button></footer></article>{notification}</section>')
    css = '''*{box-sizing:border-box}body{background:#11171c;color:#e0e6eb;font:13px Inter,Segoe UI,sans-serif;margin:32px}h1{font-size:24px}h2{font-size:14px;color:#aebbc5}h3{margin:3px 0 0;font-size:16px}p{line-height:1.45;color:#b6c2cb}small{color:#aebbc5;font-size:12px}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:24px}section{max-width:430px}svg{width:24px;height:24px;flex-shrink:0}.pill{display:inline-flex;align-items:center;height:32px;padding:4px 6px;gap:6px;border:1px solid #52606b;border-radius:10px;background:#20282f;position:relative}.badge{font-size:11px;color:#acd8c4}sup{background:#e5c084;color:#182027;border-radius:50%;padding:0 4px;position:absolute;right:-4px;top:-4px}article,aside{background:#1b232a;border:1px solid #586571;border-radius:14px;padding:16px;margin-top:16px;box-shadow:0 4px 12px #0003}header{display:flex;gap:12px;align-items:center}header svg{width:36px;height:36px}.action h3,.warning h3{color:#e5c084}.critical h3{color:#eeaaa7}.event{padding:12px;background:#28323a;border:1px solid #657078;border-radius:10px}.critical .event{background:#35282b;border-color:#986968}.event b{font-size:14px}.event p{margin:8px 0}button{min-height:34px;border-radius:8px;background:#27323b;color:#e0e6eb;border:1px solid #485560;padding:7px 12px;font:13px inherit;margin:4px 4px 0 0}.primary{background:#cad5dd;color:#182027;width:100%;margin-top:12px}footer{margin-top:16px}.activity{border-top:1px solid #3c4852;padding-top:12px}aside{display:flex;gap:12px}aside b{display:block;margin-top:4px}aside p{margin:6px 0}.quiet{font-size:12px;color:#82929e}'''
    output = ROOT / 'tmp/security-redesign/state-sheet.html'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>GREYWARD security state sheet</title><style>'+css+'</style><h1>Security Center · state sheet</h1><p>Development design fixtures. These are simulated states, not hardware or acceptance evidence.</p><main>'+''.join(cards)+'</main></html>', encoding='utf-8')
    print(output)


if __name__ == '__main__':
    main()
