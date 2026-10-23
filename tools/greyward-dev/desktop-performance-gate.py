#!/usr/bin/env python3
"""Compare matched desktop measurements; missing evidence never passes a gate."""
import argparse
import json
import math
from pathlib import Path

REQUIRED_PANELS = {f'{name}:{mode}' for name in ('launcher', 'dashboard', 'settings',
                   'control-center', 'security-center', 'strata') for mode in ('first', 'repeat')}
REQUIRED_CONDITIONS = {'hardware', 'outputs', 'renderer', 'workload', 'accounting'}


def finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError('Metrics must be finite nonnegative numbers')
    return value


def compare(baseline, candidate):
    conditions = baseline.get('conditions')
    if (not isinstance(conditions, dict) or not REQUIRED_CONDITIONS.issubset(conditions)
            or any(not conditions[key] for key in REQUIRED_CONDITIONS)
            or conditions != candidate.get('conditions')):
        raise ValueError('Hardware/output/workload/renderer and accounting conditions must match')
    if baseline.get('schema') != 'greyward.desktop-performance/v1' or candidate.get('schema') != baseline['schema']:
        raise ValueError('Unknown performance evidence schema')
    failures, improvements = [], []
    old_panels, new_panels = baseline['panels'], candidate['panels']
    if not REQUIRED_PANELS.issubset(old_panels) or set(old_panels) != set(new_panels):
        raise ValueError('Complete matching panel evidence is required')
    for name, old in old_panels.items():
        new = new_panels[name]
        if any(type(x['samples']) is not int or x['samples'] < 30 for x in (old, new)):
            raise ValueError('At least 30 samples are required per panel')
        before, after = finite(old['p95_ms']), finite(new['p95_ms'])
        if after > before + max(before * .1, 50):
            failures.append(name + ': p95 latency regression')
        if before > 0 and after <= before * .85:
            improvements.append(name)
    for label, margin in [('idle_cpu_one_core_percent', .5), ('steady_memory_bytes', None)]:
        before, after = finite(baseline[label]), finite(candidate[label])
        if after > (before + margin if margin is not None else before * 1.1):
            failures.append(label + ': regression budget exceeded')
    if any(finite(item.get('idle_duration_seconds', 0)) < 600 for item in (baseline, candidate)):
        raise ValueError('At least ten minutes of matched idle evidence is required')
    if candidate.get('continuing_growth') is not False:
        failures.append('Memory/subscription growth absent or unresolved')
    return {'schema': 'greyward.desktop-performance-result/v1',
            'regression_gate_passed': not failures, 'failures': failures,
            'improved_panels': improvements, 'improvement_target_met': len(improvements) >= 2,
            'note': 'Regression limits alone do not demonstrate improved performance'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    result = compare(json.loads(args.baseline.read_text()), json.loads(args.candidate.read_text()))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['regression_gate_passed'] else 1)
